"""诊断结论引擎。

日志的价值不在于收集了多少信息，而在于**看一眼就知道哪儿坏了**。
因此这里每一项都产出三样东西：

    事实    观察到了什么（可验证的原始状态）
    含义    这个状态说明什么
    动作    用户该做什么（没有问题时为空）

最后汇成一个 verdict —— 使用者不需要自己分析这些数据。
"""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from . import constants as C
from . import patch, runtime

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"

_STATUS_MARK = {
    STATUS_OK: "[正常]",
    STATUS_WARN: "[注意]",
    STATUS_FAIL: "[故障]",
    STATUS_INFO: "[信息]",
}


@dataclass
class Check:
    key: str
    title: str
    status: str
    fact: str                 # 观察到的
    meaning: str              # 说明什么
    action: str = ""          # 该做什么

    @property
    def mark(self) -> str:
        return _STATUS_MARK.get(self.status, "[?]")


@dataclass
class Diagnosis:
    verdict: str              # 一句话结论
    severity: str             # ok / warn / fail
    cause: str = ""           # 原因
    action: str = ""          # 下一步
    checks: list[Check] = field(default_factory=list)
    context: dict = field(default_factory=dict)

    @property
    def has_problem(self) -> bool:
        return self.severity in (STATUS_FAIL, STATUS_WARN)


# ---- 单项检查 ----------------------------------------------------------


def _check_install(exe: Path | None) -> Check:
    if exe is None or not exe.is_file():
        return Check(
            "install", "IDM 安装", STATUS_FAIL,
            fact="在常见安装路径下找不到 IDMan.exe",
            meaning="IDM 没有安装，或者装在非标准位置",
            action="先用官方安装包装上 IDM，再运行本工具",
        )
    size_mb = exe.stat().st_size / 1024 / 1024
    return Check(
        "install", "IDM 安装", STATUS_OK,
        fact=f"{exe}（{size_mb:.1f} MB）",
        meaning="IDM 已安装",
    )


def _check_version(exe: Path | None) -> tuple[Check, tuple[int, ...] | None]:
    if exe is None or not exe.is_file():
        return Check("version", "程序版本", STATUS_INFO, "未安装", "无法判断"), None

    try:
        ver = _read_file_version(exe)
    except Exception:
        ver = None

    if ver is None:
        return Check(
            "version", "程序版本", STATUS_WARN,
            fact="读不出文件版本号",
            meaning="文件可能损坏或不是标准构建",
        ), None

    if ver == C.FILE_VERSION:
        return Check(
            "version", "程序版本", STATUS_OK,
            fact=".".join(str(n) for n in ver),
            meaning=f"与工具支持的版本 {C.FILE_VERSION_TEXT} 一致",
        ), ver

    return Check(
        "version", "程序版本", STATUS_FAIL,
        fact=".".join(str(n) for n in ver),
        meaning=(
            f"这不是本工具支持的版本（支持 {C.FILE_VERSION_TEXT}）。"
            "IDM 可能已升级到更新的构建"
        ),
        action="从官方安装包重装到支持的版本，或等待工具更新",
    ), ver


def _read_file_version(exe: Path) -> tuple[int, ...] | None:
    """读取 PE 文件的版本资源，失败返回 None。

    四个 API 的签名都显式声明 —— ctypes 默认按 int 处理参数，在 64 位下会
    截断指针。
    """
    import ctypes
    from ctypes import wintypes

    ver_dll = ctypes.WinDLL("version", use_last_error=True)
    ver_dll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    ver_dll.GetFileVersionInfoSizeW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    ver_dll.GetFileVersionInfoW.restype = wintypes.BOOL
    ver_dll.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    ver_dll.VerQueryValueW.restype = wintypes.BOOL
    ver_dll.VerQueryValueW.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT),
    ]

    path = str(exe)
    ignored = wintypes.DWORD(0)
    size = ver_dll.GetFileVersionInfoSizeW(path, ctypes.byref(ignored))
    if not size:
        return None

    buf = ctypes.create_string_buffer(size)
    if not ver_dll.GetFileVersionInfoW(path, 0, size, buf):
        return None

    class _FixedFileInfo(ctypes.Structure):
        _fields_ = [
            ("dwSignature", wintypes.DWORD),
            ("dwStrucVersion", wintypes.DWORD),
            ("dwFileVersionMS", wintypes.DWORD),
            ("dwFileVersionLS", wintypes.DWORD),
        ]

    ptr = ctypes.c_void_p()
    length = wintypes.UINT(0)
    if not ver_dll.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
        return None
    if not ptr or length.value < ctypes.sizeof(_FixedFileInfo):
        return None

    info = ctypes.cast(ptr, ctypes.POINTER(_FixedFileInfo)).contents
    return (
        info.dwFileVersionMS >> 16,
        info.dwFileVersionMS & 0xFFFF,
        info.dwFileVersionLS >> 16,
        info.dwFileVersionLS & 0xFFFF,
    )


def _check_patch(exe: Path | None, state: patch.PatchState | None) -> Check:
    if state is None:
        return Check(
            "patch", "激活状态", STATUS_FAIL,
            fact="无法读取程序文件", meaning="无法判断", action="确认文件权限",
        )

    if state.overall == patch.PATCHED:
        note = f"　{state.note}" if state.note else ""
        return Check(
            "patch", "激活状态", STATUS_OK,
            fact=f"已激活，上限 {state.days} 天{note}",
            meaning="试用期上限已被改写，不会到期",
        )

    if state.overall == patch.PRISTINE:
        return Check(
            "patch", "激活状态", STATUS_FAIL,
            fact="文件是官方原版，未做任何改动",
            meaning=(
                "补丁没有生效。最常见的原因是 IDM 自动更新把 IDMan.exe "
                "换回了官方版本"
            ),
            action="点击「激活」重新处理（几秒钟）",
        )

    if state.overall == patch.INCONSISTENT:
        return Check(
            "patch", "激活状态", STATUS_FAIL,
            fact=state.note or "两处数值不一致",
            meaning="文件被部分改动过，可能被其他工具修改",
            action="先用「还原官方版」再重新「激活」",
        )

    return Check(
        "patch", "激活状态", STATUS_FAIL,
        fact=state.note or "无法识别文件状态",
        meaning=(
            "文件既不是已知的官方版本，也不像本工具处理过的版本。"
            "通常是 IDM 升级到了更新的构建"
        ),
        action="重装到支持版本，或重新运行官方安装包",
    )


def _check_days(limit: int | None) -> Check:
    if limit is None:
        return Check(
            "days", "试用上限", STATUS_INFO,
            fact="上限未知",
            meaning=f"未激活时官方默认是 {C.ORIGINAL_DAYS} 天",
        )
    if limit <= C.ORIGINAL_DAYS:
        return Check(
            "days", "试用上限", STATUS_FAIL,
            fact=f"{limit} 天（官方默认就是 {C.ORIGINAL_DAYS} 天）",
            meaning="上限没有被真正改写，效果等同于仍在试用",
            action="点击「激活」",
        )
    return Check(
        "days", "试用上限", STATUS_OK,
        fact=f"{limit} 天",
        meaning="远高于官方默认值，不存在到期问题",
    )


def _check_update() -> Check:
    """自动更新预警。

    这是整个报告里对用户最有价值的一项：更新会把 IDMan.exe 换回官方版本，
    激活随之失效。与其等它失效后再排查，不如提前说清"还有多久"。
    """
    sched = runtime.update_schedule()
    if not sched.known:
        return Check(
            "update", "自动更新", STATUS_INFO,
            fact="注册表里没有检查更新的记录",
            meaning="IDM 可能还没运行过，或该项已被清理",
        )

    if sched.overdue:
        return Check(
            "update", "自动更新", STATUS_WARN,
            fact=f"上次检查 {sched.last_check_text}，约 {sched.days_since} 天前",
            meaning=(
                "已经超出 IDM 两周一次的检查周期，随时可能更新。"
                "更新会把程序换回官方版本，激活随之失效"
            ),
            action="更新之后重新点一次「激活」即可，几秒钟完成",
        )

    return Check(
        "update", "自动更新", STATUS_OK,
        fact=f"上次检查 {sched.last_check_text}，约 {sched.days_since} 天前",
        meaning=(
            f"按两周的检查周期推算，大约 {sched.days_until_next} 天之后"
            "才会再次检查更新"
        ),
    )


def _check_process(procs: list[runtime.ProcInfo]) -> tuple[Check, runtime.ProcInfo | None]:
    idm = next((p for p in procs if p.name == "IDMan"), None)
    if idm is None:
        return Check(
            "process", "IDM 进程", STATUS_INFO,
            fact="IDM 当前没有运行",
            meaning="要处理文件或使用下载功能时需要启动它",
            action="点击「启动 IDM」",
        ), None

    others = [p.name for p in procs if p.name != "IDMan"]
    extra = f"（同时运行：{', '.join(others)}）" if others else ""
    return Check(
        "process", "IDM 进程", STATUS_OK,
        fact=f"正在运行，pid {idm.pid}，权限 {idm.integrity_label}{extra}",
        meaning="进程正常",
    ), idm


def _check_integrity(idm: runtime.ProcInfo | None) -> Check:
    """这一项是浏览器扩展失效最常见的原因。"""
    if idm is None:
        return Check(
            "integrity", "IDM 运行权限", STATUS_INFO,
            fact="IDM 未运行", meaning="无法判断权限级别",
        )

    if idm.integrity == "high" or idm.integrity == "system":
        return Check(
            "integrity", "IDM 运行权限", STATUS_FAIL,
            fact=f"以{idm.integrity_label}权限运行",
            meaning=(
                "浏览器以普通权限运行，Windows 不允许它连接管理员权限的进程。"
                "这正是浏览器扩展报 Cannot launch IDM 的原因"
            ),
            action="关掉 IDM，然后正常双击图标重新打开（不要用「以管理员身份运行」）",
        )

    if not idm.readable:
        return Check(
            "integrity", "IDM 运行权限", STATUS_WARN,
            fact="读不到进程令牌信息",
            meaning="进程权限比本工具高，很可能也是以管理员身份启动的",
            action="以普通用户身份重新打开 IDM",
        )

    return Check(
        "integrity", "IDM 运行权限", STATUS_OK,
        fact=f"以{idm.integrity_label}权限运行",
        meaning="浏览器可以连接它",
    )


def _check_channel(idm: runtime.ProcInfo | None) -> Check:
    state = runtime.port_state()
    if state == "listening":
        return Check(
            "channel", "浏览器通道", STATUS_OK,
            fact=f"127.0.0.1:{C.BROWSER_PORT} 正在监听",
            meaning="下载接管功能的通道已经建立",
        )
    if state == "occupied":
        return Check(
            "channel", "浏览器通道", STATUS_WARN,
            fact=f"端口 {C.BROWSER_PORT} 被占用但没有接受连接",
            meaning="可能是 IDM 正在启动，或驱动状态异常",
            action="稍后重试；若持续如此，重启 IDM",
        )
    if idm is None:
        return Check(
            "channel", "浏览器通道", STATUS_INFO,
            fact="端口空闲，IDM 未运行",
            meaning="IDM 启动后才会建立这个通道",
        )
    return Check(
        "channel", "浏览器通道", STATUS_WARN,
        fact=f"端口 {C.BROWSER_PORT} 空闲，但 IDM 正在运行",
        meaning=(
            "IDM 的网络过滤驱动可能没有加载，这时浏览器无法把下载交给 IDM"
        ),
        action="重启电脑；若仍然如此，以管理员身份重新安装 IDM",
    )


def _check_driver() -> Check:
    state = runtime.wfp_service_state()
    if state == "running":
        return Check(
            "driver", "网络驱动", STATUS_OK,
            fact=f"{C.WFP_SERVICE} 服务运行中",
            meaning="接管浏览器下载所需的驱动已加载",
        )
    if state == "missing":
        return Check(
            "driver", "网络驱动", STATUS_FAIL,
            fact=f"找不到 {C.WFP_SERVICE} 服务",
            meaning="驱动没有注册，浏览器扩展无法工作",
            action="以管理员身份重新安装 IDM",
        )
    return Check(
        "driver", "网络驱动", STATUS_WARN,
        fact=f"{C.WFP_SERVICE} 服务状态：{state}",
        meaning="驱动可能没有正常运行",
        action="重启电脑后再检查",
    )


def _check_extensions(exts: list[runtime.BrowserExt]) -> Check:
    installed = [e for e in exts if e.installed]
    leftover = [e for e in exts if e.leftover]
    present = [e for e in exts if e.detail != "未安装该浏览器"]
    if not present:
        return Check(
            "ext", "浏览器扩展", STATUS_INFO,
            fact="没有检测到受支持的浏览器",
            meaning="装浏览器后才需要这一步",
        )
    if not installed:
        if leftover:
            return Check(
                "ext", "浏览器扩展", STATUS_WARN,
                fact="只剩残留："
                + "、".join(f"{e.browser}（{e.detail}）" for e in leftover),
                meaning="这是浏览器缓存的旧文件，扩展已经不可能工作",
                action="装上 IDM 后扩展会自动重新注册；Firefox 需手动拖一次 xpi",
            )
        return Check(
            "ext", "浏览器扩展", STATUS_WARN,
            fact="已装浏览器："
            + "、".join(e.browser for e in present)
            + "，但都没有 IDM 扩展",
            meaning="浏览器下载不会被 IDM 接管",
            action="Chrome/Edge 重装 IDM 会自动装上；Firefox 需手动安装",
        )
    lines = [f"{e.browser}（{e.detail}）" for e in installed]
    if leftover:
        lines.append("残留：" + "、".join(e.browser for e in leftover))
    return Check(
        "ext", "浏览器扩展", STATUS_OK,
        fact="已安装：" + "、".join(lines),
        meaning="扩展已就位",
    )


def _check_backup(exe: Path | None) -> Check:
    if exe is None:
        return Check("backup", "原始备份", STATUS_INFO, "无", "未安装")
    bak = exe.with_name(exe.name + C.BACKUP_SUFFIX)
    if not bak.is_file():
        return Check(
            "backup", "原始备份", STATUS_INFO,
            fact="没有备份文件",
            meaning="还没处理过，或备份被删除",
        )
    from .patch import sha256_of
    ok = patch.is_pristine(sha256_of(bak.read_bytes()))
    if ok:
        return Check(
            "backup", "原始备份", STATUS_OK,
            fact=f"{bak.name} 是官方原版",
            meaning="随时可以还原成官方状态",
        )
    return Check(
        "backup", "原始备份", STATUS_WARN,
        fact=f"{bak.name} 不是官方原版",
        meaning="备份已被替换过，还原后可能仍不是全新状态",
    )


# ---- 汇总裁决 ----------------------------------------------------------


def diagnose(exe: Path | None = None) -> Diagnosis:
    """跑完全部检查并给出结论。"""
    if exe is None:
        exe = runtime.idm_exe()

    checks: list[Check] = []
    ctx: dict = {}

    install = _check_install(exe)
    checks.append(install)

    version, ver_tuple = (
        _check_version(exe) if exe else
        (Check("version", "程序版本", STATUS_INFO, "未安装", "无法判断"), None)
    )
    checks.append(version)

    state: patch.PatchState | None = None
    if exe is not None and exe.is_file():
        try:
            state = patch.inspect(exe.read_bytes())
        except Exception as exc:  # 读取失败不应中断整个诊断
            ctx["patch_error"] = str(exc)
    checks.append(_check_patch(exe, state))

    checks.append(_check_days(state.days if state else None))
    checks.append(_check_update())

    procs = runtime.running_processes()
    proc_check, idm_proc = _check_process(procs)
    checks.append(proc_check)
    checks.append(_check_integrity(idm_proc))
    checks.append(_check_channel(idm_proc))
    checks.append(_check_driver())
    checks.append(_check_extensions(runtime.browser_extensions()))
    checks.append(_check_backup(exe))

    # 环境上下文，出问题时便于复现
    ctx.update({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "windows": f"{platform.system()} {platform.release()} ({platform.version()})",
        "python": sys.version.split()[0],
        "frozen": bool(getattr(sys, "frozen", False)),
        "elevated": runtime.is_elevated(),
        "user": os.environ.get("USERNAME", ""),
        "computer": os.environ.get("COMPUTERNAME", ""),
        "idm_dir": str(runtime.find_idm_dir() or ""),
        "idm_exe": str(exe) if exe else "",
    })
    if state is not None:
        ctx["sha256"] = patch.sha256_of(exe.read_bytes()) if exe else ""
        ctx["site_a"] = state.site_a.state
        ctx["site_a_days"] = state.site_a.days
        ctx["site_b"] = state.site_b.state
        ctx["site_b_days"] = state.site_b.days
    ctx["registry"] = runtime.registry_snapshot()
    ctx["extension_registry"] = runtime.extension_registry()

    verdict, severity, cause, action = _decide(checks, state, idm_proc, exe)
    return Diagnosis(verdict, severity, cause, action, checks, ctx)


def _decide(
    checks: list[Check],
    state: patch.PatchState | None,
    idm_proc: runtime.ProcInfo | None,
    exe: Path | None,
) -> tuple[str, str, str, str]:
    """把一堆检查项收敛成一句人话。

    顺序即优先级：先解决"根本没有/根本不匹配"，再看具体功能故障。
    """
    by_key = {c.key: c for c in checks}

    if by_key["install"].status == STATUS_FAIL:
        return (
            "没有找到 IDM", STATUS_FAIL,
            "IDM 尚未安装，或装在非标准目录",
            "先安装 IDM，然后重新运行本工具",
        )

    if by_key["version"].status == STATUS_FAIL:
        return (
            "版本不匹配", STATUS_FAIL,
            by_key["version"].meaning,
            by_key["version"].action,
        )

    if by_key["patch"].status == STATUS_FAIL:
        if state is not None and state.overall == patch.PRISTINE:
            return (
                "激活已失效", STATUS_FAIL,
                "程序文件被还原成了官方原版，最常见的原因是 IDM 自动更新覆盖了它",
                "点击「激活」重新处理，几秒钟即可完成",
            )
        return (
            "激活状态异常", STATUS_FAIL,
            by_key["patch"].meaning,
            by_key["patch"].action or "尝试「还原官方版」后再「激活」",
        )

    if by_key["patch"].status == STATUS_OK and state and state.note:
        return (
            "激活生效但没有实际意义", STATUS_WARN,
            state.note,
            "把上限改成一个远大于 30 的值，比如默认的 99999999",
        )

    if by_key["integrity"].status == STATUS_FAIL:
        return (
            "IDM 权限过高，浏览器连不上它", STATUS_FAIL,
            by_key["integrity"].meaning,
            by_key["integrity"].action,
        )

    if by_key["driver"].status == STATUS_FAIL:
        return (
            "网络驱动缺失", STATUS_FAIL,
            by_key["driver"].meaning,
            by_key["driver"].action,
        )

    if by_key["channel"].status == STATUS_WARN and idm_proc is not None:
        return (
            "浏览器通道没有建立", STATUS_WARN,
            by_key["channel"].meaning,
            by_key["channel"].action,
        )

    if by_key["ext"].status == STATUS_WARN:
        return (
            "浏览器扩展没有装上", STATUS_WARN,
            by_key["ext"].meaning,
            by_key["ext"].action,
        )

    if by_key["backup"].status == STATUS_WARN:
        return (
            "一切正常，但备份文件已被替换", STATUS_WARN,
            by_key["backup"].meaning,
            "如需可回滚的原始备份，重装后再处理一次",
        )

    update = by_key.get("update")
    if update is not None and update.status == STATUS_WARN:
        return (
            "一切正常，但自动更新即将到来", STATUS_WARN,
            update.meaning,
            update.action,
        )

    return (
        "一切正常", STATUS_OK,
        f"IDM 已激活，试用上限 {by_key['days'].fact}",
        "",
    )


# ---- 输出 --------------------------------------------------------------


def render_text(d: Diagnosis) -> str:
    """人可读的报告。"""
    bar = "=" * 62
    lines = [bar, "IDM 诊断报告", bar, ""]
    lines.append(f"结论：{d.verdict}")
    if d.cause:
        lines.append(f"原因：{d.cause}")
    if d.action:
        lines.append(f"建议：{d.action}")
    lines.append("")
    lines.append("-" * 62)
    lines.append("各项检查")
    lines.append("-" * 62)
    for c in d.checks:
        lines.append(f"{c.mark} {c.title}")
        lines.append(f"       事实：{c.fact}")
        lines.append(f"       含义：{c.meaning}")
        if c.action:
            lines.append(f"       建议：{c.action}")
        lines.append("")
    lines.append("-" * 62)
    lines.append("环境")
    lines.append("-" * 62)
    for k, v in d.context.items():
        if isinstance(v, dict):
            lines.append(f"{k}:")
            for kk, vv in v.items():
                lines.append(f"    {kk} = {vv}")
        else:
            lines.append(f"{k} = {v}")
    lines.append("")
    lines.append(bar)
    return "\n".join(lines)


def render_json(d: Diagnosis) -> str:
    """机器可读的报告。"""
    payload = {
        "verdict": d.verdict,
        "severity": d.severity,
        "cause": d.cause,
        "action": d.action,
        "checks": [asdict(c) for c in d.checks],
        "context": d.context,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
