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
from . import patch, pe, runtime

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
    fact: str                 # 观察到的（写给人看，界面上直接显示）
    meaning: str              # 说明什么
    action: str = ""          # 该做什么
    detail: str = ""          # 技术细节：地址、字节、注册表值。只进导出报告

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
        # 界面上只说结论；具体改了哪几处、变成什么字节，进 detail。
        return Check(
            "patch", "激活状态", STATUS_OK,
            fact=f"已激活　可以正常下载，不会到期",
            meaning="下载时不会弹出「IDM 主程序文件已损坏」，也不会中断正在进行的下载",
            detail=state.note or "",
        )

    if state.overall == patch.PARTIAL:
        return Check(
            "patch", "激活状态", STATUS_FAIL,
            fact=state.note or "试用上限已改，完整定性警告未跳过",
            meaning=(
                "上限改好了，但 IDM 仍会弹出「IDM 主程序文件已损坏」"
                "并冻结正在进行的下载"
            ),
            action="点击「激活」补齐缺的那一处（几秒钟）",
        )

    if state.overall == patch.PRISTINE:
        # 与 _decide 同一根因：文件是原版有两种来路，说法不能混。有 .bak 说明
        # 处理过、后来被换回；没有则多半还没处理过 —— 对首次使用者讲「被换回了
        # 官方版本」是错的，它就没被换过。
        backed_up = (
            exe is not None
            and exe.with_name(exe.name + C.BACKUP_SUFFIX).is_file()
        )
        meaning = (
            "补丁没有生效。IDM 自动更新把 IDMan.exe 换回了官方版本"
            if backed_up
            else "补丁没有生效。这个文件还是官方原版，多半是还没处理过"
        )
        return Check(
            "patch", "激活状态", STATUS_FAIL,
            fact="文件是官方原版，未做任何改动",
            meaning=meaning,
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


def _check_checksum(exe: Path | None, state: patch.PatchState | None) -> Check:
    """PE 头里的 CheckSum 是否与文件内容自洽。

    补丁改的是代码段，而 IDM 会用 PE 头的这个字段检查自身完整性：字段与实测值
    对不上，它就报「IDM 主程序文件已损坏」并冻结正在进行的下载。所以重算校验和
    不是可有可无的收尾，而是"补丁打完整了没有"的判据本身。
    """
    if exe is None or state is None or state.overall != patch.PATCHED:
        return Check(
            "checksum", "程序文件完好", STATUS_INFO,
            fact="未检查",
            meaning="尚未激活，暂时不需要检查这一项",
        )

    try:
        data = exe.read_bytes()
        at = pe.checksum_field_offset(data)
        stored = int.from_bytes(data[at:at + 4], "little")
        want = pe.pe_checksum(data)
    except Exception as exc:  # 读不到不该中断整个诊断
        return Check(
            "checksum", "程序文件完好", STATUS_INFO,
            fact=f"读不到文件：{exc}",
            meaning="无法确认，需要看文件权限",
        )

    if stored == want:
        return Check(
            "checksum", "程序文件完好", STATUS_OK,
            fact="已通过　IDM 不会提示文件损坏",
            meaning="下载时不会弹出「IDM 主程序文件已损坏」，也不会中断正在进行的下载",
            detail=f"PE 校验和 = 0x{want:08X}，与文件内容自洽",
        )

    return Check(
        "checksum", "程序文件完好", STATUS_FAIL,
        fact="未通过　IDM 会提示文件损坏",
        meaning=(
            "改动过程序，但完整性标记没跟着更新，"
            "IDM 会误以为文件损坏并中断下载"
        ),
        action="点「激活」补上即可，不会重复改动",
        detail=(f"文件里记录的是 0x{stored:08X}，"
                f"按实际内容算出来应为 0x{want:08X}"),
    )


def _check_days(limit: int | None) -> Check:
    """界面说「会不会到期」，报告留具体天数。

    使用者不关心上限是多少天，只关心「会不会到期」。上万天这个数字摆在界面上
    只会让人多想，所以只在 detail 里留如实数值。
    """
    if limit is None:
        return Check(
            "days", "使用期限", STATUS_INFO,
            fact="暂时无法确认",
            detail=f"未激活时官方默认是 {C.ORIGINAL_DAYS} 天",
        )
    if limit <= C.ORIGINAL_DAYS:
        return Check(
            "days", "使用期限", STATUS_FAIL,
            fact="仍在试用期　会到期",
            meaning="期限没有被真正改写，效果等同于还在试用",
            action="点「激活」",
            detail=f"读取到的上限是 {limit} 天，官方默认就是 {C.ORIGINAL_DAYS} 天",
        )
    return Check(
        "days", "使用期限", STATUS_OK,
        fact="不会到期",
        meaning="远高于官方默认值，不存在到期问题",
        detail=f"试用上限 = {limit} 天",
    )


def _check_autoupdate(state: patch.PatchState | None) -> Check:
    """自动更新：给用户看结论，给报告留技术细节。

    界面上一律只说「关没关掉」。地址、注册表值这些放进 detail —— 它们对确认
    改动是否落地有价值，但堆在界面上只会让人不知道看哪里。
    """
    item = runtime.autoupdate_state()

    if state is None:
        return Check(
            "autoupdate", "自动更新", STATUS_INFO,
            fact="读不到 IDMan.exe，暂时无法判断",
            meaning="文件读不出来，也就无法确认自动更新是否已经关闭",
            action="确认文件权限后点「刷新」",
        )

    sched = runtime.update_schedule()

    # 技术细节：无论哪种状态都记全，进导出报告
    tech = [
        f"判据点 0x56F13 = "
        + ("0（恒不触发检查）" if state.autoupdate_stopped else "非 0（判据生效）"),
        f"分派点 0x88518 = "
        + ("0x28（消息 5 改指空处理，定时器分支不执行）"
           if state.autoupdate_stopped else "0x02（定时器分支照常执行）"),
    ]
    if sched.known:
        tech.append(f"LastCheckQU = {sched.last_check_ts}"
                    f"（{item.last_check_text}）")
        tech.append(f"LstCheck = {item.last_check_date or '(空)'}"
                    f"　距今约 {sched.days_since} 天")
    else:
        tech.append("LastCheckQU = 不存在")
    detail = "\n".join(tech)

    if state.autoupdate_stopped:
        return Check(
            "autoupdate", "自动更新", STATUS_OK,
            fact="已关闭　IDM 不会再检查新版本",
            meaning="以后 IDM 不会自动下载新版本来覆盖当前程序，激活也不会因此失效",
            detail=detail,
        )

    if state.autoupdate_known:
        fact = "还开着　IDM 会自动检查新版本"
        if sched.known:
            fact += f"（上次检查是 {sched.days_since} 天前）"
        return Check(
            "autoupdate", "自动更新", STATUS_WARN,
            fact=fact,
            meaning="自动更新随时可能把 IDM 换回官方版本，激活也随之失效",
            action="点「取消自动更新」，几秒钟完成",
            detail=detail,
        )

    return Check(
        "autoupdate", "自动更新", STATUS_INFO,
        fact="这个版本的 IDM 无法处理",
        meaning=(
            "当前 IDM 不是本工具支持的版本，工具不会做任何修改，"
            "以免改错地方"
        ),
        action="确认 IDM 版本；需要帮助时点「导出诊断」",
        detail=detail,
    )

def _check_update(state: patch.PatchState | None) -> Check:
    """自动更新的时间线预告。

    补丁 D 就位后这条预告失去意义 —— 周期判定恒返回「不需要检查」，
    再推算「还有几天会检查」只是自相矛盾，所以改为如实说明已关闭。
    """
    if state is not None and state.autoupdate_stopped:
        return Check(
            "update", "更新周期", STATUS_OK,
            fact="周期判定已关闭，不再有「下次检查」",
            meaning=(
                "取消之前 IDM 按「距上次检查满 6 天就再查一次」的节奏运行；"
                "现在这个判断恒为「不需要检查」"
            ),
        )

    sched = runtime.update_schedule()
    if not sched.known:
        return Check(
            "update", "更新周期", STATUS_INFO,
            fact="注册表里没有检查更新的记录",
            meaning="IDM 可能还没运行过，或该项已被清理",
        )

    if sched.overdue:
        return Check(
            "update", "更新周期", STATUS_WARN,
            fact=f"上次检查 {sched.last_check_text}，约 {sched.days_since} 天前",
            meaning=(
                f"已经超出 IDM {C.UPDATE_CHECK_INTERVAL_DAYS} 天一次的检查周期，"
                "下次启动或下一个定时器到点就会去查。"
                "更新会把程序换回官方版本，激活随之失效"
            ),
            action="先点「取消自动更新」关掉它，再考虑重打补丁",
        )

    return Check(
        "update", "更新周期", STATUS_OK,
        fact=f"上次检查 {sched.last_check_text}，约 {sched.days_since} 天前",
        meaning=(
            f"按 {C.UPDATE_CHECK_INTERVAL_DAYS} 天的周期推算，"
            f"大约 {sched.days_until_next} 天之后才会再次检查更新"
        ),
        action="想彻底关掉就点「取消自动更新」",
    )


def _check_process(
    procs: list[runtime.ProcInfo],
) -> tuple[Check, runtime.ProcInfo | None]:
    idm = next((p for p in procs if p.name == "IDMan"), None)

    # 判据以进程枚举为主，见 runtime.idm_running()：端口不能证明 IDM 在运行，
    # 1001 是 IDMWFP 驱动常驻占用的。而枚举受权限影响 —— 实测普通权限下打包版
    # 只扫到 23 个进程，所以「枚举不到」只推出「无法确认」，不推出「没运行」。
    running, why = runtime.idm_running()

    if running is True:
        if idm is not None:
            fact = f"正在运行，pid {idm.pid}，权限 {idm.integrity_label}"
            meaning = "进程正常"
        else:
            # 防御性分支：idm_running() 现在只在枚举到 IDMan 时返回 True，
            # 正常走不到这里，留作判据再改时的兜底。
            fact = f"正在运行（{why}）"
            meaning = "进程正常"
        others = [p.name for p in procs if p.name != "IDMan"]
        if others:
            fact += f"（同时运行：{', '.join(others)}）"
        return Check("process", "IDM 进程", STATUS_OK, fact=fact, meaning=meaning), idm

    if running is None:
        return Check(
            "process", "IDM 进程", STATUS_WARN,
            fact=f"无法确认是否在运行（{why}）",
            meaning=(
                "进程表读不完整，通常是权限不足。这种时候在表里找不到 IDMan，"
                "不能当作「没在运行」"
            ),
            action="以管理员身份运行本工具，判断会更准确",
        ), None

    return Check(
        "process", "IDM 进程", STATUS_INFO,
        fact="IDM 当前没有运行",
        meaning="要处理文件或使用下载功能时需要启动它",
        action="点击「启动 IDM」",
    ), None


def _check_integrity(idm: runtime.ProcInfo | None) -> Check:
    """这一项是浏览器扩展失效最常见的原因。"""
    if idm is None:
        return Check(
            "integrity", "IDM 运行权限", STATUS_INFO,
            fact="读不到进程信息",
            meaning="进程表不完整时无法判断 IDM 的权限级别",
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
        # 这个端口由 IDMWFP 驱动常驻占用（内核 pid 4），不代表 IDM 已启动。
        # 驱动在 = 具备接管能力；真正接管还要求 IDMan.exe 在运行。
        if idm is None:
            return Check(
                "channel", "浏览器通道", STATUS_WARN,
                fact=f"127.0.0.1:{C.BROWSER_PORT} 在监听，但 IDM 没在运行",
                meaning=(
                    "这个端口是 IDMWFP 驱动常驻占用的，驱动在就一直在监听。"
                    "IDM 启动后才会真正接管浏览器下载"
                ),
                action="点击「启动 IDM」",
            )
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
        fact="已装好　浏览器下载会交给 IDM",
        meaning="扩展已就位，浏览器里的下载由 IDM 接管",
        detail="已安装：" + "、".join(lines),
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
    checks.append(_check_checksum(exe, state))

    checks.append(_check_days(state.days if state else None))
    checks.append(_check_autoupdate(state))
    checks.append(_check_update(state))

    procs = runtime.running_processes()
    total = runtime.total_process_count()
    proc_check, idm_proc = _check_process(procs)
    checks.append(proc_check)
    checks.append(_check_integrity(idm_proc))
    checks.append(_check_channel(idm_proc))
    checks.append(_check_driver())
    checks.append(_check_extensions(runtime.browser_extensions()))
    checks.append(_check_backup(exe))

    # 环境上下文，出问题时便于复现
    ctx.update({
        # 工具自己的版本：拿到报告时先确认对方用的是哪一版
        "tool_version": C.TOOL_VERSION,
        # 本工具能处理的 IDM 版本，与上面的工具版本是两回事
        "supported_idm": C.FILE_VERSION_TEXT,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "windows": f"{platform.system()} {platform.release()} ({platform.version()})",
        "python": sys.version.split()[0],
        "frozen": bool(getattr(sys, "frozen", False)),
        "process_total": total,
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
        ctx["site_c"] = state.site_c.state
        if state.site_d is not None:
            ctx["site_d"] = state.site_d.state
            ctx["site_d_offset"] = state.site_d.offset
        if state.site_e is not None:
            ctx["site_e"] = state.site_e.state
            ctx["site_e_offset"] = state.site_e.offset
        ctx["autoupdate_stopped"] = state.autoupdate_stopped
    auto = runtime.autoupdate_state()
    ctx["reg_last_check_qu"] = auto.last_check_qu
    ctx["reg_last_check_date"] = auto.last_check_date
    ctx["reg_check_updt_vm"] = auto.check_updt_vm
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
        if state is not None and state.overall == patch.PARTIAL:
            # 上限改好了，但完整性警告没跳过。这不是"异常"，而是本工具早期
            # 版本留下的半成品，用户升级后就会遇到，说法要明确指路。
            return (
                "激活不完整", STATUS_FAIL,
                state.note or "试用上限已改，但完整性警告还没跳过",
                "点击「激活」补齐缺的那一处，几秒钟即可完成",
            )
        if state is not None and state.overall == patch.PRISTINE:
            # 文件是官方原版，但「为什么是原版」有两种情况，说法不能混：有 .bak
            # 说明处理过、后来被覆盖；没有 .bak 多半是头一次用 —— 对首次使用者讲
            # 「被还原成了官方原版」是错的，它本来就是原版。
            backed_up = (
                exe is not None
                and exe.with_name(exe.name + C.BACKUP_SUFFIX).is_file()
            )
            if not backed_up:
                return (
                    "还没处理过", STATUS_FAIL,
                    "程序文件是官方原版，还没有处理过",
                    "点击「激活」，几秒钟即可完成",
                )
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

    # 补丁在位不等于补得完整：校验和没重算的文件会被 IDM 判成损坏，此时
    # 光看「已激活」会得出错误的「一切正常」。
    if by_key["checksum"].status == STATUS_FAIL:
        return (
            "激活不完整", STATUS_FAIL,
            by_key["checksum"].meaning,
            by_key["checksum"].action,
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

    # 自动更新已取消：这是使用者主动做的选择，值得在结论里说一声，
    # 否则报告最后一行的「一切正常」会让人以为更新还在跑。
    auto = by_key.get("autoupdate")
    if state is not None and state.autoupdate_stopped:
        return (
            "一切正常", STATUS_OK,
            "IDM 已激活，可以正常下载；自动更新也已经关闭，"
            "以后不会再被新版本覆盖",
            "",
        )

    if auto is not None and auto.status == STATUS_WARN:
        return (
            "一切正常，但自动更新仍开着", STATUS_WARN,
            "自动更新随时可能把 IDMan.exe 换回官方版本，激活随之失效",
            "点「取消自动更新」把它关掉，几秒钟完成",
        )

    return (
        "一切正常", STATUS_OK,
        f"IDM 已激活，试用上限 {by_key['days'].fact}，"
        "完整性警告已跳过",
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
        if c.detail:
            lines.append("       技术细节：")
            for dl in c.detail.splitlines():
                lines.append(f"           {dl}")
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
