"""系统状态探测：进程、权限、注册表、网络、浏览器扩展。

全部基于标准库（ctypes / winreg / socket），不引入任何第三方依赖，
以保证打包出的 exe 干净且体积可控。
"""

from __future__ import annotations

import ctypes
import os
import socket
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import constants as C

try:
    import winreg
except ImportError:  # 非 Windows 平台，便于语法检查
    winreg = None  # type: ignore[assignment]


# ---- 进程与权限级别 ----------------------------------------------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_a32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TokenIntegrityLevel = 25

#: 完整性级别 RID
_IL_NAMES = {
    0x0000: "untrusted",
    0x1000: "low",
    0x2000: "medium",
    0x2100: "medium-plus",
    0x3000: "high",
    0x4000: "system",
}

_IL_LABEL = {
    "untrusted": "受限",
    "low": "低",
    "medium": "普通用户",
    "medium-plus": "普通用户",
    "high": "管理员",
    "system": "系统",
}


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", _SID_AND_ATTRIBUTES)]


def _integrity_rid(pid: int) -> int | None:
    """读取进程令牌的完整性级别 RID。读不到返回 None。

    读不到这件事本身就是信息：PROCESS_QUERY_LIMITED_INFORMATION 允许访问
    同级或更低级别的进程，因此失败通常意味着对方权限更高。
    """
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    token = wintypes.HANDLE()
    try:
        if not _a32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
            return None
        size = wintypes.DWORD(0)
        _a32.GetTokenInformation(
            token, TokenIntegrityLevel, None, 0, ctypes.byref(size)
        )
        if not size.value:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if not _a32.GetTokenInformation(
            token, TokenIntegrityLevel, buf, size.value, ctypes.byref(size)
        ):
            return None
        label = ctypes.cast(buf, ctypes.POINTER(_TOKEN_MANDATORY_LABEL)).contents
        sid = label.Label.Sid
        if not sid:
            return None
        _a32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        count_ptr = _a32.GetSidSubAuthorityCount(ctypes.c_void_p(sid))
        if not count_ptr:
            return None
        count = count_ptr.contents.value
        _a32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        rid_ptr = _a32.GetSidSubAuthority(ctypes.c_void_p(sid), count - 1)
        if not rid_ptr:
            return None
        return int(rid_ptr.contents.value)
    finally:
        if token:
            _k32.CloseHandle(token)
        _k32.CloseHandle(handle)


@dataclass
class ProcInfo:
    name: str
    pid: int
    integrity: str          # 'medium' / 'high' / ...
    readable: bool          # 能否读取其信息
    path: str = ""

    @property
    def integrity_label(self) -> str:
        return _IL_LABEL.get(self.integrity, self.integrity)


def _list_pids(name: str) -> list[int]:
    """枚举同名进程的 pid，用 tasklist 之外的纯 API 方式。

    用 CreateToolhelp32Snapshot 遍历，避免依赖外部命令。
    """
    TH32CS_SNAPPROCESS = 0x00000002

    class _PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or not snap:
        return []
    entry = _PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)
    pids: list[int] = []
    try:
        if _k32.Process32First(snap, ctypes.byref(entry)):
            while True:
                exe = entry.szExeFile.decode("mbcs", errors="replace")
                if exe.lower() == f"{name.lower()}.exe":
                    pids.append(int(entry.th32ProcessID))
                if not _k32.Process32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        _k32.CloseHandle(snap)
    return pids


def running_processes(names: tuple[str, ...] = C.IDM_PROCESSES) -> list[ProcInfo]:
    out: list[ProcInfo] = []
    for name in names:
        for pid in _list_pids(name):
            rid = _integrity_rid(pid)
            if rid is None:
                out.append(ProcInfo(name, pid, "unknown", False))
            else:
                key = min(_IL_NAMES, key=lambda k: abs(k - rid))
                out.append(ProcInfo(name, pid, _IL_NAMES[key], True))
    return out


def blocking_processes_running() -> list[ProcInfo]:
    """打补丁前必须退出的进程。"""
    return running_processes(C.BLOCKING_PROCESSES)


def is_elevated() -> bool:
    """当前进程是否以管理员身份运行。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---- 安装路径 ----------------------------------------------------------


def _read_hklm(path: str, value: str):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            data, _ = winreg.QueryValueEx(key, value)
            return data
    except OSError:
        return None


def _dir_from_registry() -> Path | None:
    """从注册表推导安装目录。

    IDM 允许装到非系统盘（安装器是 NSIS，支持 ``/D=``），所以不能把路径写死。
    两个来源，按可靠性排序：

    1. ``HKCU\\Software\\DownloadManager\\ExePath`` —— IDM 自己写的，指向它
       实际运行的 exe，最准。
    2. 卸载信息里的 ``UninstallString`` —— 安装程序写的，去掉文件名即目录。
       同一处的 ``InstallLocation`` 实测是空值，不可依赖。
    """
    exe = _read_hkcu(C.REG_KEY_MAIN, C.REG_VALUE_EXE_PATH)
    if isinstance(exe, str) and exe.strip():
        p = Path(exe.strip().strip('"'))
        if p.is_file():
            return p.parent

    for key in C.REG_UNINSTALL_KEYS:
        raw = _read_hklm(key, C.REG_VALUE_UNINSTALL_STRING)
        if isinstance(raw, str) and raw.strip():
            p = Path(raw.strip().strip('"'))
            if p.parent.is_dir() and (p.parent / C.EXE_FILENAME).is_file():
                return p.parent
    return None


def find_idm_dir() -> Path | None:
    """定位 IDM 安装目录。注册表优先，硬编码候选只作最后后备。"""
    found = _dir_from_registry()
    if found is not None:
        return found
    for candidate in C.IDM_DIR_CANDIDATES:
        p = Path(candidate)
        if (p / C.EXE_FILENAME).is_file():
            return p
    return None


def idm_exe() -> Path | None:
    d = find_idm_dir()
    return None if d is None else d / C.EXE_FILENAME


def idm_backup() -> Path | None:
    d = find_idm_dir()
    return None if d is None else d / (C.EXE_FILENAME + C.BACKUP_SUFFIX)


# ---- 注册表 ------------------------------------------------------------


def _read_hkcu(path: str, value: str):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            data, _ = winreg.QueryValueEx(key, value)
            return data
    except OSError:
        return None


@dataclass
class UpdateSchedule:
    """自动更新的时间线。

    这是本工具能为用户做的最有价值的预警：自动更新会把 IDMan.exe 换回
    官方版本，激活随之失效。提前知道"还有几天"比事后排查有用得多。
    """

    last_check_ts: int | None
    last_check_text: str
    days_since: int | None        # 距上次检查过了几天
    days_until_next: int | None   # 距预计下次还有几天（可能为负）
    overdue: bool                 # 是否已超出预计周期

    @property
    def known(self) -> bool:
        return self.last_check_ts is not None


def last_check_qu() -> int | None:
    """上一次检查自动更新的时刻（Unix 时间戳，秒）。"""
    v = _read_hkcu(C.REG_KEY_MAIN, C.REG_VALUE_LAST_CHECK_QU)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def version_tag() -> str:
    """注册表里的版本标记，例如 "v6.43b15 Trial"。"""
    v = _read_hkcu(C.REG_KEY_MAIN, C.REG_VALUE_VERSION_TAG)
    return "" if v is None else str(v)


def update_schedule(now: datetime | None = None) -> UpdateSchedule:
    """推算自动更新的时间线。

    依据是二进制里的原文：IDM checks for a new release every 2 weeks。
    """
    now = now or datetime.now()
    ts = last_check_qu()
    if ts is None or ts <= 0:
        return UpdateSchedule(None, "", None, None, False)

    try:
        last = datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return UpdateSchedule(None, "", None, None, False)

    days_since = max((now - last).days, 0)
    days_until = C.UPDATE_CHECK_INTERVAL_DAYS - days_since
    return UpdateSchedule(
        last_check_ts=ts,
        last_check_text=last.strftime("%Y-%m-%d %H:%M"),
        days_since=days_since,
        days_until_next=days_until,
        overdue=days_until <= 0,
    )


def registry_snapshot() -> dict[str, str]:
    """关键注册表项的当前值，供诊断报告使用。"""
    if winreg is None:
        return {}
    out: dict[str, str] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, C.REG_KEY_MAIN) as key:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    continue
                if isinstance(value, bytes):
                    value = value.hex(" ").upper()
                out[name] = str(value)
    except OSError:
        pass
    return out


def extension_registry() -> dict[str, str]:
    """Chrome 系扩展的注册表注册项。"""
    if winreg is None:
        return {}
    out: dict[str, str] = {}
    for hive, label in (
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU"),
    ):
        for path in C.REG_EXT_CHROME + C.REG_EXT_EDGE:
            try:
                with winreg.OpenKey(hive, path) as key:
                    path_val, _ = winreg.QueryValueEx(key, "path")
                    out[f"{label}\\{path}"] = str(path_val)
            except OSError:
                continue
    return out


# ---- 网络与服务 --------------------------------------------------------


def port_state(port: int = C.BROWSER_PORT) -> str:
    """端口是否有人在监听。"""
    listening = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.35)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.35):
                listening = True
        except (ConnectionRefusedError, socket.timeout, OSError):
            listening = False

    if listening:
        return "listening"
    # 连不上不等于没监听（可能被拒绝）。再确认一次是否有人 bind 着。
    try:
        bind_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            bind_probe.bind(("127.0.0.1", port))
            bind_probe.close()
            return "free"
        except OSError:
            bind_probe.close()
            return "occupied"
    except OSError:
        return "unknown"


def wfp_service_state() -> str:
    """IDMWFP 驱动服务的状态。

    sc.exe 的输出编码跟随系统区域设置 —— 中文系统返回 GBK 字节。不能依赖
    subprocess 的文本模式，它的编码可能被 PYTHONIOENCODING 之类影响，服务不
    存在时输出中文就会在读取线程里抛 UnicodeDecodeError（该异常不在主线程，
    捕不住）。这里自己按多种编码试解，最后兜底。
    """
    try:
        import subprocess
        proc = subprocess.run(
            ["sc", "query", C.WFP_SERVICE],
            capture_output=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return "unknown"

    raw = proc.stdout or b""
    out = None
    for enc in ("utf-8", "mbcs", "latin-1"):
        try:
            out = raw.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if out is None:
        out = raw.decode("latin-1", errors="replace")

    upper = out.upper()
    if "RUNNING" in upper:
        return "running"
    if "STOPPED" in upper:
        return "stopped"
    if proc.returncode != 0:
        return "missing"
    return "unknown"


# ---- 浏览器扩展 --------------------------------------------------------


@dataclass
class BrowserExt:
    browser: str
    installed: bool
    detail: str = ""
    leftover: bool = False   # 只剩浏览器缓存的文件，扩展已不可能工作


def _chromium_registered(subkeys: tuple[str, ...]) -> bool:
    """扩展是否真正注册，且注册表指向的 crx 文件确实存在。

    只看浏览器 profile 里的扩展目录会误判：IDM 卸载后 Chrome 缓存的扩展副本
    还在，但源文件已经没了，扩展不可能工作。
    """
    if winreg is None:
        return False
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for subkey in subkeys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    crx, _ = winreg.QueryValueEx(key, "path")
            except OSError:
                continue
            if isinstance(crx, str) and crx and Path(crx).is_file():
                return True
    return False


def _chromium_ext(
    browser: str,
    profile_tmpl: str,
    ext_id: str,
    reg_subkeys: tuple[str, ...],
) -> BrowserExt:
    root = Path(profile_tmpl.format(localappdata=os.environ.get("LOCALAPPDATA", "")))
    if not root.is_dir():
        return BrowserExt(browser, False, "未安装该浏览器")

    ext_dir = root / "Default" / "Extensions" / ext_id
    versions = (
        [d.name for d in ext_dir.iterdir() if d.is_dir()] if ext_dir.is_dir() else []
    )
    label = "、".join(versions) if versions else ""

    if _chromium_registered(reg_subkeys):
        return BrowserExt(browser, True, f"版本 {label}" if label else "已注册")

    if versions:
        return BrowserExt(
            browser, False,
            f"只剩扩展文件（{label}），未注册",
            leftover=True,
        )
    return BrowserExt(browser, False, "扩展未安装")


def browser_extensions() -> list[BrowserExt]:
    out: list[BrowserExt] = []
    for name, tmpl in C.BROWSER_PROFILE_DIRS.items():
        if name == "Edge":
            out.append(_chromium_ext(name, tmpl, C.EXT_EDGE_ID, C.REG_EXT_EDGE))
        else:
            out.append(_chromium_ext(name, tmpl, C.EXT_CHROME_ID, C.REG_EXT_CHROME))
    out.append(_firefox_ext())
    return out


def _firefox_ext() -> BrowserExt:
    root = Path(
        C.FIREFOX_PROFILE_DIR.format(appdata=os.environ.get("APPDATA", ""))
    )
    if not root.is_dir():
        return BrowserExt("Firefox", False, "未安装该浏览器")

    leftover: str | None = None
    for profile in root.iterdir():
        if not profile.is_dir():
            continue
        # 真正可用的判据：extensions 目录里存在 idmmzcc 的 xpi 文件。
        # 只查 extensions.json 会误判 —— IDM 卸载后那份记录还在，文件却没了。
        ext_dir = profile / "extensions"
        if ext_dir.is_dir():
            for f in ext_dir.iterdir():
                if "idmmzcc" in f.name.lower():
                    return BrowserExt("Firefox", True, f"配置文件 {profile.name}")

        ext_json = profile / "extensions.json"
        if ext_json.is_file():
            try:
                text = ext_json.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "idmmzcc" in text or "tonec" in text.lower():
                leftover = leftover or profile.name

    if leftover:
        return BrowserExt(
            "Firefox", False,
            f"只剩记录（{leftover}），扩展文件已不在",
            leftover=True,
        )
    return BrowserExt("Firefox", False, "扩展未安装")


def extension_files() -> dict[str, int]:
    """安装目录里自带的扩展文件，供手动安装 Firefox 时指路。"""
    d = find_idm_dir()
    if d is None:
        return {}
    out: dict[str, int] = {}
    for f in d.iterdir():
        if f.suffix.lower() in (".crx", ".xpi", ".nex"):
            out[f.name] = f.stat().st_size
    return out
