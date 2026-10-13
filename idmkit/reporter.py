"""诊断报告的收集与打包。

导出的是一个自解释的压缩包：拿到它的人不需要再问用户任何问题，就能知道
当前状态、哪一项坏了、以及为什么坏。
"""

from __future__ import annotations

import zipfile
from datetime import datetime
from pathlib import Path

from . import constants as C
from . import diagnose, journal, runtime


def _text(name: str, body: str) -> tuple[str, str]:
    return (name, body)


def collect(diag: diagnose.Diagnosis) -> list[tuple[str, str]]:
    """组装报告的各部分。返回 (文件名, 内容) 列表。"""
    parts: list[tuple[str, str]] = []

    parts.append(_text("01-诊断结论.txt", diagnose.render_text(diag)))
    parts.append(_text("02-诊断结论.json", diagnose.render_json(diag)))

    parts.append(_text("03-浏览器扩展状态.txt", _extension_report()))
    parts.append(_text("04-安装目录文件.txt", _directory_listing()))
    parts.append(_text("05-IDM安装日志.txt", _setup_log()))
    # 操作记录放在使用说明之前：排障时先看「做过什么、哪次失败了」，
    # 比先看怎么解读报告更有用。
    parts.append(_text("06-操作记录.txt", journal.render_text()))
    parts.append(_text("07-使用说明.txt", _readme_hint()))
    return parts


def _extension_report() -> str:
    lines = ["浏览器扩展安装状态", ""]
    for e in runtime.browser_extensions():
        mark = "已安装" if e.installed else "未安装"
        lines.append(f"{e.browser:<8} {mark:<6} {e.detail}")

    lines.append("")
    lines.append("安装目录里自带的扩展文件（Firefox 需要手动安装这些）：")
    files = runtime.extension_files()
    if files:
        for name, size in sorted(files.items()):
            lines.append(f"    {name:<20} {size / 1024:7.1f} KB")
    else:
        lines.append("    （读不到安装目录）")

    lines.append("")
    lines.append("扩展的注册表注册项（Chrome / Edge 靠这些自动安装）：")
    reg = runtime.extension_registry()
    if reg:
        for key, value in sorted(reg.items()):
            lines.append(f"    {key}")
            lines.append(f"        -> {value}")
    else:
        lines.append("    （没有注册项 —— Edge / Chrome 扩展不会自动出现）")
    return "\n".join(lines)


def _directory_listing() -> str:
    d = runtime.find_idm_dir()
    if d is None:
        return "找不到 IDM 安装目录。"
    lines = [f"安装目录：{d}", ""]
    for f in sorted(d.iterdir()):
        if f.is_file():
            lines.append(f"{f.name:<24} {f.stat().st_size / 1024:9.1f} KB")
    return "\n".join(lines)


def _setup_log(tail: int = 80) -> str:
    d = runtime.find_idm_dir()
    if d is None:
        return "找不到 IDM 安装目录。"
    log = d / "IDMSetup2.log"
    if not log.is_file():
        return "安装目录里没有 IDMSetup2.log。"
    try:
        raw = log.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"读取安装日志失败：{exc}"
    lines = raw.splitlines()
    return "\n".join(lines[-tail:])


def _readme_hint() -> str:
    d = runtime.find_idm_dir()
    xpi = C.EXT_FIREFOX_FILE
    return "\n".join([
        "拿到这份报告的人需要知道的：",
        "",
        "1. 看 01-诊断结论.txt 开头的「结论 / 原因 / 建议」三行即可定位问题。",
        "2. 「事实」是原始状态，「含义」是它代表什么，不需要另外猜测。",
        "3. **先看 06-操作记录.txt**：它记着每次动作的结果与失败原因。",
        "   如果里面有一条「失败」，那次的摘要就是根因所在 —— 诊断结论只说明",
        "   「现在是什么状态」，说不出「刚才为什么失败」。",
        "4. 若结论是「激活已失效」，让用户重新点一次「激活」按钮即可。",
        "5. 若结论涉及「IDM 权限过高」，让用户不要用管理员身份启动 IDM。",
        "6. 浏览器扩展：Chrome / Edge 由注册表自动安装；",
        f"   Firefox 需要手动把 {xpi} 拖进浏览器窗口。",
        "7. 需要更细的数据时看 02-诊断结论.json，字段最全（含各改写点偏移）。",
        "",
        f"IDM 安装目录：{d or '未找到'}",
    ])


def export(dest_dir: Path | None = None, diag: diagnose.Diagnosis | None = None) -> Path:
    """把诊断报告打包成 zip，返回产物路径。"""
    diag = diag or diagnose.diagnose()
    # 桌面位置从注册表取，不拼 Path.home() —— 见 runtime.desktop_dir 的说明
    dest = dest_dir or runtime.desktop_dir()
    dest.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = dest / f"idm-diag-{stamp}.zip"

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in collect(diag):
            zf.writestr(name, body)

    return out
