"""程序入口。

无参数时启动图形界面。带参数时以命令行模式运行 —— 界面通过提权重启自身并
传入这些参数来完成需要管理员权限的动作，因此这里必须能在没有控制台的
环境下工作，结果用系统弹窗呈现。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from idmkit import constants as C
from idmkit import diagnose, patch, reporter, runtime

APP_TITLE = "IDM 工具"


# ---- 无控制台时的输出 --------------------------------------------------


def _message(text: str, title: str = APP_TITLE, error: bool = False) -> None:
    """在 GUI 子进程里弹窗；在控制台里打印。"""
    if sys.stdout is not None and sys.stdout.isatty():
        print(text)
        return
    import ctypes
    flags = 0x10 if error else 0x40  # MB_ICONERROR / MB_ICONINFORMATION
    ctypes.windll.user32.MessageBoxW(None, text, title, flags)


# ---- 关闭 IDM ----------------------------------------------------------


def _stop_idm() -> list[str]:
    """结束所有 IDM 相关进程，返回未能结束的名字。

    按映像名调用 taskkill，而不是先枚举拿 PID：枚举结果受权限影响，普通权限
    下可能一个都拿不到，那时循环体一次都不执行，表现为「停不掉也没报错」。
    返回码 128 是「没有找到该进程」，不算失败；5 才是拒绝访问。
    """
    import subprocess
    denied: list[str] = []
    for name in C.IDM_PROCESSES:
        try:
            result = subprocess.run(
                ["taskkill", "/IM", name + ".exe", "/T", "/F"],
                capture_output=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            denied.append(name)
            continue
        if result.returncode == 5:
            denied.append(name)
    return denied


# ---- 子命令 ------------------------------------------------------------


def cmd_check() -> int:
    d = diagnose.diagnose()
    text = diagnose.render_text(d)
    if sys.stdout is not None:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0 if d.severity == diagnose.STATUS_OK else 1


def cmd_patch(days: int, quiet: bool) -> int:
    exe = runtime.idm_exe()
    if exe is None:
        _message("找不到 IDM，无法处理。", error=True)
        return 2

    running = runtime.running_processes()
    if running:
        names = "、".join(sorted({p.name for p in running}))
        _stop_idm()
        import time
        time.sleep(1.5)
        still = runtime.running_processes()
        if still:
            _message(
                f"以下进程仍在运行，请手动关闭后重试：\n"
                f"{'、'.join(sorted({p.name for p in still}))}",
                error=True,
            )
            return 3
        if not quiet:
            _message(f"已自动关闭：{names}")

    try:
        result = patch.apply_patch(exe, days)
    except Exception as exc:
        _message(f"处理失败：\n\n{exc}", error=True)
        return 4

    if not result.changed:
        _message(f"无需处理。\n\n{result.lines[0] if result.lines else ''}")
        return 0

    lines = [
        f"处理完成。",
        f"",
        f"试用上限：{result.days} 天",
        f"文件：{exe}",
        f"备份：{result.backup.name if result.backup else '(已有)'}",
        f"",
        f"下一步：以普通用户身份启动 IDM（不要用管理员身份）。",
    ]
    _message("\n".join(lines))
    return 0


def cmd_restore(quiet: bool) -> int:
    exe = runtime.idm_exe()
    if exe is None:
        _message("找不到 IDM。", error=True)
        return 2

    if runtime.running_processes():
        _stop_idm()
        import time
        time.sleep(1.5)

    try:
        result = patch.restore(exe)
    except Exception as exc:
        _message(f"还原失败：\n\n{exc}", error=True)
        return 4

    msg = f"已还原为官方原版。\n\n文件：{exe}"
    if result.warning:
        msg += f"\n\n注意：{result.warning}"
    _message(msg)
    return 0


def cmd_stop() -> int:
    """结束所有 IDM 进程。

    提权后调用。普通权限下进程表可能是残缺的，taskkill 会回报「没找到」，
    但那是看不到而不是真没有；管理员权限才读得到完整进程表。
    """
    killed: list[str] = []
    denied: list[str] = []

    for name in C.IDM_PROCESSES:
        try:
            result = subprocess.run(
                ["taskkill", "/IM", name + ".exe", "/F"],
                capture_output=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            continue
        if result.returncode == 0:
            killed.append(name)
        elif result.returncode == 5:
            denied.append(name)

    if killed:
        _message("已关闭：\n\n" + "、".join(killed))
        return 0
    if denied:
        _message("以下进程拒绝访问：\n\n" + "、".join(denied), error=True)
        return 4
    _message("没有找到正在运行的 IDM 进程。")
    return 0


def cmd_export() -> int:
    try:
        out = reporter.export()
    except Exception as exc:
        _message(f"导出失败：{exc}", error=True)
        return 4
    _message(f"诊断报告已生成：\n\n{out}")
    return 0


def cmd_gui() -> int:
    from idmkit import ui
    return ui.run()


# ---- 参数 --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="idm-kit",
        description="IDM 6.43 build 15 试用期管理工具",
        add_help=True,
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--patch", action="store_true", help="把试用上限改成指定天数")
    g.add_argument("--restore", action="store_true", help="从备份还原为官方原版")
    g.add_argument("--export", action="store_true", help="导出诊断报告到桌面")
    g.add_argument("--check", action="store_true", help="在终端输出诊断报告")
    g.add_argument("--stop", action="store_true", help="结束所有 IDM 进程（提权后使用）")

    p.add_argument(
        "--days", type=int, default=C.DEFAULT_DAYS,
        help=f"试用上限天数，默认 {C.DEFAULT_DAYS}",
    )
    p.add_argument("--quiet", action="store_true", help="减少提示弹窗")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.patch:
        return cmd_patch(args.days, args.quiet)
    if args.restore:
        return cmd_restore(args.quiet)
    if args.export:
        return cmd_export()
    if args.check:
        return cmd_check()
    if args.stop:
        return cmd_stop()
    return cmd_gui()


if __name__ == "__main__":
    sys.exit(main())
