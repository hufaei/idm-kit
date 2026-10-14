"""程序入口。

无参数时启动图形界面。带参数时以命令行模式运行 —— 界面通过提权重启自身并
传入这些参数来完成需要管理员权限的动作，因此这里必须能在没有控制台的
环境下工作，结果用系统弹窗呈现。
"""

from __future__ import annotations

import argparse
import subprocess
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
    """在终端输出诊断报告。

    实测：打包成 GUI 程序后这个子命令不产生输出 —— 此时 `sys.stdout` 并不是
    None，而是一个指向无效句柄的对象，print 写进去看不到，但进程仍以正确的
    退出码结束。无法用 isatty() 区分这种情况和 `--check > report.txt` 这类
    重定向（两者都不是终端），所以这里保持"总是 print"：重定向照常工作，
    GUI 版静默。界面里用不到这个子命令。
    """
    d = diagnose.diagnose()
    text = diagnose.render_text(d)
    if sys.stdout is not None:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0 if d.severity == diagnose.STATUS_OK else 1


def _stop_running_idm(quiet: bool) -> tuple[bool, str]:
    """结束正在运行的 IDM。返回 (可以继续, 错误说明)。"""
    running = runtime.running_processes()
    if not running:
        return True, ""

    names = "、".join(sorted({p.name for p in running}))
    _stop_idm()
    import time
    time.sleep(1.5)

    still = runtime.running_processes()
    if still:
        return False, (
            f"以下进程仍在运行，请手动关闭后重试：\n"
            f"{'、'.join(sorted({p.name for p in still}))}"
        )
    if not quiet:
        _message(f"已自动关闭：{names}")
    return True, ""


def _parse_days(text: str, default: int) -> int:
    """天数既接受十进制，也接受 0x 开头的十六进制。

    十六进制在这里不是花活：上限字段是 4 字节无符号数，0xFFFFFFFF 这种写法
    比它的十进制形式好核对得多。
    """
    text = (text or "").strip()
    if not text:
        return default
    try:
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        raise patch.PatchError(
            f"天数「{text}」不是整数。可以写十进制，也可以写 0x 开头的十六进制。"
        ) from None
    if not (1 <= value <= 0xFFFFFFFF):
        raise patch.PatchError("天数必须是 1 到 4294967295（0xFFFFFFFF）之间的整数。")
    return value


def cmd_patch(days: int, quiet: bool) -> int:
    exe = runtime.idm_exe()
    if exe is None:
        _message("找不到 IDM，无法处理。", error=True)
        return 2

    ok, err = _stop_running_idm(quiet)
    if not ok:
        _message(err, error=True)
        return 3

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


def cmd_cancel_update(quiet: bool) -> int:
    """取消自动更新：停掉那条定时器分支，让 IDM 不再自动去查新版本。

    IDM 的实际检查动作由它的窗口过程按消息号分派出去，和「距上次检查过了
    几天」那个判据是两条独立的链路 —— 只改判据挡不住，两个改写点都要动。

    文件若尚未激活，会一并完成激活 —— 那条路径本来就要改同样的字节，
    没有理由让使用者分两步走。
    """
    exe = runtime.idm_exe()
    if exe is None:
        _message("找不到 IDM，无法处理。", error=True)
        return 2

    ok, err = _stop_running_idm(quiet)
    if not ok:
        _message(err, error=True)
        return 3

    try:
        # 天数不在这里暴露：本动作的语义是「关掉自动更新」，上限沿用文件里
        # 已有的值，或者用默认值补齐尚未激活的文件。
        result = patch.apply_patch(
            exe, C.DEFAULT_DAYS, cancel_autoupdate=True)
    except Exception as exc:
        _message(f"处理失败：\n\n{exc}", error=True)
        return 4

    lines = [f"文件：{exe}"]
    if result.days is not None:
        lines.append(f"试用上限：{result.days} 天")
    lines.extend(result.lines)

    if result.autoupdate_stopped:
        head = "自动更新已取消。IDM 不会再自动检查更新、也不会被更新覆盖。"
    else:
        head = (
            "未能确认自动更新已关闭：\n"
            "IDMan.exe 里找不到可识别的改写点（需要两个都改到）。"
            "文件未被改动。"
        )
    _message(head + "\n\n" + "\n".join(lines))
    return 0


def cmd_silence_nag(quiet: bool) -> int:
    """静默催购弹窗：把 nag 生成函数的入口改成直接返回。

    未注册状态下 IDM 每次添加下载都会弹「试用结束，请购买」。它与试用上限
    是两套独立机制 —— 上限补丁全绿它也照弹，所以单独提供一个动作。

    文件若尚未激活，会一并完成激活 —— 那条路径本来就要改同样的字节，
    没有理由让使用者分两步走。
    """
    exe = runtime.idm_exe()
    if exe is None:
        _message("找不到 IDM，无法处理。", error=True)
        return 2

    ok, err = _stop_running_idm(quiet)
    if not ok:
        _message(err, error=True)
        return 3

    try:
        # 天数不在这里暴露：本动作的语义是「关掉催购弹窗」，上限沿用文件里
        # 已有的值，或者用默认值补齐尚未激活的文件。
        result = patch.apply_patch(
            exe, C.DEFAULT_DAYS, silence_nag=True)
    except Exception as exc:
        _message(f"处理失败：\n\n{exc}", error=True)
        return 4

    lines = [f"文件：{exe}"]
    if result.days is not None:
        lines.append(f"试用上限：{result.days} 天")
    lines.extend(result.lines)

    if result.nag_silenced:
        head = "催购弹窗已静默。以后添加下载不会再弹「试用结束」的提示。"
    else:
        # 按实际字节状态说实话：只说「文件未被改动」在两个改写点都找不到时
        # 才对；已经改成一个的场合文件其实变了，而且那种情况再点一次能补齐。
        state = patch.inspect(exe.read_bytes())
        sites = (state.site_f, state.site_f2)
        done = sum(1 for s in sites if s is not None and s.state == patch.APPLIED)
        if done:
            head = (
                f"催购弹窗有 {done}/{len(sites)} 处改写点已改好 —— 文件已经变了，\n"
                "但没能全部就位，弹窗可能照旧会弹。\n"
                "关闭 IDM 后再执行一次，通常就能补齐。"
            )
        else:
            head = (
                "未能确认催购弹窗已静默：\n"
                "IDMan.exe 里找不到可识别的改写点。文件未被改动。"
            )
    _message(head + "\n\n" + "\n".join(lines))
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
        official = patch.is_pristine(patch.sha256_of(
            exe.with_name(exe.name + C.BACKUP_SUFFIX).read_bytes()))
    except Exception:
        official = True   # 备份读不出来时交给 restore() 自己报错

    try:
        result = patch.restore(exe)
    except Exception as exc:
        _message(f"还原失败：\n\n{exc}", error=True)
        return 4

    if official:
        msg = f"已还原为官方原版。\n\n文件：{exe}"
    else:
        msg = (
            "已用备份覆盖了当前的 IDMan.exe。\n\n"
            "但这份备份并不是官方原版（多半是当初激活后才备份的），"
            "所以试用期和自动更新不会恢复成官方状态。\n\n"
            "要真正回到官方原版，请重装 IDM。"
        )
    if result.warning:
        msg += f"\n\n注意：{result.warning}"
    _message(msg)
    return 0


def cmd_stop(quiet: bool = False) -> int:
    """结束所有 IDM 进程。

    提权后调用。普通权限下进程表可能是残缺的，taskkill 会回报「没找到」，
    但那是看不到而不是真没有；管理员权限才读得到完整进程表。

    任何异常都记进 denied，不允许被静默吞掉 —— 这个动作的失败必须说出来。
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
            denied.append(name)
            continue
        if result.returncode == 0:
            killed.append(name)
        elif result.returncode == 5:
            denied.append(name)

    if denied:
        _message("以下进程拒绝访问：\n\n" + "、".join(denied), error=True)
        return 4
    if killed:
        if not quiet:
            _message("已关闭：\n\n" + "、".join(killed))
        return 0
    if not quiet:
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
    g.add_argument("--cancel-update", action="store_true",
                   help="取消自动更新（IDM 不再自动检查新版本）")
    g.add_argument("--silence-nag", action="store_true",
                   help="静默催购弹窗（添加下载时不再弹「试用结束」提示）")
    g.add_argument("--restore", action="store_true", help="从备份还原为官方原版")
    g.add_argument("--export", action="store_true", help="导出诊断报告到桌面")
    g.add_argument("--check", action="store_true", help="在终端输出诊断报告")
    g.add_argument("--stop", action="store_true", help="结束所有 IDM 进程（提权后使用）")

    p.add_argument(
        "--days", type=str, default=str(C.DEFAULT_DAYS),
        help=f"试用上限天数，默认 {C.DEFAULT_DAYS}；也接受 0x 开头的十六进制",
    )
    p.add_argument("--quiet", action="store_true", help="减少提示弹窗")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.patch or args.cancel_update or args.silence_nag:
        try:
            days = _parse_days(args.days, C.DEFAULT_DAYS)
        except patch.PatchError as exc:
            _message(str(exc), error=True)
            return 2
        if args.cancel_update:
            return cmd_cancel_update(args.quiet)
        if args.silence_nag:
            return cmd_silence_nag(args.quiet)
        return cmd_patch(days, args.quiet)
    if args.restore:
        return cmd_restore(args.quiet)
    if args.export:
        return cmd_export()
    if args.check:
        return cmd_check()
    if args.stop:
        return cmd_stop(args.quiet)
    return cmd_gui()


if __name__ == "__main__":
    sys.exit(main())
