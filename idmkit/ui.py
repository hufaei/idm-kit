"""图形界面。

界面以什么权限启动由用户决定，标题栏会写明当前是「管理员」还是「普通权限」。
推荐以管理员身份运行：普通权限下进程表可能是残缺的，实测同一台机器上打包版
只扫到 23 个进程，而源码运行能看到 360 个 —— 关闭 IDM 这类操作会莫名失败。

提权带来一个副作用：子进程会继承令牌。所以「启动 IDM」不能直接 Popen，
必须走 `runtime.launch_idm()` 让 IDM 回到普通权限，否则浏览器（Medium）会被
UIPI 挡在 1001 通道之外，扩展反而报 Cannot launch IDM。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import constants as C
from . import diagnose, patch, reporter, runtime

# ---- 配色（浅色，避免默认灰的呆板感）----------------------------------

BG = "#f7f7f5"
CARD = "#ffffff"
FG = "#1c1c1e"
MUTED = "#6b6b70"
LINE = "#e2e2df"
OK = "#1a7f4b"
WARN = "#a86a00"
FAIL = "#c02a2a"
ACCENT = "#1f4fd8"

_STATUS_COLOR = {
    diagnose.STATUS_OK: OK,
    diagnose.STATUS_WARN: WARN,
    diagnose.STATUS_FAIL: FAIL,
    diagnose.STATUS_INFO: MUTED,
}
_STATUS_SYMBOL = {
    diagnose.STATUS_OK: "●",
    diagnose.STATUS_WARN: "▲",
    diagnose.STATUS_FAIL: "■",
    diagnose.STATUS_INFO: "·",
}

# 这些检查项只在排查时才有意义，界面上不显示，但导出报告里一条不少。
# 「程序版本」「安装目录」这类信息，使用者平时不需要看到；
# 「更新周期」在自动更新关掉之后更是自相矛盾。
_TECHNICAL_KEYS = frozenset({
    "version",    # 程序版本 —— 结论里版本不匹配时会单独提示
    "install",    # 安装路径 —— 使用者不需要知道装在哪
    "update",     # 更新周期预告 —— 关掉自动更新后已无意义
    "process",    # IDM 进程 —— 按钮状态本身就在反映这件事
    "driver",     # 网络驱动 —— 只有出故障时才需要看
    "channel",    # 浏览器通道 —— 同上
    "integrity",  # IDM 运行权限 —— 底部已经提示过一次，列表里不必再说
})


def _friendly_result(action: str, result) -> str:
    """把操作结果翻译成用户能看懂的话。

    刻意不包含地址、锚点、字节这类内容 —— 使用者要做的是确认「事情成了没有、
    我接下来该干什么」，而不是读一份改动清单。想核对细节的人可以点「导出诊断」，
    完整的技术信息在那里。

    只有出问题时才提到细节：失败是需要排查的，那时信息越多越好。
    """
    days = result.days or C.DEFAULT_DAYS

    if action == "cancel-update":
        if result.autoupdate_stopped:
            return ("IDM 不会再自动联网检查新版本了，\n"
                    "以后也不会被新版本覆盖掉。\n\n"
                    "想核对改动细节，点「导出诊断」。")
        return ("试用期限制已经处理好了。\n\n"
                "但自动更新还有一处没能关掉，IDM 仍有可能联网检查新版本。\n"
                "建议点「导出诊断」把结果发出来。")

    if action == "silence-nag":
        if result.nag_silenced:
            return ("以后添加下载不会再弹「试用结束，请购买」的提示了。\n\n"
                    "它本来就不影响下载，只是催购；关掉图个清净。\n"
                    "想核对改动细节，点「导出诊断」。")
        return ("处理已完成。\n\n"
                "但催购弹窗的改写点没能确认，可能还会弹。\n"
                "建议点「导出诊断」把结果发出来。")

    # 「激活」
    return (f"IDM 已激活，可以正常下载。\n\n"
            f"不会再出现试用到期（上限 {days} 天）。\n"
            f"下载时如果弹过「主程序文件已损坏」，也不会再弹。")


def _done_text(action: str) -> str:
    """提权执行完成后给用户的确认。

    提权路径拿不到 result 对象，所以这里只说结论；想看细节就走「导出诊断」。
    """
    if action == "cancel-update":
        return ("IDM 不会再自动检查更新了，\n以后也不会被新版本覆盖掉。")
    if action == "silence-nag":
        return ("以后添加下载不会再弹「试用结束」的催购提示了。")
    if action == "restore":
        return ("已还原成官方原版。\n\n"
                "注意：试用期限制和自动更新也一起恢复成官方状态了。")
    return ("IDM 已激活，可以正常下载，不会再出现试用到期。")


def _title_for(action: str, done: bool) -> str:
    if action == "cancel-update":
        return "自动更新已关闭" if done else "取消自动更新"
    if action == "silence-nag":
        return "催购弹窗已静默" if done else "静默催购弹窗"
    if action == "restore":
        return "已还原" if done else "还原官方版"
    return "已激活" if done else "激活"


def _is_writable(path: Path) -> bool:
    """实际试着打开来写，而不是读 ACL。

    ACL 的继承规则、只读属性、文件占用都会影响结果，判断"能不能改"最可靠的
    办法就是真去试一次。这里只打开不写入，代价可以忽略。
    """
    try:
        with open(path, "r+b"):
            return True
    except OSError:
        return False


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        # 权限状态直接写进标题。普通权限下进程表可能是残缺的（实测只扫到
        # 23 个进程），关闭 IDM 这类操作用管理员身份运行才不会遇到怪现象。
        self.elevated = runtime.is_elevated()
        self.title(
            f"IDM 工具 v{C.TOOL_VERSION}"
            + ("（管理员）" if self.elevated else "（普通权限）")
        )
        self.configure(bg=BG)
        self.geometry("780x660")
        self.minsize(700, 560)

        self.diag: diagnose.Diagnosis | None = None
        self.exe: Path | None = runtime.idm_exe()
        self._watch_job: str | None = None
        self._start_deadline = 0.0
        self._stop_deadline = 0.0
        # 提权执行完拿不到返回值，先记下待告知的操作，等刷新完成再弹回执。
        self._pending_notice: tuple[str, str] | None = None

        self._build()
        self.refresh()

        # IDM 默认开机自启，用户打开界面时它可能还没起来。只靠打开那一刻的
        # 快照，按钮状态会一直是旧的：IDM 明明在跑，界面却让点「启动 IDM」。
        self._watch_processes()
        self.bind("<FocusIn>", self._on_focus)

    def _watch_processes(self) -> None:
        """低频同步按钮状态。

        完整 refresh 要读文件、查注册表、跑 sc 查询，代价不小；但"进程在不在"
        只要一次快照，很便宜，所以这里只刷按钮，不重跑诊断。
        """
        if not self.winfo_exists():
            return
        try:
            self._sync_buttons()
        except Exception:
            pass
        self._watch_job = self.after(3000, self._watch_processes)

    def _on_focus(self, _event=None) -> None:
        """切回窗口时对齐一次，省得用户等轮询周期。"""
        try:
            self._sync_buttons()
        except Exception:
            pass

    # ---- 构建 ----------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_header()
        self._build_verdict()
        self._build_checks()
        self._build_actions()
        self._build_footer()

    def _build_header(self) -> None:
        head = tk.Frame(self, bg=BG)
        head.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 8))
        head.columnconfigure(0, weight=1)

        tk.Label(
            head, text="IDM 工具", bg=BG, fg=FG,
            font=("Segoe UI", 16, "bold"),
        ).grid(row=0, column=0, sticky="w")

        tk.Label(
            head, text=f"版本 {C.TOOL_VERSION}　·　支持 IDM {C.FILE_VERSION_TEXT}",
            bg=BG, fg=MUTED, font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        self.btn_refresh = tk.Button(
            head, text="刷新", command=self.refresh,
            bg=CARD, fg=FG, relief="solid", bd=1,
            activebackground=BG, font=("Microsoft YaHei UI", 9),
            padx=14, pady=4, cursor="hand2",
        )
        self.btn_refresh.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_verdict(self) -> None:
        wrap = tk.Frame(self, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        wrap.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        wrap.columnconfigure(1, weight=1)

        self.lbl_dot = tk.Label(
            wrap, text="●", bg=CARD, fg=MUTED, font=("Segoe UI", 14),
        )
        self.lbl_dot.grid(row=0, column=0, sticky="nw", padx=(14, 8), pady=(14, 0))

        self.lbl_verdict = tk.Label(
            wrap, text="正在检查…", bg=CARD, fg=FG,
            font=("Microsoft YaHei UI", 12, "bold"), anchor="w", justify="left",
        )
        self.lbl_verdict.grid(row=0, column=1, sticky="ew", padx=(0, 14), pady=(12, 0))

        self.lbl_cause = tk.Label(
            wrap, text="", bg=CARD, fg=MUTED,
            font=("Microsoft YaHei UI", 9), anchor="w", justify="left",
            wraplength=560,
        )
        self.lbl_cause.grid(row=1, column=1, sticky="ew", padx=(0, 14))

        self.lbl_action = tk.Label(
            wrap, text="", bg=CARD, fg=ACCENT,
            font=("Microsoft YaHei UI", 9, "bold"), anchor="w", justify="left",
            wraplength=560,
        )
        self.lbl_action.grid(row=2, column=1, sticky="ew", padx=(0, 14), pady=(4, 14))

    def _build_checks(self) -> None:
        outer = tk.Frame(self, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        outer.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 10))
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(outer, bg=CARD, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        bar = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        bar.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=bar.set)

        self.inner = tk.Frame(self.canvas, bg=CARD)
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(
                self.canvas.find_all()[0], width=e.width
            ),
        )
        # 鼠标滚轮
        self.canvas.bind_all(
            "<MouseWheel>",
            lambda e: self.canvas.yview_scroll(int(-e.delta / 120), "units"),
        )

    def _build_actions(self) -> None:
        bar = tk.Frame(self, bg=BG)
        bar.grid(row=3, column=0, sticky="ew", padx=18)
        # 中间一列吃掉多余宽度，把两组按钮分别推到最左和最右。用 grid 而不是
        # pack(side=...)，是为了让左右分组由明确的列号决定，不依赖创建顺序。
        bar.columnconfigure(4, weight=1)

        # 按「对 IDM 做处理」和「围绕使用」分成左右两组，中间留空。六个按钮
        # 平铺一排时，使用者要读完每个才能找到要点的那个；分组之后位置固定：
        # 想改 IDM 就往左看，想开或关就往右看。
        self.btn_patch = self._action_button(
            bar, 0, "激活", self.do_patch, primary=True)
        # 特意与「激活」分开：关掉自动更新是使用者的选择，不该在激活时顺手做掉。
        self.btn_cancel_update = self._action_button(
            bar, 1, "取消自动更新", self.do_cancel_update)
        # 与「取消自动更新」同理：催购弹窗不影响下载，关不关由使用者决定。
        self.btn_silence_nag = self._action_button(
            bar, 2, "静默催购弹窗", self.do_silence_nag)
        self.btn_restore = self._action_button(
            bar, 3, "还原官方版", self.do_restore)

        self.btn_export = self._action_button(
            bar, 5, "导出诊断", self.do_export)
        self.btn_start = self._action_button(
            bar, 6, "启动 IDM", self.do_start)
        self.btn_stop = self._action_button(
            bar, 7, "关闭 IDM", self.do_stop)

    def _action_button(self, parent, col: int, text, cmd,
                       primary=False) -> tk.Button:
        b = tk.Button(
            parent, text=text, command=cmd,
            bg=ACCENT if primary else CARD,
            fg="#ffffff" if primary else FG,
            relief="solid", bd=1,
            activebackground=ACCENT if primary else BG,
            activeforeground="#ffffff" if primary else FG,
            font=("Microsoft YaHei UI", 10),
            padx=13, pady=7, cursor="hand2",
        )
        b.grid(row=0, column=col, sticky="w", padx=(0, 6))
        return b

    def _build_footer(self) -> None:
        foot = tk.Frame(self, bg=BG)
        foot.grid(row=4, column=0, sticky="ew", padx=18, pady=(10, 14))
        foot.columnconfigure(0, weight=1)

        self.lbl_hint = tk.Label(
            foot, text="", bg=BG, fg=MUTED,
            font=("Microsoft YaHei UI", 8), anchor="w", justify="left",
            wraplength=620,
        )
        self.lbl_hint.grid(row=0, column=0, sticky="ew")

        tk.Label(
            foot, text="查看完整说明：使用说明.md", bg=BG, fg=ACCENT,
            font=("Microsoft YaHei UI", 8, "underline"), cursor="hand2",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

    # ---- 数据 ----------------------------------------------------------

    def refresh(self) -> None:
        self.btn_refresh.configure(state="disabled", text="检查中…")
        self.update_idletasks()
        try:
            self.exe = runtime.idm_exe()
            self.diag = diagnose.diagnose(self.exe)
        except Exception as exc:
            self.diag = None
            self.lbl_verdict.configure(text="检查时出错", fg=FAIL)
            self.lbl_cause.configure(text=str(exc))
            return
        finally:
            self.btn_refresh.configure(state="normal", text="刷新")

        self._render_verdict()
        self._render_checks()
        self._render_footer()
        self._sync_buttons()
        self._flush_pending_notice()

    def _flush_pending_notice(self) -> None:
        """刷新完成后补发提权操作的回执。

        提权走的是独立进程，拿不到返回值，所以只能等刷新把真实状态读回来，
        再告诉用户结果 —— 这样回执反映的是文件的实际状态，不是我们的猜测。
        """
        pending, self._pending_notice = self._pending_notice, None
        if pending is None:
            return
        action, _ = pending
        messagebox.showinfo(_title_for(action, done=True), _done_text(action))

    def _render_verdict(self) -> None:
        d = self.diag
        if d is None:
            return
        color = _STATUS_COLOR.get(d.severity, MUTED)
        self.lbl_dot.configure(fg=color)
        self.lbl_verdict.configure(text=d.verdict, fg=color if d.severity != diagnose.STATUS_OK else FG)
        self.lbl_cause.configure(text=d.cause)
        self.lbl_action.configure(text=("建议：" + d.action) if d.action else "")

    def _render_checks(self) -> None:
        for child in self.inner.winfo_children():
            child.destroy()
        if self.diag is None:
            return

        # 界面上只留使用者真正关心的几项：能不能用、自动更新关没关、有没有退路。
        # 「程序版本」「安装目录」这类只在出问题时才有意义的项从界面上撤下来 ——
        # 它们一条不少地留在「导出诊断」的报告里，排查时不会缺东西。
        shown = [c for c in self.diag.checks if c.key not in _TECHNICAL_KEYS]

        for i, c in enumerate(shown):
            row = tk.Frame(self.inner, bg=CARD)
            row.grid(row=i, column=0, sticky="ew", padx=14, pady=(0, 2))
            row.columnconfigure(1, weight=1)

            color = _STATUS_COLOR.get(c.status, MUTED)
            tk.Label(
                row, text=_STATUS_SYMBOL.get(c.status, "·"), bg=CARD, fg=color,
                font=("Segoe UI", 9),
            ).grid(row=0, column=0, sticky="nw", padx=(2, 9), pady=(9, 0))

            tk.Label(
                row, text=c.title, bg=CARD, fg=FG,
                font=("Microsoft YaHei UI", 9, "bold"), anchor="w",
            ).grid(row=0, column=1, sticky="w", pady=(8, 0))

            tk.Label(
                row, text=c.fact, bg=CARD, fg=MUTED,
                font=("Microsoft YaHei UI", 9), anchor="w", justify="left",
                wraplength=520,
            ).grid(row=1, column=1, sticky="ew", pady=(1, 8))

        self.inner.columnconfigure(0, weight=1)

    def _render_footer(self) -> None:
        d = self.diag
        hints = []
        if d is not None:
            for c in d.checks:
                if c.key in ("integrity", "update") and c.action:
                    hints.append(c.action)
        if not hints:
            hints.append("不要以管理员身份运行 IDM，否则浏览器无法把下载交给它。")
        self.lbl_hint.configure(text="　".join(hints))

    def _sync_buttons(self) -> None:
        installed = self.exe is not None and self.exe.is_file()
        has_backup = (
            self.exe is not None
            and self.exe.with_name(self.exe.name + C.BACKUP_SUFFIX).is_file()
        )
        state = "normal" if installed else "disabled"
        self.btn_patch.configure(state=state)
        self.btn_restore.configure(state="normal" if has_backup else "disabled")
        self.btn_export.configure(state="normal")

        # 「取消自动更新」在已关闭时就地变成状态显示，而不是留一个点了没反应的
        # 按钮 —— 使用者一眼就能看出这件事已经做过了。
        stopped = bool(self.diag is not None
                       and self.diag.context.get("autoupdate_stopped"))
        # 加勾但**不改名**：按钮叫「取消自动更新」就一直是这个名字，做过了用
        # 勾和置灰表示。改名字会让使用者下次找不到自己刚才点的那个按钮。
        self.btn_cancel_update.configure(
            text="✓ 取消自动更新" if stopped else "取消自动更新",
            state="disabled" if stopped else ("normal" if installed else "disabled"),
        )

        # 「静默催购弹窗」与上面同一套状态呈现逻辑。
        silenced = bool(self.diag is not None
                        and self.diag.context.get("nag_silenced"))
        self.btn_silence_nag.configure(
            text="✓ 静默催购弹窗" if silenced else "静默催购弹窗",
            state="disabled" if silenced else ("normal" if installed else "disabled"),
        )

        # 判据以进程枚举为主，端口不能当作 IDM 在运行的证据 —— 1001 由
        # IDMWFP 驱动常驻占用，驱动在就一直在监听。详见 runtime.idm_running()。
        running = runtime.idm_running()[0]
        # 「启动 IDM」的语义是「确保它以普通权限运行」，所以 IDM 正在跑时也得
        # 可点：权限不对就引导关掉重开，权限正常则只做一次状态确认（见 do_start）。
        # 早先它在 running is True 时是禁用的，恰好把最需要修的那个状态挡在门外 ——
        # IDM 以管理员权限运行时按钮是灰的，用户根本点不到。
        self.btn_start.configure(state=state)
        self.btn_stop.configure(state="normal" if running is True else "disabled")

    # ---- 动作 ----------------------------------------------------------

    def _elevated_run(self, args: list[str]) -> tuple[bool, str]:
        """以管理员身份重新启动本程序执行某个动作。

        只有普通权限下做不到的事才走这里：写 Program Files、结束权限更高的
        IDM 进程。界面自身是否提权由用户决定，标题栏会显示当前权限。
        """
        import ctypes

        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(args)
        else:
            exe = sys.executable
            main_py = Path(__file__).resolve().parent.parent / "main.py"
            params = subprocess.list2cmdline([str(main_py)] + args)

        try:
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, str(Path.cwd()), 1
            )
        except Exception as exc:
            return False, f"提权失败：{exc}"

        # ShellExecuteW 返回值 <= 32 表示失败；5 通常是用户点了"否"
        if rc <= 32:
            return False, f"提权未成功（返回码 {rc}）。可能是取消了授权。"
        return True, ""

    def do_patch(self) -> None:
        if self.exe is None:
            return
        if not messagebox.askokcancel(
            "激活",
            "将把 IDM 的试用上限改写成一个极大的值。\n\n"
            "处理前需要先关闭 IDM（如果正在运行）。\n"
            "原始文件会备份为 IDMan.exe.bak，可随时还原。\n\n"
            "过程中会弹出一次管理员授权，请点「是」。",
        ):
            return
        self._run_inline_action("patch")

    def do_restore(self) -> None:
        if not messagebox.askokcancel(
            "还原官方版",
            "将把 IDMan.exe 还原成备份中的官方原版。\n"
            "还原后试用期会恢复成 30 天，自动更新也会恢复开启。",
        ):
            return
        self._run_inline_action("restore")

    def do_cancel_update(self) -> None:
        if self.exe is None:
            return
        if not messagebox.askokcancel(
            "取消自动更新",
            "将改写 IDMan.exe 里「要不要检查更新」的周期判定，"
            "让 IDM 不再自动去查新版本。\n\n"
            "处理前需要先关闭 IDM（如果正在运行）。\n"
            "这个改动独立于「激活」，只影响自动更新。\n"
            "想恢复自动更新，点「还原官方版」即可。\n\n"
            "过程中可能弹出一次管理员授权，请点「是」。",
        ):
            return
        self._run_inline_action("cancel-update")

    def do_silence_nag(self) -> None:
        if self.exe is None:
            return
        if not messagebox.askokcancel(
            "静默催购弹窗",
            "未注册状态下，IDM 每次添加下载都会弹一次「试用结束，请购买」"
            "的置顶提示。\n\n"
            "它不影响下载，纯粹是催购；这个动作会把生成弹窗的函数入口改成"
            "直接返回，两条催购文案（含假序列号警告）一并静默。\n\n"
            "处理前需要先关闭 IDM（如果正在运行）。\n"
            "这个改动独立于「激活」。\n"
            "过程中可能弹出一次管理员授权，请点「是」。",
        ):
            return
        self._run_inline_action("silence-nag")

    def _is_official_bak(self) -> bool:
        """备份是不是真正的官方原版。

        IDM 自动更新覆盖 IDMan.exe 之后，用户往往会在覆盖后才点「激活」，
        于是 .bak 存下来的其实是「被覆盖的那个版本」而不是官方原版；老版本
        的 .bak 也可能根本是打过补丁的。还原前必须确认，否则那句「已还原为
        官方原版」就是假的。
        """
        if self.exe is None:
            return False
        bak = self.exe.with_name(self.exe.name + C.BACKUP_SUFFIX)
        try:
            data = bak.read_bytes()
        except OSError:
            return False
        return patch.is_pristine(patch.sha256_of(data))

    def _run_inline_action(self, action: str) -> None:
        """尽量不提权。

        装到 Program Files 时文件归 Administrators 所有，必须提权；但如果 IDM
        装在用户可写的位置（例如非系统盘），直接改就行，不必让用户过一遍 UAC。
        """
        exe = self.exe
        if exe is None:
            return

        label = {"patch": "激活", "restore": "还原官方版",
                 "cancel-update": "取消自动更新",
                 "silence-nag": "静默催购弹窗"}.get(action, action)
        days = C.DEFAULT_DAYS

        # 「取消自动更新」「静默催购弹窗」既要能在激活过的文件上补打，也要能
        # 独立使用，所以只有它们带各自的开关；「激活」两个都不动。
        if action == "restore":
            official = self._is_official_bak()

        writable = _is_writable(exe)
        if writable:
            try:
                if action == "restore":
                    result = patch.restore(exe)
                else:
                    result = patch.apply_patch(
                        exe, days,
                        cancel_autoupdate=(action == "cancel-update"),
                        silence_nag=(action == "silence-nag"))
            except Exception as exc:
                messagebox.showerror("失败", str(exc))
                return

            if action == "restore":
                if official:
                    text = ("已还原成官方原版。\n\n"
                            "注意：试用期限制和自动更新也一起恢复成官方状态了。")
                else:
                    text = (
                        "已把备份里的文件装回去了。\n\n"
                        "但这份备份不是官方原版（多半是当初激活之后才做的备份），"
                        "所以试用期和自动更新并没有恢复成官方状态。\n\n"
                        "要真正回到官方原版，需要重新安装 IDM。"
                    )
                messagebox.showinfo(_title_for(action, done=True), text)
                self.refresh()
                return

            if not result.changed:
                messagebox.showinfo(
                    "已经处理过了",
                    "当前不需要再做改动。\n\n"
                    "IDM 已经是激活状态，说明之前处理过。\n"
                    "想核对细节可以点「导出诊断」。",
                )
                self.refresh()
                return

            if action == "cancel-update" and not result.autoupdate_stopped:
                detail = "\n".join(f"　{line}" for line in result.lines)
                messagebox.showwarning(
                    "没能完全关掉",
                    "试用期限制已经处理好了。\n\n"
                    "但自动更新还有一处没能关掉，IDM 仍有可能联网检查新版本。\n"
                    "建议点「导出诊断」把结果发出来。\n\n"
                    f"技术细节：\n{detail}",
                )
            elif action == "silence-nag" and not result.nag_silenced:
                detail = "\n".join(f"　{line}" for line in result.lines)
                messagebox.showwarning(
                    "没能静默",
                    "处理已完成，但催购弹窗的改写点没能确认，可能还会弹。\n"
                    "建议点「导出诊断」把结果发出来。\n\n"
                    f"技术细节：\n{detail}",
                )
            else:
                title = _title_for(action, done=True)
                messagebox.showinfo(title, _friendly_result(action, result))
            self.refresh()
            return

        # 文件不可写，只能提权。注意这里必须给回执 —— 早先的版本执行完只是
        # 静默刷新，用户在提权场景下完全看不到「到底改没改」，只能靠猜。
        ok, err = self._elevated_run([f"--{action}", "--quiet"])
        if not ok:
            messagebox.showerror("失败", err)
            return
        self._pending_notice = (action, "")
        self.after(900, self.refresh)

    def do_export(self) -> None:
        try:
            out = reporter.export(diag=self.diag)
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        if messagebox.askyesno(
            "导出完成",
            f"诊断报告已生成：\n{out}\n\n是否打开所在文件夹？",
        ):
            try:
                subprocess.Popen(["explorer", "/select,", str(out)])
            except Exception:
                pass

    def do_start(self) -> None:
        """让 IDM 跑起来，而且必须是普通权限。

        这是「扩展报 Cannot launch IDM」的正面解法：工具提权是为了读完整
        进程表，可它拉起的 IDM 绝不能继承管理员令牌 —— 浏览器以 Medium
        运行，UIPI 不允许它连接更高完整性的进程，1001 通道会被重置。
        真正干活的是 runtime.launch_idm()。
        """
        exe = self.exe
        if exe is None:
            return

        idm = runtime.idm_process()
        if idm is not None:
            # 已经在跑：权限不对就重开，而不是再拉一个新的
            if runtime.is_elevated_level(idm.integrity):
                self._restart_idm_as_user(idm)
            else:
                messagebox.showinfo(
                    "已经在运行",
                    f"IDM 正以{idm.integrity_label}权限运行（pid {idm.pid}），"
                    "浏览器可以连接它。",
                )
            return

        running, why = runtime.idm_running()
        if running is None:
            messagebox.showwarning(
                "无法确认",
                f"{why}\n\n以管理员身份运行本工具才能读到完整进程表。",
            )
            return

        result = runtime.launch_idm(exe)
        if not result.ok:
            messagebox.showerror("启动失败", result.detail)
            return

        # 不假设降权一定成功 —— shell 会不会照做不属于我们的契约，
        # 只有回读到的完整性级别才算证据。见 _await_start。
        self._start_deadline = time.monotonic() + 12
        self._await_start()

    def _await_start(self) -> None:
        """启动后回读校验。

        用 after 轮询而不是 sleep：在界面线程里阻塞十几秒，窗口会假死。
        判据是读回来的权限级别，不是「Popen 没抛异常」。
        """
        if not self.winfo_exists():
            return

        idm = runtime.idm_process()

        if idm is None:
            if time.monotonic() >= self._start_deadline:
                messagebox.showwarning(
                    "没有等到 IDM",
                    "12 秒内没有检测到 IDMan 进程。\n\n"
                    "可以双击桌面上的 IDM 图标打开它 —— 那条路径一定以"
                    "普通权限运行。",
                )
                self.refresh()
                return
            self.after(500, self._await_start)
            return

        self.refresh()
        if runtime.is_elevated_level(idm.integrity):
            messagebox.showwarning(
                "IDM 仍然是管理员权限",
                f"IDM（pid {idm.pid}）以{idm.integrity_label}权限运行，"
                "浏览器依然连不上它。\n\n"
                "请双击桌面上的 IDM 图标启动 —— 那条路径不走本工具，"
                "一定是普通权限。",
            )
        elif idm.readable:
            messagebox.showinfo(
                "已启动",
                f"IDM（pid {idm.pid}）以{idm.integrity_label}权限运行，"
                "浏览器可以连接它。",
            )
        else:
            messagebox.showinfo(
                "已启动",
                f"IDM（pid {idm.pid}）已启动，但读不到它的权限级别。\n\n"
                "点「刷新」重新检查。",
            )

    def _restart_idm_as_user(self, idm: runtime.ProcInfo) -> None:
        """当前 IDM 权限过高：关掉它，再以普通权限拉起来。"""
        if not messagebox.askokcancel(
            "需要重新启动 IDM",
            f"IDM 正以{idm.integrity_label}权限运行，浏览器（普通权限）连不上它 —— "
            "这正是扩展报 Cannot launch IDM 的原因。\n\n"
            "关闭它并以普通权限重新启动吗？关闭时需要一次管理员授权。",
        ):
            return

        ok, err = self._elevated_run(["--stop", "--quiet"])
        if not ok:
            messagebox.showerror("失败", err)
            return

        self._stop_deadline = time.monotonic() + 15
        self._await_stopped()

    def _await_stopped(self) -> None:
        """等提权子进程把 IDM 关掉，然后走正常启动流程。"""
        if not self.winfo_exists():
            return

        if runtime.idm_process() is None:
            self.do_start()
            return

        if time.monotonic() >= self._stop_deadline:
            messagebox.showwarning(
                "没有关掉",
                "IDM 仍在运行。请手动关闭它，再点「启动 IDM」。",
            )
            return
        self.after(600, self._await_stopped)

    def do_stop(self) -> None:
        if not messagebox.askokcancel("关闭 IDM", "将结束所有 IDM 相关进程。"):
            return

        running, why = runtime.idm_running()

        # 端口不通而且进程表里也没有 —— 那确实没什么可关的
        if running is False:
            messagebox.showinfo("没有需要关闭的", "IDM 当前没有运行。")
            self.refresh()
            return

        # 按映像名结束，而不是先枚举拿 PID。枚举结果受权限影响 —— 普通权限下
        # 可能一个都拿不到，那时循环体一次都不执行，用户看到的就是「点了没反应」。
        # 交给 taskkill 自己去找，它不需要我们先枚举。
        names = [n + ".exe" for n in C.IDM_PROCESSES]
        kicked: list[str] = []
        blocked: list[str] = []

        for name in names:
            try:
                result = subprocess.run(
                    ["taskkill", "/IM", name, "/F"],
                    capture_output=True, timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                blocked.append(name)
                continue
            # 返回码 128 是「没有找到该进程」，不算失败；
            # 返回码 5 是「拒绝访问」，那个才是真的没权限。
            if result.returncode == 0:
                kicked.append(name)
            elif result.returncode == 5:
                blocked.append(name)

        if kicked:
            self.after(900, self.refresh)
            if blocked:
                messagebox.showwarning(
                    "部分未关闭",
                    "以下进程拒绝访问：\n" + "、".join(blocked),
                )
            return

        # 一个都没杀到。如果端口说它明明在跑，那问题就不是「不存在」而是权限：
        # 普通权限下进程表可能是残缺的，taskkill 看不到目标，只能回报「没找到」。
        if running is True:
            if not messagebox.askokcancel(
                "需要管理员权限",
                f"IDM 正在运行（{why}），但当前权限看不到它的进程，无法结束。\n\n"
                "用管理员权限再试一次吗？会弹出授权提示。",
            ):
                return
            ok, err = self._elevated_run(["--stop", "--quiet"])
            if not ok:
                messagebox.showerror("失败", err)
                return
            self.after(1800, self.refresh)
            return

        # 端口没监听、进程表也读不完整 —— 说不清，别硬给结论
        messagebox.showinfo(
            "没有找到",
            "没有找到正在运行的 IDM 进程，它可能已经关掉了。",
        )
        self.refresh()


def run() -> int:
    app = App()
    app.mainloop()
    return 0
