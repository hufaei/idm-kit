"""图形界面。

设计取舍：界面本身以普通权限启动，这样打开就能读状态；只有写 Program Files
的那一步才提权。若界面一开始就提权，用户会看到一切正常却依然无法排查权限
相关问题，而且"以管理员身份运行"正是浏览器扩展失效的头号原因。
"""

from __future__ import annotations

import os
import subprocess
import sys
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
        self.title("IDM 工具（管理员）" if self.elevated else "IDM 工具（普通权限）")
        self.configure(bg=BG)
        self.geometry("680x620")
        self.minsize(620, 560)

        self.diag: diagnose.Diagnosis | None = None
        self.exe: Path | None = runtime.idm_exe()
        self._watch_job: str | None = None

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
            head, text=f"支持版本 {C.FILE_VERSION_TEXT}", bg=BG, fg=MUTED,
            font=("Segoe UI", 9),
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

        self.btn_patch = self._action_button(bar, "激活", self.do_patch, primary=True)
        self.btn_restore = self._action_button(bar, "还原官方版", self.do_restore)
        self.btn_export = self._action_button(bar, "导出诊断", self.do_export)
        self.btn_start = self._action_button(bar, "启动 IDM", self.do_start)
        self.btn_stop = self._action_button(bar, "关闭 IDM", self.do_stop)

    def _action_button(self, parent, text, cmd, primary=False) -> tk.Button:
        b = tk.Button(
            parent, text=text, command=cmd,
            bg=ACCENT if primary else CARD,
            fg="#ffffff" if primary else FG,
            relief="solid", bd=1,
            activebackground=ACCENT if primary else BG,
            activeforeground="#ffffff" if primary else FG,
            font=("Microsoft YaHei UI", 10),
            padx=16, pady=7, cursor="hand2",
        )
        b.pack(side="left", padx=(0, 8))
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

        for i, c in enumerate(self.diag.checks):
            row = tk.Frame(self.inner, bg=CARD)
            row.grid(row=i, column=0, sticky="ew", padx=12, pady=0)
            row.columnconfigure(1, weight=1)

            color = _STATUS_COLOR.get(c.status, MUTED)
            tk.Label(
                row, text=_STATUS_SYMBOL.get(c.status, "·"), bg=CARD, fg=color,
                font=("Segoe UI", 9),
            ).grid(row=0, column=0, sticky="nw", padx=(2, 8), pady=(8, 0))

            tk.Label(
                row, text=c.title, bg=CARD, fg=FG,
                font=("Microsoft YaHei UI", 9, "bold"), anchor="w",
            ).grid(row=0, column=1, sticky="w", pady=(7, 0))

            tk.Label(
                row, text=c.fact, bg=CARD, fg=MUTED,
                font=("Microsoft YaHei UI", 8), anchor="w", justify="left",
                wraplength=520,
            ).grid(row=1, column=1, sticky="ew", pady=(0, 7))

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

        # 端口优先判断，见 runtime.idm_running()：只看进程列表会在权限不足
        # 时误报「没运行」，而这台机器上实测普通权限下只扫得到 23 个进程。
        running = runtime.idm_running()[0]
        self.btn_start.configure(state="disabled" if running is True else "normal")
        self.btn_stop.configure(state="normal" if running is True else "disabled")

    # ---- 动作 ----------------------------------------------------------

    def _elevated_run(self, args: list[str]) -> tuple[bool, str]:
        """以管理员身份重新启动本程序执行某个动作。

        界面自身不提权，只有真正需要写 Program Files 的动作才提权。这样
        打开工具时不会因为自身权限过高而误判 IDM 的权限状态。
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
            "还原后试用期会恢复成 30 天。",
        ):
            return
        self._run_inline_action("restore")

    def _run_inline_action(self, action: str) -> None:
        """尽量不提权。

        装到 Program Files 时文件归 Administrators 所有，必须提权；但如果 IDM
        装在用户可写的位置（例如非系统盘），直接改就行，不必让用户过一遍 UAC。
        """
        exe = self.exe
        if exe is None:
            return

        writable = _is_writable(exe)
        if writable and action == "patch":
            try:
                result = patch.apply_patch(exe, C.DEFAULT_DAYS)
            except Exception as exc:
                messagebox.showerror("失败", str(exc))
                return
            if result.changed:
                messagebox.showinfo(
                    "完成",
                    f"处理完成，无需管理员权限。\n\n"
                    f"试用上限：{result.days} 天\n文件：{exe}",
                )
            else:
                messagebox.showinfo("无需处理", "当前状态不需要改动。")
            self.refresh()
            return

        if writable and action == "restore":
            try:
                result = patch.restore(exe)
            except Exception as exc:
                messagebox.showerror("失败", str(exc))
                return
            messagebox.showinfo("完成", f"已还原为官方原版，无需管理员权限。\n\n{exe}")
            self.refresh()
            return

        # 文件不可写，只能提权
        ok, err = self._elevated_run([f"--{action}", "--quiet"])
        if not ok:
            messagebox.showerror("失败", err)
            return
        self.after(1200, self.refresh)

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
        exe = self.exe
        if exe is None:
            return

        # 关键：必须以普通权限启动 IDM，否则浏览器连不上它。
        #
        # 而本工具推荐以管理员身份运行，子进程默认继承管理员令牌 —— 直接
        # Popen 会把 IDM 拉成 High 完整性级别，浏览器（Medium）就再也无法
        # 通过 1001 通道连上它，扩展会报 Cannot launch IDM。
        #
        # 降权的办法是让 explorer.exe 代跑：它以登录用户身份常驻，
        # 由它启动的进程自然回到普通权限。
        try:
            if runtime.is_elevated():
                subprocess.Popen(
                    ["explorer.exe", str(exe)],
                    cwd=str(exe.parent),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                subprocess.Popen([str(exe)], cwd=str(exe.parent))
        except Exception as exc:
            messagebox.showerror("启动失败", str(exc))
            return
        self.after(2500, self.refresh)

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
            ok, err = self._elevated_run(["--stop"])
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
