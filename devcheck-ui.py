"""开发期自检：验证界面确实渲染出了预期内容。不属于发布产物。"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tkinter as tk

from idmkit.ui import App


def main() -> int:
    app = App()
    app.update()

    print("窗口标题:", app.title())
    print("窗口尺寸:", app.geometry())
    print()
    print("--- 界面上的全部文字 ---")

    def walk(w, depth=0):
        for c in w.winfo_children():
            cls = c.winfo_class()
            if cls in ("Label", "Button"):
                try:
                    t = c.cget("text")
                except Exception:
                    t = ""
                if t:
                    kind = "BUTTON" if cls == "Button" else "label "
                    extra = ""
                    try:
                        extra = "  [state=" + str(c.cget("state")) + "]"
                    except Exception:
                        pass
                    print("  " * depth + kind + ": " + t + extra)
            walk(c, depth + 1)

    walk(app)

    print()
    print("--- 按钮可用性 ---")
    for name, btn in [
        ("激活", app.btn_patch),
        ("取消自动更新", app.btn_cancel_update),
        ("静默催购弹窗", app.btn_silence_nag),
        ("还原官方版", app.btn_restore),
        ("导出诊断", app.btn_export),
        ("启动 IDM", app.btn_start),
        ("关闭 IDM", app.btn_stop),
    ]:
        print(f"  {name:<12} {btn.cget('state')}")

    print()
    print("--- 诊断结论 ---")
    if app.diag:
        print("  严重度:", app.diag.severity)
        print("  结论  :", app.diag.verdict)
        print("  原因  :", app.diag.cause)
        print("  检查项:", len(app.diag.checks))

    app.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
