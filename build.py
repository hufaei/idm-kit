"""打包工具。

默认产出 onedir 形态（一个文件夹，里面是 exe）：它不需要往临时目录解压，
因此在各种受限环境里都能启动。onefile 形态更便于分发，但每次运行都要解压
到 %TEMP%，容易被沙箱或安全软件干扰。

用法：
    python build.py                 # onedir（推荐，最可靠）
    python build.py --onefile       # 单文件 exe
    python build.py --console       # 保留控制台，便于看报错
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP_NAME = "IDM-Tool"
ENTRY = ROOT / "main.py"
DIST = ROOT / "dist"
BUILD = ROOT / "build"

# 明确排除没有用到的重型模块，控制体积
EXCLUDES = [
    "numpy", "PIL", "pytest", "setuptools", "pip",
    "unittest", "pydoc", "email", "http", "xml",
    "sqlite3", "multiprocessing", "distutils", "lib2to3",
]


def main() -> int:
    onefile = "--onefile" in sys.argv
    console = "--console" in sys.argv

    # 单文件形态会在运行前把自己解压到一个临时目录。默认走 %TEMP%，但在装了
    # 沙箱组件的机器上，引导器建不出 %TEMP% 下的目录，直接报：
    #     [PYI-xxxxx:ERROR] Could not create temporary directory!
    # 它会卡在那儿重试约 100 秒才弹框，每次启动都弹一次。
    #
    # 实测（2026-10-13）：同一台机器上
    #     %TEMP%             -> 失败
    #     指定 %LOCALAPPDATA% 下的目录 -> 失败
    #     _MEIPASS2 环境变量  -> 失败
    #     exe 同级目录 "."    -> 成功（4.7 秒启动，无残留）
    # 所以单文件默认把解压目录定在 exe 自己所在的位置。exe 放在用户可写的地方
    # 即可（桌面、下载目录都行）；放进 Program Files 这类只读位置会失败。
    tmpdir = "." if onefile else None
    if "--tmpdir" in sys.argv:
        i = sys.argv.index("--tmpdir")
        if i + 1 >= len(sys.argv):
            print("--tmpdir 后面要跟一个目录路径。")
            return 1
        tmpdir = sys.argv[i + 1]

    if not ENTRY.is_file():
        print(f"找不到入口文件：{ENTRY}")
        return 1

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("没有安装 PyInstaller。请先执行：")
        print("    pip install pyinstaller")
        return 1

    for d in (DIST, BUILD):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile" if onefile else "--onedir",
        "--console" if console else "--windowed",
        "--name", APP_NAME,
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(BUILD),
    ]
    if tmpdir:
        args += ["--runtime-tmpdir", tmpdir]
    for mod in EXCLUDES:
        args += ["--exclude-module", mod]
    args.append(str(ENTRY))

    print("打包中…（首次运行约需一到两分钟）")
    proc = subprocess.run(args, cwd=str(ROOT))
    if proc.returncode != 0:
        print("\n打包失败。")
        return proc.returncode

    target = DIST / (f"{APP_NAME}.exe" if onefile else f"{APP_NAME}/{APP_NAME}.exe")
    if not target.is_file():
        print(f"\n打包命令成功但找不到产物：{target}")
        return 1

    if onefile:
        size = target.stat().st_size / 1024 / 1024
        print(f"\n完成：{target}")
        print(f"体积：{size:.1f} MB（单文件）")
        print("\n注意：单文件形态每次运行都会解压到 %TEMP%，")
        print("      在受限环境或激进的安全软件下可能启动失败。")
    else:
        folder = target.parent
        total = sum(f.stat().st_size for f in folder.rglob("*") if f.is_file())
        print(f"\n完成：{target}")
        print(f"文件夹：{folder}")
        print(f"体积：{total / 1024 / 1024:.1f} MB（共 {len(list(folder.rglob('*')))} 个文件）")
        print("\n把整个文件夹一起复制过去，双击里面的 exe 即可运行。")
        print("它不依赖临时目录，比单文件形态更不容易启动失败。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
