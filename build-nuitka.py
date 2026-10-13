"""用 Nuitka 把工具编译成单个 exe。

与 build.py 的分工：
    build.py  PyInstaller，产出「解压式」exe，依赖少、启动快
    本脚本    Nuitka，把 Python 编译成机器码，源码不可还原

Nuitka 编译出来的 exe 不是加密产物 —— 它把 .py 变成 C 再编译成机器码，
看得到的是汇编，不是源码。需要真加密得用 Nuitka 商业版。

用法：
    python build-nuitka.py                 # 单文件，无控制台
    python build-nuitka.py --console       # 保留控制台便于看报错
    python build-nuitka.py --standalone    # 产出文件夹（启动更快）
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENTRY = ROOT / "main.py"
# 产物名保持 ASCII：中文名在 CI 的 shell 里会被编码坏掉（实测显示成
# IDM????.exe），进而把 --output-filename 传成非法值。中文用在产品名和
# 文件描述里，那些是给属性页看的。
APP_NAME = "IDM-Tool"


def _file_version() -> str:
    """从 idmkit.constants 取打包用的版本号。

    版本信息一旦给了任意一项，Nuitka 就要求连版本号一起给，所以这里必须有个
    确定的值，而不是省略。constants 里 FILE_VERSION 是元组 (6, 43, 15, 2)，
    FILE_VERSION_TEXT 才是点分字符串，两种形态都要能吃。
    """
    sys.path.insert(0, str(ROOT))
    try:
        from idmkit import constants as C

        v = getattr(C, "FILE_VERSION", None)
        if isinstance(v, (tuple, list)) and v:
            return ".".join(str(n) for n in v[:4])

        for attr in ("FILE_VERSION_TEXT", "VERSION"):
            text = getattr(C, attr, None)
            if text:
                parts = str(text).replace(",", ".").split(".")
                nums = [p for p in parts if p.isdigit()][:4]
                if nums:
                    return ".".join(nums)
    except Exception:
        pass
    return "1.0.0.0"


FILE_VERSION = _file_version()
OUT = ROOT / "dist-nuitka"

# 这些是 PyInstaller 用的裁剪项，Nuitka 不认，这里只保留真正需要的排除
EXCLUDES = [
    "pytest", "unittest", "pydoc", "doctest", "test",
]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    console = "--console" in sys.argv
    standalone = "--standalone" in sys.argv

    # 解压位置可以覆盖：某些机器上 %TEMP% 被拦，需要换地方。
    # Nuitka 的占位符：{TEMP} {CACHE_DIR} {HOME} {PROGRAM} 等，
    # 默认 {CACHE_DIR}/IDM-Tool 会落到 %LOCALAPPDATA%\Nuitka\... 之下。
    args_tmpdir = None
    if "--tmpdir" in sys.argv:
        i = sys.argv.index("--tmpdir")
        if i + 1 >= len(sys.argv):
            print("--tmpdir 后面要跟一个路径（可含 Nuitka 占位符）。")
            return 1
        args_tmpdir = sys.argv[i + 1]

    if not ENTRY.is_file():
        print(f"找不到入口文件：{ENTRY}")
        return 1

    try:
        import nuitka  # noqa: F401
    except ImportError:
        print("没有安装 Nuitka。请先执行：")
        print("    pip install nuitka")
        print("\nWindows 上还需要一个 C 编译器（MSVC 或 MinGW）。")
        return 1

    if OUT.exists():
        shutil.rmtree(OUT, ignore_errors=True)

    # 单文件形态要在运行前把自己解压出来，解压位置是编译期定死的。
    #
    # 本机实测（装了拦截组件时）：
    #   %TEMP%                        -> 拒绝：failed to open '...\Temp\onefile_x\main.dll'
    #   %LOCALAPPDATA%\IDM-Tool       -> 拒绝：failed to open '...\Local\IDM-Tool\IDM-Tool.exe'
    #   exe 所在目录                  -> 通过
    # 也就是说 %TEMP% 和 %LOCALAPPDATA% 整片写可执行文件都被拒，只有 exe 旁边能过。
    #
    # 默认取 {PROGRAM_DIR}（exe 所在目录）而不是系统缓存目录：在两处都被拦的
    # 机器上，这是唯一能跑起来的选择。解压内容会被复用，不会每次重来。
    # 普通机器（没有拦截组件）上两种都行，所以这个默认值不会伤到别人。
    # 需要换地方时用 --tmpdir 覆盖，例如 --tmpdir "{CACHE_DIR}/IDM-Tool"。
    tmp_spec = args_tmpdir or "{PROGRAM_DIR}/.idm-tool-cache"

    # Nuitka 的若干选项只认 --name=value 写法，用空格分隔会报
    # "option requires an argument with '='"。路径类参数尤其如此。
    args = [
        sys.executable, "-m", "nuitka",
        "--assume-yes-for-downloads",
        "--standalone" if standalone else "--onefile",
        f"--output-dir={OUT}",
        f"--output-filename={APP_NAME}.exe",
        # 关掉控制台窗口：这是给普通用户用的图形工具
        "--windows-console-mode=disable" if not console else
        "--windows-console-mode=force",
        "--enable-plugin=tk-inter",
        "--company-name=idm-kit",
        # 产品名用 ASCII：中文经 subprocess 传给 Nuitka 会被按 ANSI 代码页
        # 编坏（manifest 里出现 IDM????）。中文放进描述字段，那里是 UTF-8。
        f"--product-name={APP_NAME}",
        # 给了 company/file-description 就必须同时给版本号，否则 Nuitka 直接报
        # "company name and file or product version need to be given"。
        f"--file-version={FILE_VERSION}",
        f"--product-version={FILE_VERSION}",
        "--file-description=IDM 激活与自动更新管理工具",
        "--remove-output",
    ]
    if not standalone:
        args.append(f"--onefile-tempdir-spec={tmp_spec}")
    for mod in EXCLUDES:
        args.append(f"--nofollow-import-to={mod}")
    args.append(str(ENTRY))

    print("Nuitka 编译中…（首次编译需要几分钟到十几分钟）")
    start = time.time()
    proc = subprocess.run(args, cwd=str(ROOT))
    elapsed = time.time() - start

    if proc.returncode != 0:
        print(f"\n编译失败（退出码 {proc.returncode}）。")
        return proc.returncode

    if standalone:
        target = OUT / f"{APP_NAME}.dist" / f"{APP_NAME}.exe"
    else:
        target = OUT / f"{APP_NAME}.exe"

    print(f"\n编译完成，用时 {elapsed / 60:.1f} 分钟")
    if target.is_file():
        print(f"产物：{target}")
        print(f"大小：{target.stat().st_size / 1024 / 1024:.1f} MB")
    else:
        print(f"预期产物未找到：{target}")
        print(f"请检查 {OUT} 下的内容：")
        for p in sorted(OUT.rglob("*"))[:20]:
            print(f"    {p.relative_to(OUT)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
