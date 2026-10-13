"""IDM 6.43 build 15 工具集 —— 版本相关常量。

所有与具体 build 绑定的魔数集中在本模块。换 build 时只需要改这里，
其余模块不含任何硬编码的字节序列或文件偏移。
"""

from __future__ import annotations

# ---- 目标版本 ----------------------------------------------------------

FILE_VERSION = (6, 43, 15, 2)
FILE_VERSION_TEXT = ".".join(str(n) for n in FILE_VERSION)

# ---- 官方安装包 --------------------------------------------------------

INSTALLER_FILENAME = "idman643build15.exe"
INSTALLER_URL = (
    "https://download.internetdownloadmanager.com/idman643build15.exe"
)
INSTALLER_SHA256 = (
    "A902E77169A3E4D8A88EE2CCAAB11D3D43AB209483625A3602438ED4A22BBFD9"
)
INSTALLER_ARGS = ["/skipdlgs"]

# ---- IDMan.exe ---------------------------------------------------------

EXE_FILENAME = "IDMan.exe"
BACKUP_SUFFIX = ".bak"

#: 未改动的官方 IDMan.exe。白名单只认这一个哈希 —— 补丁后的产物哈希随
#: 天数变化，无法枚举，因此绝不能作为判据。
PRISTINE_SHA256 = (
    "E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8"
)

# ---- 补丁 A：试用上限的计算代码 ----------------------------------------
#
# 原始逻辑按注册状态算出 30 或 15 天，写进 [0x77bd28]：
#
#   A1 24BD7700   mov  eax, [0x77bd24]
#   F7 D8         neg  eax
#   1B C0         sbb  eax, eax
#   83 E0 0F      and  eax, 0xf
#   83 C0 0F      add  eax, 0xf          <- 只替换这 6 字节
#   A3 28BD7700   mov  [0x77bd28], eax
#
# 首尾两条指令带绝对地址，在 PE .reloc 表里各占一项。整块替换会让重定位
# 条目相对移位，加载器把映像基址差值加到错误位置，写坏新指令的地址字段。
# 因此只替换等长的中间算术，两端字节原样保留。

ANCHOR_A = bytes.fromhex("A124BD7700F7D81BC083E00F83C00FA328BD7700")
PATCH_A_AT = 9                       # 中间 6 字节在块内的偏移
PATCH_A_OLD = bytes.fromhex("83E00F83C00F")
PATCH_A_CODE = 6                     # 替换长度必须等于 len(PATCH_A_OLD)

#: 打补丁后依然存在的前缀，用于幂等探测。
PREFIX_A = ANCHOR_A[:PATCH_A_AT]

# ---- 补丁 B：.data 中的上限默认值 --------------------------------------
#
# 镜像 .data 里 [0x77bd28] 的初值本来就是 30。无论补丁 A 那段代码路径是否
# 执行，这个值在进程启动时就已经存在，所以必须一并改写。
#
# 锚点取目标 **之后** 的 8 字节（两个链接基址指针），绝不包含被改写的
# dword：否则补丁一落地锚点就消失，工具再也回不到现场。

ANCHOR_B = bytes.fromhex("38936900D0036A00")
ANCHOR_B_DELTA = -4                  # 目标位置 = 锚点位置 + DELTA
PATCH_B_OLD = (30).to_bytes(4, "little")
PATCH_B_LEN = 4

# ---- 补丁 C：跳过「IDM 主程序文件已损坏」警告 ---------------------------
#
# 改完前两个站点后，IDM 在下载时会弹一个模态警告框（标题 Internet Download
# Manager，带倒计时进度条和「继续下载」「打开 IDM 网站」两个按钮），冻结下载
# 直到倒计时走完。判定点：
#
#   0049BB6F  F6 86 84 00 00 00 08   test byte ptr [esi+0x84], 8    ; 守卫A
#   0049BB76  75 16                   jne  0x49BB8E
#   0049BB78  83 3D A0 93 78 00 00    cmp  dword ptr [0x7893A0], 0   ; 守卫B
#   0049BB7F  74 0D                   je   0x49BB8E                 <- 只替换这 2 字节
#   0049BB81  E8 9A D2 00 00          call 0x4A8E20                 ; 弹窗
#   0049BB86  85 C0                   test eax, eax
#   0049BB88  0F 84 0F 01 00 00       je   0x49BC9D
#   0049BB8E  ...                                                   后续正常流程
#
# 把 je 换成 jmp：不论守卫 B 的结论如何都跳到 0x49BB8E。弹窗调用连同它后面
# 那条返回值判断一并被跳过，代码从后续流程继续，行为等同于"守卫认为不该弹"。
# 守卫 A 原样保留，仍按位标志自主决定。
#
# 为什么不改上游：0x49A5F0 是守卫 B 那个标志唯一的写入点，它由消息 0x51 经
# 跳转表路由过来。实测改写索引表（0x9AA75 的 0x25 改成 0x6D）无效 —— 补丁
# 确实加载进内存，标志却照样被置 1，说明上游还有一层这里没吃透的调用。
# 改判断本身则不依赖对上游语义的任何理解，是硬性的。
#
# 锚点取判断代码本身（守卫A + 守卫B 共 16 字节），目标紧跟在后面。

ANCHOR_C = bytes.fromhex("F68684000000087516833DA093780000")
PATCH_C_AT = 16                      # 目标在锚点内的偏移
PATCH_C_OLD = bytes.fromhex("740D")  # je  rel8 +0x0D
PATCH_C_NEW = bytes.fromhex("EB0D")  # jmp rel8 +0x0D
PATCH_C_CODE = 2                     # 替换长度必须等于 len(PATCH_C_OLD)

# ---- 天数 --------------------------------------------------------------

DEFAULT_DAYS = 99999999              # 本工具的默认值
ORIGINAL_DAYS = 30                   # 官方未改动时的上限
MIN_USEFUL_DAYS = 31                 # <= 30 等于没打

# ---- 关键变量（RVA，相对映像基址）-------------------------------------

TRIAL_LIMIT_RVA = 0x37BD28           # 试用上限
REG_FLAG_RVA = 0x37BD24              # 注册状态标志

# ---- 注册表 ------------------------------------------------------------
#
# 实测：并不存在名为 Therad 的"已用天数"值。IDM 6.43 把可用的时间信息记在
# LastCheckQU（Unix 时间戳，秒），配合 LstCheck（可读日期）标出上一次检查
# 更新的时刻。据此可以预测下一次自动更新，提前提醒用户。

REG_KEY_MAIN = r"Software\DownloadManager"

REG_VALUE_LAST_CHECK_QU = "LastCheckQU"   # 上次检查更新的 Unix 时间戳
REG_VALUE_LAST_CHECK = "LstCheck"         # 上次检查更新的可读日期
REG_VALUE_VERSION_TAG = "idmvers"         # 例："v6.43b15 Trial"
REG_VALUE_CURRENT_BUILD = "vCOUFP"        # 例："643b15"
REG_VALUE_LAUNCH_ON_START = "LaunchOnStart"
REG_VALUE_ENABLE_DRIVER = "EnableDriver"
REG_VALUE_EXE_PATH = "ExePath"          # IDM 自己写：实际运行的 exe 完整路径

#: 卸载信息所在的键。实测 InstallLocation 是空值，只有 UninstallString 可用；
#: 去掉文件名即安装目录。IDM 允许装到非系统盘（安装器是 NSIS，支持 /D=），
#: 所以不能把安装路径写死。
REG_UNINSTALL_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Internet Download Manager",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Internet Download Manager",
)
REG_VALUE_UNINSTALL_STRING = "UninstallString"

#: 最后的后备：注册表都读不到时的猜测。放在最后是因为 IDM 可以装在别处。
IDM_DIR_CANDIDATES = (
    r"C:\Program Files (x86)\Internet Download Manager",
    r"C:\Program Files\Internet Download Manager",
)

#: 二进制中的原文：IDM checks for a new release every 2 weeks
UPDATE_CHECK_INTERVAL_DAYS = 14

# ---- 浏览器扩展 --------------------------------------------------------

EXT_CHROME_ID = "ngpampappnmepgilojfohadhhmbhlaek"
EXT_EDGE_ID = "llbjbkhnmlidjebalopleeepgdfgcpec"
EXT_CHROME_FILE = "IDMGCExt.crx"
EXT_EDGE_FILE = "IDMEdgeExt.crx"
EXT_FIREFOX_FILE = "idmmzcc3.xpi"

#: Chrome 系扩展目录（注册表自动安装路径）
REG_EXT_CHROME = (
    rf"SOFTWARE\Google\Chrome\Extensions\{EXT_CHROME_ID}",
    rf"SOFTWARE\WOW6432Node\Google\Chrome\Extensions\{EXT_CHROME_ID}",
)
REG_EXT_EDGE = (
    rf"SOFTWARE\Microsoft\Edge\Extensions\{EXT_EDGE_ID}",
    rf"SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\{EXT_EDGE_ID}",
)

BROWSER_PROFILE_DIRS = {
    "Chrome": r"{localappdata}\Google\Chrome\User Data",
    "Edge": r"{localappdata}\Microsoft\Edge\User Data",
    "Brave": r"{localappdata}\BraveSoftware\Brave-Browser\User Data",
}
FIREFOX_PROFILE_DIR = r"{appdata}\Mozilla\Firefox\Profiles"

# ---- 网络与驱动 --------------------------------------------------------

BROWSER_PORT = 1001
WFP_SERVICE = "IDMWFP"
WFP_DRIVER_FILES = ("idmwfp.sys", "idmwfp64.sys", "idmtdi64.sys")

# ---- 进程 --------------------------------------------------------------

IDM_PROCESSES = (
    "IDMan",
    "IEMonitor",
    "idmBroker",
    "IDMMsgHost",
    "IDMIntegrator64",
    "MediumILStart",
)

#: 打补丁前必须全部退出
BLOCKING_PROCESSES = IDM_PROCESSES

# ---- 外部链接（提示用）------------------------------------------------

IDM_WEBSITE = "https://www.internetdownloadmanager.com/"
