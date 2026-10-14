"""IDM 6.43 build 15 工具集 —— 版本相关常量。

所有与具体 build 绑定的魔数集中在本模块。换 build 时只需要改这里，
其余模块不含任何硬编码的字节序列或文件偏移。
"""

from __future__ import annotations

# ---- 版本号 ------------------------------------------------------------
#
# 这里有两套版本号，语义不同，不能混用：
#
#   FILE_VERSION   本工具能处理的 IDMan.exe 版本，也就是 IDM 自己的版本。
#                  它绑死补丁偏移，换 build 时这里和站点定义一起改。
#   TOOL_VERSION   工具本身的版本。发布时用它打 tag、写进 exe 的文件属性，
#                   以及显示在标题栏。
#
# 早先把 IDM 的版本号拿去当工具的 tag（v6.43.15.2、v6.43.15.3），结果分成
# 不清哪个数字涨了：是 IDM 换了 build，还是工具改了一行。现在分开。

#: 本工具能处理的 IDM 版本（6.43 build 15）。
FILE_VERSION = (6, 43, 15, 2)
FILE_VERSION_TEXT = ".".join(str(n) for n in FILE_VERSION)

#: 工具自己的版本。发布时用它打 tag（形如 ``tool-v0.1.1``）、写进 exe 的
#: 文件属性，并显示在界面上。
#:
#: 这里是**本地构建的默认值**。正式发布由 CI 从 tag 推导，经
#: ``build-nuitka.py --version`` 覆盖 —— tag 才是唯一来源，两者不一致时以
#: tag 为准。仍要记得同步，别让数字互相矛盾。
TOOL_VERSION = "0.1.1"

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

# ---- 补丁 D：取消自动更新 -------------------------------------------------
#
# IDM 每次运行都会走一个周期判定，决定「这次要不要去检查更新」。判定逻辑
# 在 0x56E93，反汇编如下（rva 均为链接基址 0x400000 下的地址）：
#
#   0x56ED8  push 'LastCheckQU'
#   0x56EE4  call RegQueryValueExA      ; 读上次检查的时刻
#   0x56EEC  jne  0x56F30               ; 读不到 -> 返回 1（该去检查）
#   0x56EF6  call time()                ; 当前时刻
#   0x56F01  sub  eax, esi              ; now - LastCheckQU
#   0x56F07  push 0x15180               ; 86400 秒
#   0x56F0E  call 0x240a40              ; 64 位有符号除法 -> 已过天数
#   0x56F13  mov  ecx, 6                ; 阈值：6 天     <- 只替换这 5 字节
#   0x56F18  cmp  ecx, eax
#   0x56F1A  sbb  eax, eax
#   0x56F1C  neg  eax                   ; 返回 (6 > 已过天数)
#   0x56F2F  ret
#
# 返回值 1 才会真的去检查更新。把阈值从 6 改成 0 之后，任何已过天数都满足
# `0 > days` 为假，函数恒返回 0，等于「不需要检查」。
#
# 实测依据（2026-10-13）：删掉注册表 LastCheckQU 后重启 IDM，IDM 在 60 秒内
# 建立到 67.18.60.145:443 的连接，6 秒后把 LastCheckQU 写成当前时间戳。
# 也就是说这条链路是活的，且 LastCheckQU 是它自己盖的时间戳。
#
# 为什么改阈值而不是改入口：0x56E93 只做「要不要检查」的判断，不涉及下载和
# 替换，改它不会影响「帮助 -> 检查更新」这个手动入口，也不改变任何界面文案。
#
# 锚点取目标之前的三条指令（push edx; push eax; call），不含被改写的 5 字节。
# 实测该锚点在原始文件与已补丁文件中各命中恰好 1 次。

ANCHOR_D = bytes.fromhex("5250E82D9B1E00")   # 0x56F0C .. 0x56F13
PATCH_D_AT = 7                               # 目标 = 锚点位置 + 7
PATCH_D_OLD = bytes.fromhex("B906000000")    # mov ecx, 6
PATCH_D_NEW = bytes.fromhex("B900000000")    # mov ecx, 0
PATCH_D_CODE = 5                             # 替换长度必须等于 len(PATCH_D_OLD)

#: 已打过「取消自动更新」的完整文件哈希（A+B+C+D+E，默认天数）。
#: 只作参考，判据仍以站点内容为准 —— 见 README「状态检查」一节。
PREV_AUTOUPDATE_STOPPED_SHA256 = ""

# ---- 补丁 E：掐断自动更新的定时器分支 -------------------------------------
#
# 补丁 D 只改了「要不要检查」的判据，实测不足以关掉自动更新 —— 因为真正去
# 检查的那条链路根本不看这个返回值。它的实际触发路径是：
#
#   IDM 的窗口过程 0x86D58 用跳转表按消息号分派：
#       0x86D98  movzx eax, byte ptr [eax + 0x488514]   ; 索引表，一字节一条消息
#       0x86D9F  jmp   dword ptr [eax*4 + 0x488470]     ; 目标表，四项一条消息
#   索引 = 消息号 - 1。消息 5 的条目是第 4 项：
#       rva 0x88518 = 0x02  ->  目标 rva 0x88478 = 0x487C8B
#
#   0x487C8B 这个分支做四件事：
#       0x87C93  KillTimer(hwnd, 5)                     ; 先把自己停掉
#       0x87CA8  call 0x38430                          ; 问「现在有没有活动」
#       0x87CB7  je 0x87D0B                            ; 没活动 -> 只重设定时器
#       0x87CF8  RegSetValueExA('LastCheckQU')          ; 写「刚检查过」的时间戳
#       0x87D16  SetTimer(hwnd, 5, 0x1D4C0)             ; 2 分钟后再来一次
#
# 索引表旁边还有一个 0x28 的条目，指向 0x488449 —— 那个地址是空处理（直接
# 返回）。把消息 5 的索引字节从 0x02 改成 0x28，这条分支就整条不再执行，
# 定时器也就没人续期了。
#
# 实测依据（2026-10-13）：只打补丁 D 时，清空 LastCheckQU 后重启 IDM，两轮
# 里有一轮仍然建立到 67.18.60.145:443 的连接并重写时间戳；改成同时打 D 和 E
# 之后，同样的刺激不再出现连网。
#
# 索引表与目标表在文件里是连着的（目标表 rva 0x88470，索引表 rva 0x88514，
# 相差 0xA4 = 41 项 × 4 字节）。
#
# 锚点必须**完全落在目标字节之前**：要改的那个字节本身就是锚点内容的一部分时，
# 改完之后锚点就消失了，第二次运行既定位不到、也判定不出「已经改过」。这和站点
# A 用前缀、站点 C 用 PATCH_C_AT 是同一个理由。这里取目标前 12 字节，实测在原
# 始文件与已补丁文件里都唯一命中。

ANCHOR_E = bytes.fromhex("a77148004984480000282801")
PATCH_E_AT = 12                              # 目标 = 锚点位置 + 12
PATCH_E_OLD = bytes.fromhex("02")            # 分派到 0x487C8B（会去检查更新）
PATCH_E_NEW = bytes.fromhex("28")            # 分派到空处理 0x488449
PATCH_E_CODE = 1

# ---- 补丁 F：静默「未注册 / 假序列号」催购弹窗 ---------------------------
#
# 现象：补丁 A-E 全部就位后，每次添加下载（浏览器接管或命令行 /d）仍会弹一个
# 「IDM has not been registered for 30 days. Trial period is over.」的置顶
# 警告框；纯启动不弹。关掉后下载完全正常。
#
# 调查结论（2026-10-13，逆向 + 动态抓栈验证）：这条 nag 与补丁 A/B 改写的
# 试用上限是**两套独立机制**。生成函数 0x4757D0(type) 在栈上逐字节拼出
# XOR-0x17 加密的文案（所以全文件搜不到明文），按参数二选一：
#
#   type == 9 -> "IDM has not been registered for 30 days. Trial period is over."
#   其他       -> "Internet Download Manager has been registered with a fake
#                 Serial Number or the Serial Number has been blocked. ..."
#
# 再经封装 0x474EE0（全局开关 byte [0x788C2D] 分派）送进 0x46DCE0，装一个
# WH_CBT 钩子后 MessageBoxW，样式 0x41030 = MB_ICONEXCLAMATION |
# MB_SYSTEMMODAL | MB_TOPMOST。全程不读 [0x77BD28] / [0x77BD24] —— 上限改成
# 多大它都照弹，「上限不可达 = 所有下游判定失效」对这条 nag 不成立。
#
# 函数以 cdecl 回调被调度（尾部 0x47626B 是裸 ret），入口即返则栈自平衡；
# 序言此处尚未分配任何资源，跳过全部逻辑没有清理问题。两条催购文案一并静默。
# 代价是函数尾部那记 Sleep(250) + PostMessage(WM_COMMAND, 0x149B) 一并跳过，
# 实测（2026-10-13）手动关掉弹窗走完这条尾巴与直接跳过，下载行为没有差别。
#
# 锚点取目标之后 11 字节（push 0x66885B ; mov eax, fs:[0]），不含被改的
# 1 字节 —— 与站点 A 用前缀、C/D/E 取目标之前是同一条硬规则。目标前的
# push -1 是 6A FF 两字节中的第一个。

ANCHOR_F = bytes.fromhex("685B886600" + "64A100000000")
PATCH_F_AT = -2                              # 目标 = 锚点位置 - 2（push -1 的 6A）
PATCH_F_OLD = bytes.fromhex("6A")            # push -1
PATCH_F_NEW = bytes.fromhex("C3")            # ret
PATCH_F_CODE = 1

# ---- 补丁 F2：第二个催购分派器 -------------------------------------------
#
# 2026-10-14 续报：F1（0x4757D0）已确认生效后，「Trial period is over」
# 仍在新进程里弹出。趁弹窗在场抓栈，调用链指向 0x47C880 —— 同一个 nag
# 调度开关（0x4944E3 跳转表）里的**第二个分派器**，注册点 0x4950FF 就在
# F1 的 0x4951B2 旁边。结构与 F1 相同：按参数选文案（试用催购 / 假序列号
# 警告），文案同样是栈上逐字节构造的密文（这个用 XOR 0x0B）。
#
# 它还多一层自续期：弹完 Sleep(250ms) + PostMessage(0x149F)，再
# Sleep(0x975E0)（约 10.3 分钟）+ PostMessage(0x14B2) 重弹 —— 长会话里
# 弹窗越叠越多就是它干的。入口即返后整条链含自续期一并失效。
#
# 调度开关里另有 0x474D90 / 0x476270 等回调也调弹窗封装，但文案来源与
# 用途未确认（可能是正经提示），**不打** —— 只杀已被栈证据钉死的两个
# 催购分派器。

ANCHOR_F2 = bytes.fromhex("68BB906600" + "64A100000000")
PATCH_F2_AT = -2                             # 目标 = 锚点位置 - 2（push -1 的 6A）
PATCH_F2_OLD = bytes.fromhex("6A")           # push -1
PATCH_F2_NEW = bytes.fromhex("C3")           # ret
PATCH_F2_CODE = 1

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
REG_VALUE_CHECK_UPDT_VM = "CheckUpdtVM"   # 更新检查状态标记（IDM 写入 "10"）
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

#: 桌面等系统文件夹的真实位置。不能拼 Path.home()/"Desktop" —— 桌面可能被
#: 重定向到 OneDrive，也可能被企业策略移到别的盘，拼出来的路径在那种机器上
#: 并不存在。
REG_KEY_SHELL_FOLDERS = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
)
REG_KEY_USER_SHELL_FOLDERS = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)

#: 最后的后备：注册表都读不到时的猜测。放在最后是因为 IDM 可以装在别处。
IDM_DIR_CANDIDATES = (
    r"C:\Program Files (x86)\Internet Download Manager",
    r"C:\Program Files\Internet Download Manager",
)

#: 自动检查更新的周期（天）。
#:
#: 取值来自二进制，不是官方帮助里的说法。周期判定在 0x56E93，把「距上次检查
#: 的天数」算出来之后与 6 比较（0x56F13：mov ecx, 6），返回值 1 才真的去查。
#: 所以「距上次检查不足 6 天就不再检查（也不重复写时间戳）」是它的真实节奏。
#: 帮助里那句 "checks for a new release every 2 weeks" 说的是发布节奏，不是
#: 检查节奏，两者不能混用。
UPDATE_CHECK_INTERVAL_DAYS = 6

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
