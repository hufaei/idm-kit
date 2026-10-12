# idm-kit

Internet Download Manager 6.43 build 15 的试用期上限离线补丁，以及在一台新机器上从零部署的脚本。

只针对下面这一个精确版本做过验证，其他 build 一律拒绝执行。

## 版本矩阵

| 项 | 值 |
|---|---|
| 产品版本 | `6, 43, 15, 2` |
| 官方安装包 | `idman643build15.exe` |
| 安装包 SHA256 | `A902E77169A3E4D8A88EE2CCAAB11D3D43AB209483625A3602438ED4A22BBFD9` |
| `IDMan.exe` SHA256（原始） | `E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8` |
| `IDMan.exe` SHA256（已补丁） | `AC81B41812EE1BABC3B7E0D606012C706D598ED27B9610E24563494D9D1E8D58` |

## 原理

试用期上限是全局变量 `[0x77bd28]`。判定在 `0x46753c`：

```asm
0x467539  mov  ecx, [ebp-0x24]     ; 已用天数（来自注册表 Therad）
0x46753c  cmp  ecx, [0x77bd28]     ; 与上限比较
0x467542  jae  0x4675c2            ; 已用 >= 上限 -> 过期分支
```

上限本身由 `0x44cf37` 的代码块按注册状态算成 30 或 15：

```asm
A1 24 BD 77 00   mov  eax, [0x77bd24]
F7 D8            neg  eax
1B C0            sbb  eax, eax
83 E0 0F         and  eax, 0xf
83 C0 0F         add  eax, 0xf        ; -> 30 或 15
A3 28 BD 77 00   mov  [0x77bd28], eax
```

把上限改成一个不可达的大数，所有下游判定一并失效。

## 两处补丁

| 补丁 | 文件偏移 | 定位锚点 | 原始 | 补丁后 |
|---|---|---|---|---|
| A：上限计算 | `0x4C340`（6 字节） | `0x4C337`（整块 20 字节，只改 `[9..14]`） | `83 E0 0F 83 C0 0F` | `B8 FF E0 F5 05 90` |
| B：`.data` 默认值 | `0x379528`（4 字节） | `0x37952C`（目标**之后** 8 字节，目标 = 锚点 − 4） | `1E 00 00 00`（30） | `FF E0 F5 05`（99999999） |

两处地址都由锚点搜索得到，脚本里没有写死任何一个文件偏移。

补丁 A 只替换中间那段纯算术（`and eax,0xf` + `add eax,0xf` → `mov eax,99999999` + `nop`），等长 6 字节，两端带绝对地址的指令一字不动。那两条指令在 PE `.reloc` 表里各占一项（RVA `0x4CF38` / `0x4CF47`）；如果整块替换，第一个 disp32 会相对重定位项平移一个字节，加载器把映像基址差值加错位置，直接写坏新指令的地址字段——补丁会打开一个非法写入地址。

补丁 B 是必须的。`[0x77bd28]` 在镜像 `.data` 里的默认值本来就是 30，代码路径跑不跑，这个值在启动时就已存在。

锚点的选择有一条硬规则：**锚点字节区间不得覆盖被本补丁修改的字节**，否则补丁一落地锚点就消失，脚本再也回不到现场。A 的锚点覆盖整块 20 字节，但只重写其中 `[9..14]`，两端带绝对地址的指令保持原样，所以补丁后依旧可匹配。B 最初把目标 dword 本身（`1E 00 00 00`）包含进锚点，打丁后锚点永久失效，`verify.ps1` 直接报 `anchor found 0x`——改用目标之后的 8 字节（`38 93 69 00 D0 03 6A 00`，两个链接基址指针 `0x699338` / `0x6A03D0`）后，锚点在原始与已补丁文件中各出现恰好 1 次，实测通过。

## 用法

### 新机器一键部署

```powershell
# 以管理员身份运行
.\bootstrap.ps1
```

下载官方安装包 → 校验 SHA256 → 静默安装 → 停掉 IDM 进程 → 打补丁 → 回读校验。

### 已安装，只打补丁

```powershell
# 以管理员身份运行
.\patch-IDM.ps1
```

### 查看当前状态

```powershell
.\verify.ps1
```

### 回滚

```powershell
.\patch-IDM.ps1 -Revert
```

有 `.bak` 才能回滚。首次打补丁时脚本会自动生成。

## 验证

补丁是否真的生效，看运行中进程的 `[0x77bd28]`：补丁前 30，补丁后 99999999。

本机实测：

| | 补丁前 | 补丁后 |
|---|---|---|
| `[0x77bd28]` 运行时值 | `1E 00 00 00` = **30** | `FF E0 F5 05` = **99999999** |

读取方式：对 `IDMan.exe` 模块基址加 RVA `0x37BD28` 做 `ReadProcessMemory`。

## 查看剩余试用天数

IDM 自己的"剩余天数"提示框只在剩余 <= 15 天时才会自动弹（`0x4876d2`: `cmp eax,0xf / ja`）。
打了补丁之后剩余天数永远是个天文数字，所以 IDM 再也不会主动弹它了 —— 这正是想要的效果，
代价是界面上没有常驻的地方能看天数。

用 `days-left.ps1` 随时把它调出来：

```powershell
.\days-left.ps1
```

它从运行中的进程读上限（`[0x77bd28]`），从注册表读已用天数（`Therad`），算出真实剩余值，
再用 IDM 自己的 `WM_COMMAND (0x111, id 0x13ca)` 弹出提示框。

实测输出：

```
上限 : 99999999
已用 : 0
剩余 : 99999999
```

弹出来的框内容：

> 您还有 99999999 天的剩余时间来试用 Internet Download Manager。您希望现在注册 IDM 副本吗？

注意：

- IDM 必须正在运行
- 这是模态框，点掉之前 IDM 界面会暂时无响应，点"否"关闭
- 帮助 → 关于 IDM 显示的是授权状态（"未注册版本"），不显示天数
- 注册 → 注册 是纯输入表单（名字 / 姓氏 / 电子邮件 / 序列号），也不显示天数

## 地址层次：为什么换机器也有效

看到 `0x77bd28` 这类地址，容易误以为补丁依赖运行时地址、换机器就会失效。实际要分三层看：

| 层次 | 例子 | 是否固定 | 本方案是否依赖 |
| --- | --- | --- | --- |
| 文件偏移 | `0x4C340`、`0x379528` | 同一 build 固定 | 是（落笔位置），但由锚点搜索得出，脚本未写死 |
| RVA | `0x37BD28` | 同一 build 固定 | 是（配合运行时基址） |
| 运行时 VA | `0x77BD28`、`0x134BD28` | ASLR 每次都变 | 否 |

补丁改的是**磁盘文件里的字节**，发生在加载之前，此时 ASLR 还没介入。`0x77bd28` 只是链接基址
（`0x400000`）下的 VA，它出现在指令的操作数字段里（文件字节 `28 BD 77 00`），加载时由 `.reloc`
表修正。脚本从不写这个地址，只在锚点里匹配这些字节。

- Patch A 的两条绝对寻址指令（`A1 24 BD 77 00` / `A3 28 BD 77 00`）**字节保持原样**，所以
  `.reloc` 条目依然对得上；只替换中间的 6 字节算术。这是 v2 相对 v1 的关键修正。
- Patch B 改的 `.data` 初值是 `int` 而非指针，本身没有重定位条目。
- `days-left.ps1` 读内存时用 `模块运行时基址 + 0x37BD28`，这是 ASLR 正确的写法。

**换机器的前提**：同一个 `IDMan.exe`（SHA256 `E3FC655A…BBFD8`）。同一个安装包装出来的文件字节
完全相同，所以锚点匹配、补丁结果也完全相同。SHA256 allowlist 把住这一关，不同 build 会在写盘
之前 abort。

实测：整个文件里两个锚点在原始与已补丁文件中各只出现 1 次；pristine → patched 的输出哈希确定为
`AC81B418…E8D58`；多次重启 IDM，运行时基址在 `0x3A0000` / `0xC80000` / `0xF90000` / `0xFF0000` /
`0xFD0000` / `0x250000` 之间变化，读数始终是 `99999999`。

## 注意事项

- 补丁后 Authenticode 签名变为 `HashMismatch`。Windows 加载器不靠证书有效性决定是否运行，程序照跑；Defender 实测未拦截。
- **自动更新会覆盖 `IDMan.exe`，补丁随之失效。** 程序与数据不会受损。完整的后果说明与恢复步骤见「[自动更新：后果与恢复](#自动更新后果与恢复)」。
- 这件事**没有注册表开关可关**，原因在该节里给出了反汇编证据。
- 补丁不涉及注册流程，不需要屏蔽服务器域名。
- 试用计数在 `HKCU\Software\DownloadManager\Therad`（REG_DWORD，已用天数），另有冗余备份键 `HKCU\Software\Classes\CLSID\{84797876-C678-1780-A556-0CD06786780F}`。
- 脚本的失败策略：SHA256 不在白名单拒绝执行；锚点命中数不等于 1 拒绝执行；原字节不符拒绝执行。任何异常都发生在写入之前，文件保持原样。

## 自动更新：后果与恢复

### 事实基础

IDM 会定期自动检查更新，这个行为写死在程序里。二进制中的原文：

```
IDM checks for a new release every 2 weeks by requesting an update page from its home site.
A: CheckUpdtVM     A: LastCheckQU     A: LstCheck
```

Quick Update 的产物是**替换 `IDMan.exe` 本身**，所以它一旦跑起来，补丁就被抹掉了。

**这件事没有注册表开关可以关。** 结论是确定的，排查过程如下。

二进制里唯一像开关的值名是 `CheckUpdtVM`。反汇编它的唯一引用点（`0x45A4CC`）：

```asm
0x0045A499  mov  ax,  word ptr [0x698900]   ; 数据区内容 31 30 00 = "10"
0x0045A49F  mov  cl,  byte ptr [0x698902]
0x0045A4A5  mov  word ptr [esp], ax
0x0045A4AC  mov  byte ptr [esp+2], cl       ; 在栈上拼出字符串 "10"
0x0045A4CC  push 0x6a2550                   ; "CheckUpdtVM"
0x0045A4D2  call dword ptr [0x695090]
```

它把字符串 `"10"` **写进去**，而不是读出来做真假判断——这是一个**状态标记**，不是布尔开关。所以在脚本里实现"改注册表关闭自动更新"不具备可行性；写一个语义未经证实的值进去，只会伪造出一种"已经关掉了"的假象。

### 不关会怎样

| 情况 | 后果 |
|---|---|
| 被同 build 覆盖 | 补丁失效，退回 30 天试用态。程序、下载数据、注册表配置均不受损 |
| 更新到更新的 build | 同上，且 `patch-IDM.ps1` 会**拒绝执行**（SHA256 不在白名单）。这是设计意图：绝不往未知二进制里写字节 |

两种情况都不会损坏程序，也不会丢已完成的任务。

### 怎么发现

```powershell
.\verify.ps1
```

看 `state` 一行：

| `state` 输出 | 含义 |
|---|---|
| `PATCHED` | 补丁在位，无需动作 |
| `PRISTINE (untouched official build)` | 被同 build 覆盖了，补丁已失效 |
| `UNKNOWN build (not in allowlist)` | 更新到了别的 build |

### 怎么恢复

**情况 A：`state: PRISTINE`**（被同版本覆盖）

```powershell
# 管理员身份
.\patch-IDM.ps1
```

几秒完成。锚点重新搜索，不依赖任何写死的偏移。

**情况 B：`state: UNKNOWN build`**（更新到了新版本）

此时补丁脚本会主动拒绝执行，需要退回已知版本：

```powershell
# 1. 卸载当前 IDM（控制面板，或安装目录的 Uninstall.exe）
# 2. 用留存的官方安装包重装并打补丁（管理员身份）
.\bootstrap.ps1 -SkipDownload
```

`-SkipDownload` 表示不重新下载，直接用 `-WorkDir`（默认 `%TEMP%\idm-kit`）里已有的安装包；**SHA256 校验依然强制执行**，文件不对会在安装前中止。

### 预防

按可靠性排序：

1. 定期跑 `.\verify.ps1`。这是最可靠的一道保险——无论 IDM 以什么方式更新，补丁状态一测便知，恢复只需一条命令。
2. 在 IDM 的界面选项里关掉自动检查更新（若有该开关）。这是常规做法，不依赖任何未验证的注册表值。
3. 把 `IDMan.exe` 设为只读，让更新写入失败。**可行性未经验证**，可能干扰 IDM 自身的正常行为，故未写入脚本。

## 浏览器集成：扩展报 "Cannot launch IDM"

### 症状

装好 IDM、打完补丁、IDM 自己下载完全正常，但浏览器里的 IDM 扩展失效。Chrome 与 Firefox 同时报出同一句话：

```
Internet Download Manager extension for Chrome/Firefox has been installed.
Error: Cannot launch IDM, either IDM application is not installed, or some of its files are corrupted
```

**这句话是误报**——IDM 装得好好的。

### 机制

扩展的连接逻辑（`background.js`）是先连本机端口，失败才回落到 native messaging：

```javascript
La = ["127.0.0.1:1001", "0.1.0.1:1001"]
...
if (a < La.length) {
    a = this.S = new WebSocket(`ws://${La[a]}/?cid=…&rnd=…`,
                               "plugin.v3.internetdownloadmanager.com");
} else {
    a = this.S = browser.runtime.connectNative("com.tonec.idm");   // 兜底
}
```

也就是说 **IDM 6.42+ 的集成主通道是本机 1001 端口上的 WebSocket**，native messaging 只是备胎。所以 Chrome 和 Firefox 会一起挂——它们连的是同一个端点。

该端点由 IDM 的网络过滤驱动（`IDMWFP` / `idmwfp.sys`）监听，并且做 **Origin 白名单校验**。实测（同一台机器、逐一改变量）：

```
Origin: chrome-extension://ngpampappnmepgilojfohadhhmbhlaek  ->  HTTP/1.1 101 Switching Protocols
Origin: http://127.0.0.1:8812                                ->  连接被重置
不带 Origin                                                  ->  连接被重置
带 permessage-deflate / Sec-Fetch-*                          ->  不影响结果
```

**唯一决定成败的是 Origin。** 只有扩展身份能连上，用普通网页或脚本去探测 1001 一律被拒——所以不要拿一个自建网页当作"扩展失效"的证据，那种测试从设计上就不可能通过。

### 真正的原因：IDM 不能以管理员身份运行

如果 IDM 是**以管理员权限**启动的，浏览器（中等完整性级别）会因 Windows 的 UIPI 规则无法与它建立这条通道，1001 直接重置连接。

对照实测：

| IDM 进程权限 | 从正确 Origin 发起连接的结果 |
|---|---|
| 管理员（High IL） | 连接被重置 |
| 普通用户（Medium IL） | `HTTP/1.1 101 Switching Protocols` |

这也解释了安装目录里 `MediumILStart.exe` 的用途——IDM 官方为此专门准备了一个"以中等完整性级别启动"的工具。

> 注意：**打补丁的脚本本身是提权运行的**，它停掉又重启 IDM 时，IDM 会继承管理员令牌，从而触发这个问题。打完补丁后，请以普通用户身份启动 IDM。

### 修法

1. 右击 IDM 快捷方式 → 属性 → 兼容性，确认**没有**勾选"以管理员身份运行"。
2. 不要从管理员权限的终端里启动 `IDMan.exe`。
3. 关掉 IDM 后重新以普通用户身份启动它。

IDM 自己开机自启（`HKCU\Software\DownloadManager\LaunchOnStart = 1`）走的是普通用户权限，那条路径是正常的。

### 怎么确认修好了

一次真实的浏览器下载，看 IDM 是否接管。判定依据是**服务端是否收到多个并发 Range 请求**——那是 IDM 多线程分段下载的指纹，浏览器自身下载是顺序单流：

```
[xx] /dl  Range=bytes=233600-8388607     ← 线程 1
[xx] /dl  Range=bytes=233600-            ← 线程 1 续传
[xx] /dl  Range=bytes=4316943-           ← 线程 2，从不同偏移开始
```

或者直接查 IDM 主窗口的下载列表，以及文件是否完整落盘。

## 文件

| 文件 | 作用 |
|---|---|
| `patch-IDM.ps1` | 补丁 / 回滚 |
| `bootstrap.ps1` | 新机器一键部署 |
| `verify.ps1` | 只读状态检查 |
