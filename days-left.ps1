#Requires -Version 5.1
<#
  显示 IDM 自己的"剩余试用天数"对话框。

  背景
    IDM 只在剩余天数 <= 15 时主动弹这个提示（见 0x4876d2: cmp eax,0xf / ja）。
    打了试用上限补丁后，剩余天数是个天文数字，所以 IDM 再也不会自己弹了。
    这个脚本用同样的 WM_COMMAND (0x111, id 0x13ca) 让对话框出现，
    并传入实时算出的真实剩余天数。

  天数算法
    上限 = 运行中进程 [0x77bd28]（补丁后为 99999999）
    已用 = HKCU\Software\DownloadManager\Therad（REG_DWORD，不存在按 0 计）
    剩余 = 上限 - 已用

  用法
    .\days-left.ps1
#>
[CmdletBinding()]
param(
    [string]$ProcessName = 'IDMan',
    [string]$ModuleName  = 'IDMan.exe',
    [long]$LimitRva      = 0x37BD28,
    [int]$CommandId      = 0x13ca
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -Namespace DLT -Name Impl -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
[DllImport("user32.dll")]
public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
'@

$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if (-not $proc) { throw "IDM 没有运行，先启动 Internet Download Manager 再执行本脚本。" }
$proc = $proc | Select-Object -First 1

# --- 上限：从运行中的进程读，拿不到就退回文件里的静态值 ---
$limit = $null
$mod = $proc.Modules | Where-Object { $_.ModuleName -eq $ModuleName }
if ($mod) {
    $addr = [int64]$mod.BaseAddress + $LimitRva
    $h = [DLT.Impl]::OpenProcess(0x0010 -bor 0x0400, $false, $proc.Id)
    if ($h -ne [IntPtr]::Zero) {
        $buf = New-Object byte[] 4
        $read = [IntPtr]::Zero
        if ([DLT.Impl]::ReadProcessMemory($h, [IntPtr]$addr, $buf, 4, [ref]$read)) {
            $limit = [BitConverter]::ToUInt32($buf, 0)
        }
        [void][DLT.Impl]::CloseHandle($h)
    }
}

# --- 已用天数 ---
$key = 'HKCU:\Software\DownloadManager'
$used = 0
if (Test-Path $key) {
    $props = (Get-Item $key).Property
    if ($props -contains 'Therad') { $used = [int](Get-ItemProperty $key -Name 'Therad').Therad }
}

if ($null -eq $limit) {
    Write-Host "读不到运行中的上限值，用文件里的静态值。" -ForegroundColor Yellow
    $exe = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
    if (Test-Path $exe) {
        $b = [IO.File]::ReadAllBytes($exe)
        $limit = [BitConverter]::ToUInt32($b, 0x379528)
    } else {
        throw "找不到 $exe"
    }
}

# 先在 64 位下做减法再转换：Therad 异常大于上限时 [uint32] 负数会直接抛异常，
# 所以负数判断必须发生在类型转换之前。
$rem64  = [int64]$limit - $used
$remain = if ($rem64 -lt 0) { [uint32]0 } else { [uint32]$rem64 }

Write-Host ("上限 : {0}" -f $limit)
Write-Host ("已用 : {0}" -f $used)
Write-Host ("剩余 : {0}" -f $remain) -ForegroundColor Cyan

$hMain = $proc.MainWindowHandle
if ($hMain -eq [IntPtr]::Zero) { throw "拿不到 IDM 主窗口句柄。" }

[void][DLT.Impl]::PostMessage($hMain, 0x111, [IntPtr]$CommandId, [IntPtr]$remain)
Write-Host "已弹出 IDM 的天数提示框（未点掉之前 IDM 界面会暂时无响应）。" -ForegroundColor Green
