#Requires -Version 5.1
<#
  IDM 诊断信息收集工具

  用途：IDM 装好了但用不了的时候，一次把排查需要的所有信息收集起来，
        打包成一个 zip，发给帮你排查的人。

  用法：右键这个文件 → 使用 PowerShell 运行
        或者在 PowerShell 里执行：  .\collect-logs.ps1

  产出：桌面上的 idm-diag-<日期时间>.zip

  这个脚本只读取信息，不修改任何东西，不需要管理员权限。
#>
[CmdletBinding()]
param(
    [string]$OutDir = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'Continue'

$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$work    = Join-Path $env:TEMP "idm-diag-$stamp"
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Save {
    param([string]$Name, [scriptblock]$Block)
    $path = Join-Path $work $Name
    try {
        # *>&1 captures every stream, not just errors. verify.ps1 reports with
        # Write-Host, which writes to the Information stream and would be lost
        # under a plain 2>&1.
        $out = & $Block *>&1 | Out-String -Width 400
    } catch {
        $out = "收集这一项时出错: $_"
    }
    if ([string]::IsNullOrWhiteSpace($out)) { $out = '(无内容)' }
    Set-Content -LiteralPath $path -Value $out -Encoding UTF8
    Write-Host "  已收集 $Name"
}

Write-Host ''
Write-Host 'IDM 诊断信息收集' -ForegroundColor Cyan
Write-Host '只会读取信息，不会改动任何设置'
Write-Host ''

# ---------------- 1. 环境 ----------------
Save '01-系统环境.txt' {
    "时间        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "计算机名    : $env:COMPUTERNAME"
    "当前用户    : $env:USERNAME"
    "是管理员    : $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    "PowerShell  : $($PSVersionTable.PSVersion)"
    "系统架构    : $env:PROCESSOR_ARCHITECTURE"
    ""
    "--- 操作系统 ---"
    (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue |
        Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List | Out-String).Trim()
}

# ---------------- 2. IDM 文件 ----------------
$idmDir = "${env:ProgramFiles(x86)}\Internet Download Manager"

Save '02-IDM文件.txt' {
    "安装目录    : $idmDir"
    "目录存在    : $(Test-Path -LiteralPath $idmDir)"
    ""
    if (Test-Path -LiteralPath $idmDir) {
        "--- 主程序与备份哈希 ---"
        foreach ($f in 'IDMan.exe', 'IDMan.exe.bak') {
            $p = Join-Path $idmDir $f
            if (Test-Path -LiteralPath $p) {
                $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
                $v = (Get-Item -LiteralPath $p).VersionInfo.FileVersion
                "$f`n    version = $v`n    sha256  = $h"
            } else {
                "$f  => 不存在"
            }
        }
        ""
        "--- 浏览器扩展文件（安装时自带的） ---"
        Get-ChildItem -LiteralPath $idmDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.crx', '.xpi', '.nex' } |
            ForEach-Object { "{0,-20} {1,8:N1} KB   {2}" -f $_.Name, ($_.Length / 1KB), $_.LastWriteTime }
    }
}

# ---------------- 3. 补丁状态 ----------------
Save '03-补丁状态.txt' {
    $vs = Join-Path $PSScriptRoot 'verify.ps1'
    if (Test-Path -LiteralPath $vs) {
        & $vs 2>&1 | Out-String
    } else {
        "没找到 verify.ps1（应该在 $PSScriptRoot）"
    }
}

# ---------------- 4. 进程与权限 ----------------
Save '04-进程与权限.txt' {
    $names = 'IDMan', 'IEMonitor', 'idmBroker', 'IDMMsgHost', 'IDMIntegrator64', 'MediumILStart'
    foreach ($n in $names) {
        $ps = Get-Process -Name $n -ErrorAction SilentlyContinue
        if ($ps) {
            foreach ($p in $ps) {
                $pathText = $null
                try { $pathText = $p.Path } catch { $pathText = '(读不到)' }
                "$n  pid=$($p.Id)  启动=$($p.StartTime)"
                "        路径=$pathText"
                # 路径读得到 => 与当前进程同级；读不到 => 权限更高（很可能是管理员运行）
                if ($pathText -eq '(读不到)') {
                '        权限=比当前高（很可能是以管理员身份运行，这会打断浏览器扩展）'
                } else {
                '        权限=普通用户（正确）'
                }
            }
        } else {
            "$n  => 未运行"
        }
    }
    ""
    "--- IDM 是否被设为管理员兼容 ---"
    $appcompat = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    if (Test-Path $appcompat) {
        $props = (Get-Item $appcompat).Property
        $hit = $props | Where-Object { $_ -like '*IDMan*' }
        if ($hit) { $hit | ForEach-Object { "  $_ = $((Get-ItemProperty $appcompat -Name $_).$_)" } }
        else { '  没有针对 IDMan 的兼容性设置（正常）' }
    } else {
        '  没有兼容性设置记录（正常）'
    }
}

# ---------------- 5. 注册表 ----------------
Save '05-注册表.txt' {
    "--- HKCU\Software\DownloadManager ---"
    $k = 'HKCU:\Software\DownloadManager'
    if (Test-Path $k) {
        $item = Get-Item $k
        foreach ($p in $item.Property) {
            $v = (Get-ItemProperty $k -Name $p).$p
            if ($v -is [byte[]]) { $v = ($v | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' }
            "  $p = $v"
        }
    } else {
        "  键不存在（IDM 可能没运行过）"
    }
    ""
    "--- 试用计数备份键 ---"
    $b = 'HKCU:\Software\Classes\CLSID\{84797876-C678-1780-A556-0CD06786780F}'
    if (Test-Path $b) {
        (Get-Item $b).Property | ForEach-Object { "  $_ = $((Get-ItemProperty $b -Name $_).$_)" }
    } else {
        "  不存在（正常）"
    }
    ""
    "--- 浏览器扩展的本机通信注册 ---"
    foreach ($p in 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.tonec.idm',
                   'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.tonec.idm',
                   'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.tonec.idm',
                   'HKCU:\Software\Mozilla\NativeMessagingHosts\com.tonec.idm') {
        if (Test-Path $p) {
            "  $p"
            "      -> $((Get-ItemProperty $p).'(default)')"
        } else {
            "  $p  => 不存在"
        }
    }
}

# ---------------- 6. 网络与服务 ----------------
Save '06-网络与服务.txt' {
    "--- 1001 端口（IDM 给浏览器扩展用的通道） ---"
    $c = Get-NetTCPConnection -LocalPort 1001 -ErrorAction SilentlyContinue
    if ($c) {
        $c | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Format-Table -AutoSize | Out-String
    } else {
        '  没人在用 1001 端口（IDM 没运行，或者驱动没装上）'
    }
    ""
    "--- IDMWFP 驱动服务 ---"
    $svc = Get-Service -Name 'IDMWFP' -ErrorAction SilentlyContinue
    if ($svc) {
        "  服务状态 = $($svc.Status)"
        "  启动类型 = $((Get-CimInstance Win32_Service -Filter \"Name='IDMWFP'\").StartMode)"
    } else {
        '  IDMWFP 服务不存在（驱动没装上）'
    }
    ""
    "--- 驱动文件 ---"
    foreach ($f in 'idmwfp.sys', 'idmwfp64.sys', 'idmtdi64.sys') {
        $p = Join-Path $env:SystemRoot "System32\drivers\$f"
        if (Test-Path $p) { "  $f  存在" } else { "  $f  不存在" }
    }
}

# ---------------- 7. 浏览器扩展安装状态 ----------------
Save '07-浏览器扩展.txt' {
    $chromeExtId = 'ngpampappnmepgilojfohadhhmbhlaek'
    $candidates = @(
        @{ Name = 'Chrome';  Profile = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Name = 'Edge';    Profile = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Name = 'Brave';   Profile = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
    )
    foreach ($b in $candidates) {
        "--- $($b.Name) ---"
        if (-not (Test-Path $b.Profile)) { "  未安装"; continue }
        $extDir = Join-Path $b.Profile "Default\Extensions\$chromeExtId"
        if (Test-Path $extDir) {
            $ver = (Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue).Name -join ', '
            "  扩展已安装，版本目录: $ver"
        } else {
            "  扩展未安装（没找到 $chromeExtId）"
        }
        # 扩展是否被 Chrome 禁用
        $sec = Join-Path $b.Profile 'Default\Secure Preferences'
        if (Test-Path $sec) {
            $txt = Get-Content $sec -Raw -ErrorAction SilentlyContinue
            if ($txt -match [regex]::Escape($chromeExtId)) {
                "  Secure Preferences 里有这个扩展的记录"
            }
        }
    }
    ""
    "--- Firefox ---"
    $ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $ffProfiles) {
        foreach ($prof in Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue) {
            $extJson = Join-Path $prof.FullName 'extensions.json'
            if (Test-Path $extJson) {
                $txt = Get-Content $extJson -Raw -ErrorAction SilentlyContinue
                if ($txt -match 'idmmzcc|internetdownloadmanager|tonec') {
                    "  $($prof.Name): 有 IDM 扩展记录"
                } else {
                    "  $($prof.Name): 没有 IDM 扩展"
                }
            }
        }
    } else {
        "  Firefox 未安装"
    }
}

# ---------------- 8. IDM 自带日志 ----------------
Save '08-IDM自带日志.txt' {
    foreach ($p in "$env:APPDATA\IDM", "$env:LOCALAPPDATA\IDM", "$env:ProgramData\IDM") {
        "--- $p ---"
        if (Test-Path $p) {
            Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                ForEach-Object { "  $($_.FullName)   $([math]::Round($_.Length/1KB,1)) KB   $($_.LastWriteTime)" }
        } else {
            "  目录不存在"
        }
    }
    ""
    "--- 安装日志 IDMSetup2.log（末尾 60 行） ---"
    $setup = Join-Path $idmDir 'IDMSetup2.log'
    if (Test-Path $setup) {
        Get-Content $setup -Tail 60 -ErrorAction SilentlyContinue
    } else {
        "  不存在"
    }
}

# ---------------- 打包 ----------------
$zip = Join-Path $OutDir "idm-diag-$stamp.zip"
try {
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host '收集完成。' -ForegroundColor Green
    Write-Host "文件在：$zip" -ForegroundColor Cyan
    Write-Host '把这个 zip 发给帮你排查的人即可。'
} catch {
    Write-Host ''
    Write-Host "打包失败：$_" -ForegroundColor Red
    Write-Host "散装文件在：$work"
}

Write-Host ''
Write-Host '按任意键关闭...'
try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
