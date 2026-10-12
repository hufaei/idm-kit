#Requires -Version 5.1
<#
  One-shot deploy on a fresh machine:
    1. download the pinned official installer
    2. verify its SHA256 against the allowlist
    3. silent install
    4. wait for IDMan.exe to appear
    5. stop every IDM process
    6. apply the trial-limit patch
    7. read back and verify the patched bytes

  Must run elevated: install writes Program Files, patch writes IDMan.exe.
#>
[CmdletBinding()]
param(
    [string]$WorkDir     = "$env:TEMP\idm-kit",
    [switch]$SkipDownload,
    [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallerUrl = 'https://download.internetdownloadmanager.com/idman643build15.exe'
$InstallerSha = 'A902E77169A3E4D8A88EE2CCAAB11D3D43AB209483625A3602438ED4A22BBFD9'
$Installer    = Join-Path $WorkDir 'idman643build15.exe'
$ExePath      = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
$PatchScript  = Join-Path $PSScriptRoot 'patch-IDM.ps1'

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this elevated (Run as administrator).'
}
if (-not (Test-Path -LiteralPath $PatchScript)) { throw "missing patch-IDM.ps1 next to this script" }

if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }

if (-not $SkipDownload -and -not (Test-Path -LiteralPath $Installer)) {
    Write-Host "downloading: $InstallerUrl"
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $Installer -UseBasicParsing
}

# Verify unconditionally, including under -SkipDownload: that switch means
# "do not fetch", not "trust whatever is already on disk". Without this the
# allowlist silently stops applying to any pre-placed installer.
if (-not (Test-Path -LiteralPath $Installer)) { throw "installer not found: $Installer" }
$h = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
Write-Host "installer sha256: $h"
if ($h -ne $InstallerSha) { throw "installer hash mismatch.`nexpected $InstallerSha`ngot      $h" }
Write-Host 'installer verified'

if (-not $SkipInstall) {
    if (Test-Path -LiteralPath $ExePath) {
        Write-Host "already installed: $ExePath"
    } else {
        Write-Host 'installing (silent /skipdlgs)...'
        Start-Process -FilePath $Installer -ArgumentList '/skipdlgs' -Wait
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Seconds 3
            if (Test-Path -LiteralPath $ExePath) { break }
        }
        if (-not (Test-Path -LiteralPath $ExePath)) { throw "install did not produce $ExePath" }
        Write-Host "installed: $ExePath"
    }
}

Write-Host 'stopping IDM processes...'
Get-Process -Name IDMan,IEMonitor,idmBroker,IDMMsgHost,IDMIntegrator64,MediumILStart `
            -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

& $PatchScript -ExePath $ExePath

Write-Host ''
Write-Host 'done. remaining manual step: turn off IDM auto-update,' -ForegroundColor Yellow
Write-Host 'otherwise Quick Update overwrites IDMan.exe and the patch is lost.' -ForegroundColor Yellow
