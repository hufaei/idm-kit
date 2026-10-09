#Requires -Version 5.1
<#
  Static verification: inspect the two patch sites on disk and report state.
  Read-only, no elevation needed for reading.
#>
[CmdletBinding()]
param(
    [string]$ExePath = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pristineSha = 'E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8'
$patchedSha  = 'AC81B41812EE1BABC3B7E0D606012C706D598ED27B9610E24563494D9D1E8D58'
$anchorA     = [byte[]]@(0xA1,0x24,0xBD,0x77,0x00,0xF7,0xD8,0x1B,0xC0,
                         0x83,0xE0,0x0F,0x83,0xC0,0x0F,0xA3,0x28,0xBD,0x77,0x00)
$offB        = 0x379528

if (-not (Test-Path -LiteralPath $ExePath)) { throw "not found: $ExePath" }
$exeFull = (Resolve-Path -LiteralPath $ExePath).Path
$sha = (Get-FileHash -LiteralPath $exeFull -Algorithm SHA256).Hash
$ver = (Get-Item -LiteralPath $exeFull).VersionInfo.FileVersion

Write-Host "file    : $exeFull"
Write-Host "version : $ver"
Write-Host "sha256  : $sha"
switch ($sha) {
    $pristineSha { Write-Host "state   : PRISTINE (untouched official build)" -ForegroundColor Yellow }
    $patchedSha  { Write-Host "state   : PATCHED" -ForegroundColor Green }
    default      { Write-Host "state   : UNKNOWN build (not in allowlist)" -ForegroundColor Red }
}

$bytes = [IO.File]::ReadAllBytes($exeFull)

$hit = -1; $p = 0
while ($p -le $bytes.Length - $anchorA.Length) {
    $i = [Array]::IndexOf($bytes, $anchorA[0], $p)
    if ($i -lt 0) { break }
    $j = 1
    while ($j -lt $anchorA.Length -and $bytes[$i + $j] -eq $anchorA[$j]) { $j++ }
    if ($j -eq $anchorA.Length) { $hit = $i; break }
    $p = $i + 1
}

if ($hit -ge 0) {
    $blk = (($bytes[$hit..($hit+19)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
    Write-Host "anchor  : found at 0x$('{0:X}' -f $hit)"
    Write-Host "block   : $blk"
    $mid = (($bytes[($hit+9)..($hit+14)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
    Write-Host "middle6 : $mid"
    if ($mid -eq 'B8 FF E0 F5 05 90') {
        Write-Host "patchA  : APPLIED (mov eax,99999999 + nop)" -ForegroundColor Green
    } elseif ($mid -eq '83 E0 0F 83 C0 0F') {
        Write-Host "patchA  : NOT applied (still and/add arithmetic)" -ForegroundColor Yellow
    } else {
        Write-Host "patchA  : UNRECOGNISED code at that site" -ForegroundColor Red
    }
} else {
    Write-Host "patchA  : anchor NOT found (different build or already altered)" -ForegroundColor Red
}

$b = (($bytes[$offB..($offB+3)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
$bval = [BitConverter]::ToUInt32($bytes, $offB)
Write-Host "dataB   : $b  -> $bval"
if ($bval -eq 99999999) {
    Write-Host "patchB  : APPLIED (.data default = 99999999)" -ForegroundColor Green
} elseif ($bval -eq 30) {
    Write-Host "patchB  : NOT applied (.data default = 30)" -ForegroundColor Yellow
} else {
    Write-Host "patchB  : UNEXPECTED value" -ForegroundColor Red
}

$bak = "$exeFull.bak"
if (Test-Path -LiteralPath $bak) {
    $bh = (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash
    Write-Host "backup  : $bak"
    Write-Host "backup sha256: $bh $(if ($bh -eq $pristineSha) { '(pristine, good)' } else { '(NOT pristine!)' })"
} else {
    Write-Host "backup  : none" -ForegroundColor Yellow
}
