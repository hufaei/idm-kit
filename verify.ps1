#Requires -Version 5.1
<#
  Static verification: inspect the two patch sites on disk and report state.
  Read-only, no elevation needed for reading.

  Both sites are located by anchor search, never by a hardcoded file offset,
  so the report stays correct even if the image layout differs.

  Note: the search helper deliberately returns a single int, and the caller
  accumulates hits in an explicit List. Returning a collection from a
  PowerShell function triggers automatic unrolling, which under
  Set-StrictMode makes .Count disappear or nests the value unexpectedly.
#>
[CmdletBinding()]
param(
    [string]$ExePath = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pristineSha = 'E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8'
$patchedSha  = 'AC81B41812EE1BABC3B7E0D606012C706D598ED27B9610E24563494D9D1E8D58'

# Site A's bytes change, so locate it by the 9-byte prefix that survives patching.
$prefixA = [byte[]]@(0xA1,0x24,0xBD,0x77,0x00,0xF7,0xD8,0x1B,0xC0)
$midOldA = '83 E0 0F 83 C0 0F'
$midNewA = 'B8 FF E0 F5 05 90'

# Site B: the 8 bytes AFTER the target. The anchor must never contain the
# patched dword itself (1E 00 00 00), otherwise it disappears as soon as the
# patch is applied and the report degrades to "anchor found 0x".
$anchorB = [byte[]]@(0x38,0x93,0x69,0x00, 0xD0,0x03,0x6A,0x00)
$bDelta  = -4

function Find-Bytes {
    param([byte[]]$Hay, [byte[]]$Needle, [int]$Start = 0)
    $pos  = $Start
    $last = $Hay.Length - $Needle.Length
    while ($pos -le $last) {
        $i = [Array]::IndexOf($Hay, $Needle[0], $pos)
        if ($i -lt 0 -or $i -gt $last) { return -1 }
        $j = 1
        while ($j -lt $Needle.Length -and $Hay[$i + $j] -eq $Needle[$j]) { $j++ }
        if ($j -eq $Needle.Length) { return $i }
        $pos = $i + 1
    }
    return -1
}

function HexOf {
    param([byte[]]$B, [int]$Start, [int]$Len)
    return (($B[$Start..($Start + $Len - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
}

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

# ---------------- site A ----------------
Write-Host ''
$haHits = New-Object 'Collections.Generic.List[int]'
$p = 0
while ($true) {
    $i = Find-Bytes -Hay $bytes -Needle $prefixA -Start $p
    if ($i -lt 0) { break }
    $haHits.Add($i); $p = $i + 1
}
if ($haHits.Count -eq 0) {
    Write-Host 'patchA  : site NOT found (unexpected for a known build)' -ForegroundColor Red
} elseif ($haHits.Count -gt 1) {
    Write-Host "patchA  : prefix occurs $($haHits.Count)x -- cannot decide" -ForegroundColor Red
} else {
    $hit = $haHits[0]
    Write-Host "block   : $(HexOf -B $bytes -Start $hit -Len 20)"
    $mid = HexOf -B $bytes -Start ($hit + 9) -Len 6
    Write-Host "middle6 : $mid"
    if ($mid -eq $midNewA) {
        Write-Host 'patchA  : APPLIED (mov eax,99999999 + nop)' -ForegroundColor Green
    } elseif ($mid -eq $midOldA) {
        Write-Host 'patchA  : NOT applied (still and/add arithmetic)' -ForegroundColor Yellow
    } else {
        Write-Host 'patchA  : UNRECOGNISED code at that site' -ForegroundColor Red
    }
}

# ---------------- site B ----------------
$hbHits = New-Object 'Collections.Generic.List[int]'
$p = 0
while ($true) {
    $i = Find-Bytes -Hay $bytes -Needle $anchorB -Start $p
    if ($i -lt 0) { break }
    $hbHits.Add($i); $p = $i + 1
}
if ($hbHits.Count -ne 1) {
    Write-Host "patchB  : anchor found $($hbHits.Count)x -- cannot decide" -ForegroundColor Red
} else {
    $offB = $hbHits[0] + $bDelta
    $bval = [BitConverter]::ToUInt32($bytes, $offB)
    Write-Host ("dataB   : at 0x{0:X}  {1}  -> {2}" -f $offB, (HexOf -B $bytes -Start $offB -Len 4), $bval)
    if ($bval -eq 99999999) {
        Write-Host 'patchB  : APPLIED (.data default = 99999999)' -ForegroundColor Green
    } elseif ($bval -eq 30) {
        Write-Host 'patchB  : NOT applied (.data default = 30)' -ForegroundColor Yellow
    } else {
        Write-Host 'patchB  : UNEXPECTED value' -ForegroundColor Red
    }
}

# ---------------- backup ----------------
Write-Host ''
$bak = "$exeFull.bak"
if (Test-Path -LiteralPath $bak) {
    $bh = (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash
    Write-Host "backup  : $bak"
    Write-Host "backup sha256: $bh $(if ($bh -eq $pristineSha) { '(pristine, good)' } else { '(NOT pristine!)' })"
} else {
    Write-Host 'backup  : none' -ForegroundColor Yellow
}
