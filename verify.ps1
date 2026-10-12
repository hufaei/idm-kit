#Requires -Version 5.1
<#
  Static verification: inspect the two patch sites on disk and report state.
  Read-only, no elevation needed.

  Both sites are located by anchor search, never by a hardcoded file offset,
  so the report stays correct even if the image layout differs.

  State is decided by the CONTENT of the patch sites, not by the file hash.
  A patched file's SHA256 depends on the -Days value that produced it, so a
  fixed hash can only ever recognise one exact patched build; using it as the
  primary signal would misreport every other -Days value as an unknown build.
  The hash is therefore used only to recognise the untouched official build.

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

# Site A's middle changes, so locate it by the 9-byte prefix that survives patching.
$prefixA = [byte[]]@(0xA1,0x24,0xBD,0x77,0x00,0xF7,0xD8,0x1B,0xC0)
$midOldA = '83 E0 0F 83 C0 0F'          # and eax,0xf / add eax,0xf
# $midNewA is B8 <imm32> 90; the imm32 varies with -Days, so it is parsed
# rather than compared against a fixed literal.

# Site B: the 8 bytes AFTER the target. The anchor must never contain the
# patched dword itself, otherwise it disappears as soon as the patch is applied
# and the report degrades to "anchor found 0x".
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

function Find-All {
    param([byte[]]$Hay, [byte[]]$Needle)
    $out = New-Object 'Collections.Generic.List[int]'
    $p = 0
    while ($true) {
        $i = Find-Bytes -Hay $Hay -Needle $Needle -Start $p
        if ($i -lt 0) { break }
        $out.Add($i); $p = $i + 1
    }
    return , $out
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

$bytes = [IO.File]::ReadAllBytes($exeFull)

# ---------------- site A ----------------
$haHits = Find-All -Hay $bytes -Needle $prefixA
$stateA = 'MISSING'
$daysA  = $null
$offA   = -1

if ($haHits.Count -eq 0) {
    $stateA = 'MISSING'
} elseif ($haHits.Count -gt 1) {
    $stateA = "AMBIGUOUS ($($haHits.Count)x)"
} else {
    $offA = $haHits[0]
    # A real site A is a 20-byte block: the 9-byte prefix plus 6 bytes of code
    # plus the trailing instruction. The detail report below reads all 20, so
    # the guard must cover 20 as well -- checking only 15 would leave HexOf
    # slicing past EOF for a match near the end of the file.
    if ($offA + 20 -gt $bytes.Length) {
        $stateA = 'TRUNCATED'
    } else {
        $raw = $bytes[($offA + 9)..($offA + 14)]
        $mid = ($raw | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
        if ($mid -eq $midOldA) {
            $stateA = 'NOT applied'
        } elseif ($raw[0] -eq 0xB8 -and $raw[5] -eq 0x90) {
            $stateA = 'APPLIED'
            $daysA = [BitConverter]::ToUInt32($raw, 1)
        } else {
            $stateA = 'UNRECOGNISED'
        }
    }
}

# ---------------- site B ----------------
$hbHits = Find-All -Hay $bytes -Needle $anchorB
$stateB = 'MISSING'
$daysB  = $null
$offB   = -1

if ($hbHits.Count -ne 1) {
    $stateB = "AMBIGUOUS ($($hbHits.Count)x)"
} else {
    $offB = $hbHits[0] + $bDelta
    $daysB = [BitConverter]::ToUInt32($bytes, $offB)
    # Agreement with site A is checked FIRST. The shipped .data default is 30,
    # so -Days 30 rewrites the code but leaves this dword untouched; testing for
    # 30 before testing for agreement would report that file as "not applied"
    # and push the overall state to UNKNOWN even though the code was patched.
    if ($null -ne $daysA -and $daysB -eq $daysA) { $stateB = 'APPLIED' }
    elseif ($daysB -eq 30) { $stateB = 'NOT applied' }
    else { $stateB = "OTHER ($daysB)" }
}

# ---------------- overall state ----------------
# Decided from site content, with the hash only disambiguating an untouched build.
if ($stateA -eq 'APPLIED' -and $stateB -eq 'APPLIED') {
    if ($daysA -eq $daysB) {
        Write-Host "state   : PATCHED (trial limit = $daysA days)" -ForegroundColor Green
    } else {
        Write-Host "state   : PATCHED but INCONSISTENT (code=$daysA, data=$daysB)" -ForegroundColor Red
    }
} elseif ($stateA -eq 'NOT applied' -and $stateB -eq 'NOT applied') {
    if ($sha -eq $pristineSha) {
        Write-Host 'state   : PRISTINE (untouched official build)' -ForegroundColor Yellow
    } else {
        Write-Host 'state   : NOT PATCHED, but sha256 is not the known official build' -ForegroundColor Red
    }
} else {
    Write-Host 'state   : UNKNOWN (sites disagree or could not be read)' -ForegroundColor Red
}

# ---------------- detail ----------------
Write-Host ''
if ($offA -ge 0) {
    Write-Host "block   : $(HexOf -B $bytes -Start $offA -Len 20)"
    Write-Host "middle6 : $(HexOf -B $bytes -Start ($offA + 9) -Len 6)"
}
if ($stateA -eq 'APPLIED') {
    Write-Host "patchA  : APPLIED (mov eax,$daysA + nop)" -ForegroundColor Green
} elseif ($stateA -eq 'NOT applied') {
    Write-Host 'patchA  : NOT applied (still and/add arithmetic)' -ForegroundColor Yellow
} else {
    Write-Host "patchA  : $stateA" -ForegroundColor Red
}

if ($offB -ge 0) {
    Write-Host ("dataB   : at 0x{0:X}  {1}  -> {2}" -f $offB, (HexOf -B $bytes -Start $offB -Len 4), $daysB)
}
if ($stateB -eq 'APPLIED') {
    Write-Host "patchB  : APPLIED (.data default = $daysB)" -ForegroundColor Green
} elseif ($stateB -eq 'NOT applied') {
    Write-Host 'patchB  : NOT applied (.data default = 30)' -ForegroundColor Yellow
} else {
    Write-Host "patchB  : $stateB" -ForegroundColor Red
}

# 30 days is what the unpatched build already grants, so patching to 30 changes
# the code without changing the effective limit. Worth saying out loud.
if ($stateA -eq 'APPLIED' -and $daysA -eq 30) {
    Write-Host ''
    Write-Host 'note    : 30 is the shipped default, so this patch has no effect' -ForegroundColor Yellow
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
