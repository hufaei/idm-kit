#Requires -Version 5.1
<#
  IDM 6.43 build 15  --  trial-limit patch  (v2, relocation-safe)

  WHY v1 FAILED
    v1 replaced the whole 20-byte block with C7 05 28BD7700 <imm32>.
    The original block contains two absolute operands:
        A1 24BD7700   mov eax,[0x77bd24]   -> disp32 at RVA 0x4CF38
        A3 28BD7700   mov [0x77bd28],eax   -> disp32 at RVA 0x4CF47
    Both have entries in the PE .reloc table. v1 shifted the first disp32 to
    RVA 0x4CF39 while the reloc entry stayed at 0x4CF38, so the loader added
    the image delta to the wrong byte offset and corrupted the new immediate's
    address field (observed in memory: 28 BD 77 00 -> 28 76 78 00).
    Result: the patch opened an illegal write address -- a crash waiting for
    that code path to run.

  v2 STRATEGY
    Patch A: keep both absolute-operand instructions byte-identical (reloc
             entries stay valid), replace only the middle arithmetic
                 83 E0 0F 83 C0 0F   (and eax,0xf / add eax,0xf)
             with
                 B8 <imm32> 90       (mov eax, Days / nop)
             Same 6-byte length. No reloc interaction whatsoever.
    Patch B: .data default for 0x77bd28 is 0x1E (30) -- it is initialised in
             the image, so the limit is already 30 before any code runs.
             Set it to Days too, so the value holds whether or not the code
             path at 0x44cf37 ever executes. .data holds an int, not a pointer,
             so it has no reloc entry.
#>
[CmdletBinding()]
param(
    [string]$ExePath = "${env:ProgramFiles(x86)}\Internet Download Manager\IDMan.exe",
    [uint32]$Days    = 99999999,
    [switch]$Force,
    [switch]$Revert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$imm = [byte[]][BitConverter]::GetBytes($Days)

# ---- patch point definitions ----
# A: anchor = full original 20-byte block; only bytes [9..14] are rewritten.
$anchorA = [byte[]]@(0xA1,0x24,0xBD,0x77,0x00,0xF7,0xD8,0x1B,0xC0,
                     0x83,0xE0,0x0F,0x83,0xC0,0x0F,0xA3,0x28,0xBD,0x77,0x00)
$oldA    = [byte[]]@(0x83,0xE0,0x0F,0x83,0xC0,0x0F)
$newA    = [byte[]]@(0xB8) + $imm + [byte[]]@(0x90)

# The first 9 bytes of anchor A survive patching, so they can locate site A in
# an already-patched file (the full 20-byte anchor cannot: its middle is gone).
$prefixA = [byte[]]@(0xA1,0x24,0xBD,0x77,0x00,0xF7,0xD8,0x1B,0xC0)

# B: .data default of [0x77bd28]. Anchored by an 8-byte run that sits AFTER
#    the target, never by a hardcoded file offset. The run holds two
#    linked-base pointers (0x699338, 0x6A03D0) and is unique in the file both
#    before and after patching (verified on build 15). It must NOT include the
#    patched dword itself, or the anchor would vanish once the patch is applied.
$anchorB = [byte[]]@(0x38,0x93,0x69,0x00, 0xD0,0x03,0x6A,0x00)
$bDelta  = -4              # the patch target sits 4 bytes BEFORE the anchor
$oldB    = [byte[]]@(0x1E,0x00,0x00,0x00)
$newB    = $imm

if ($newA.Length -ne $oldA.Length) { throw "internal: patch A length mismatch" }
if ($newB.Length -ne $oldB.Length) { throw "internal: patch B length mismatch" }

if (-not (Test-Path -LiteralPath $ExePath)) { throw "target not found: $ExePath" }
$exeFull = (Resolve-Path -LiteralPath $ExePath).Path
$bak     = "$exeFull.bak"

if ($Revert) {
    if (-not (Test-Path -LiteralPath $bak)) { throw "no backup: $bak" }
    Copy-Item -LiteralPath $bak -Destination $exeFull -Force
    Write-Host "RESTORED: $exeFull" -ForegroundColor Green
    return
}

$busy = Get-Process -Name IDMan,IEMonitor,idmBroker,IDMMsgHost,IDMIntegrator64,MediumILStart `
                   -ErrorAction SilentlyContinue
if ($busy) { throw "IDM is running (PID $($busy.Id -join ',')). Exit it fully first." }

try {
    $fs = [IO.File]::Open($exeFull, 'Open', 'ReadWrite', 'None'); $fs.Close(); $fs.Dispose()
} catch { throw "target not writable ($exeFull). Run elevated." }

$hash = (Get-FileHash -LiteralPath $exeFull -Algorithm SHA256).Hash
$ver  = (Get-Item -LiteralPath $exeFull).VersionInfo.FileVersion
Write-Host "target : $exeFull"
Write-Host "version: $ver"
Write-Host "sha256 : $hash"

$bytes = [IO.File]::ReadAllBytes($exeFull)

# ---- idempotency probe (state-driven, independent of -Days) ----
# A patched file's SHA256 depends on the -Days value, so no fixed hash can
# enumerate every already-patched state. Decide from the code instead: locate
# site A by the surviving 9-byte prefix, then let the six bytes after it decide.
$probeHits = New-Object 'Collections.Generic.List[int]'
$q = 0
while ($true) {
    $i = Find-Bytes -Hay $bytes -Needle $prefixA -Start $q
    if ($i -lt 0) { break }
    $probeHits.Add($i); $q = $i + 1
}
if ($probeHits.Count -eq 1) {
    $mp = $probeHits[0] + 9
    $curMid = $bytes[$mp..($mp + 5)]
    if ($curMid[0] -eq 0xB8 -and $curMid[5] -eq 0x90) {
        $curDays = [BitConverter]::ToUInt32($curMid, 1)
        Write-Host "already patched: trial limit is currently $curDays days, nothing to do." -ForegroundColor Green
        Write-Host 'rollback: -Revert'
        return
    }
}

$pristine = 'E3FC655A335E17A6FDD09A9B315291D0C8863180F0D801E5DD7433C9E56AFBD8'
if (-not $Force -and $hash -ne $pristine) {
    throw "unverified build (sha256 not recognised). Re-run with -Force if sure."
}

# ---------- patch A ----------
$hits = New-Object 'Collections.Generic.List[int]'
$p = 0
while ($true) {
    $i = Find-Bytes -Hay $bytes -Needle $anchorA -Start $p
    if ($i -lt 0) { break }
    $hits.Add($i); $p = $i + 1
}
if ($hits.Count -ne 1) { throw "anchor A hit count = $($hits.Count) (need exactly 1). Aborted, untouched." }
$offA = $hits[0] + 9
# Display only: 0x400C00 is (linked VA - file offset) for this build, i.e. the
# distance between file layout and the 0x400000 linked image base. It does not
# affect the patch itself, only the address printed for reference.
Write-Host ("A      : anchor at 0x{0:X}, target 0x{1:X} (va 0x{2:X})" -f ($hits[0]), $offA, ($offA + 0x400C00))

$curA = $bytes[$offA..($offA + 5)]
$alreadyA = ($curA -join ',') -eq ($newA -join ',')
if ($alreadyA) {
    Write-Host "A      : already patched, skip"
} else {
    for ($k = 0; $k -lt $oldA.Length; $k++) {
        if ($bytes[$offA + $k] -ne $oldA[$k]) { throw ("A: original byte mismatch at 0x{0:X}. Aborted." -f ($offA + $k)) }
    }
}

# ---------- patch B ----------
$hitsB = New-Object 'Collections.Generic.List[int]'
$p = 0
while ($true) {
    $i = Find-Bytes -Hay $bytes -Needle $anchorB -Start $p
    if ($i -lt 0) { break }
    $hitsB.Add($i); $p = $i + 1
}
if ($hitsB.Count -ne 1) { throw "anchor B hit count = $($hitsB.Count) (need exactly 1). Aborted, untouched." }
$offB = $hitsB[0] + $bDelta
Write-Host ("B      : anchor at 0x{0:X}, target 0x{1:X}" -f ($hitsB[0]), $offB)

$curB = $bytes[$offB..($offB + 3)]
$alreadyB = ($curB -join ',') -eq ($newB -join ',')
if ($alreadyB) {
    Write-Host "B      : already patched, skip"
} else {
    for ($k = 0; $k -lt $oldB.Length; $k++) {
        if ($bytes[$offB + $k] -ne $oldB[$k]) { throw ("B: original byte mismatch at 0x{0:X}. Aborted." -f ($offB + $k)) }
    }
}

# ---------- backup ----------
if (-not (Test-Path -LiteralPath $bak)) {
    Copy-Item -LiteralPath $exeFull -Destination $bak
    Write-Host "backup : $bak"
} else {
    Write-Host "backup : exists, keeping (already pristine copy)"
    $bh = (Get-FileHash -LiteralPath $bak -Algorithm SHA256).Hash
    if ($bh -ne $pristine) { Write-Warning "backup sha256 is $bh (not the pristine build!)" }
}

# ---------- apply ----------
if (-not $alreadyA) { for ($k = 0; $k -lt $newA.Length; $k++) { $bytes[$offA + $k] = $newA[$k] } }
if (-not $alreadyB) { for ($k = 0; $k -lt $newB.Length; $k++) { $bytes[$offB + $k] = $newB[$k] } }
[IO.File]::WriteAllBytes($exeFull, $bytes)

# ---------- read-back ----------
$chk = [IO.File]::ReadAllBytes($exeFull)
$okA = (($chk[$offA..($offA+5)]   | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
$okB = (($chk[$offB..($offB+3)]   | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
$blk = (($chk[($hits[0])..($hits[0]+19)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
Write-Host "A read : $okA"
Write-Host "B read : $okB"
Write-Host "block  : $blk"
if ($okA -ne (($newA | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')) { throw "read-back A failed" }
if ($okB -ne (($newB | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')) { throw "read-back B failed" }
Write-Host "OK     : trial limit = $Days days (code + .data default)" -ForegroundColor Green
Write-Host "rollback: -Revert"
