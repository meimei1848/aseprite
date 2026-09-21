# Check that the built Windows binaries can actually run:
#   1) every statically imported DLL is a system DLL or shipped next to the exe
#   2) aseprite.exe starts and prints its version
param(
  [Parameter(Mandatory = $true)][string]$BinDir
)

$ErrorActionPreference = "Stop"
$BinDir = (Resolve-Path $BinDir).Path

function Get-ImportDlls([string]$path) {
  $b = [System.IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToUInt32($b, 0x3C)
  if ($pe -le 0 -or $pe -ge $b.Length) { throw "not a PE file: $path" }
  $numSec   = [BitConverter]::ToUInt16($b, $pe + 6)
  $optSize  = [BitConverter]::ToUInt16($b, $pe + 20)
  $opt      = $pe + 24
  $magic    = [BitConverter]::ToUInt16($b, $opt)
  $ddOff    = if ($magic -eq 0x20b) { $opt + 112 } else { $opt + 96 }
  $impRva   = [BitConverter]::ToUInt32($b, $ddOff + 8)
  $secStart = $opt + $optSize
  $secs = @()
  for ($i = 0; $i -lt $numSec; $i++) {
    $s = $secStart + ($i * 40)
    $secs += [pscustomobject]@{
      VSize   = [BitConverter]::ToUInt32($b, $s + 8)
      VA      = [BitConverter]::ToUInt32($b, $s + 12)
      RawSize = [BitConverter]::ToUInt32($b, $s + 16)
      RawPtr  = [BitConverter]::ToUInt32($b, $s + 20)
    }
  }
  function RvaToOff([int]$rva) {
    foreach ($s in $secs) {
      if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VSize, $s.RawSize))) {
        return $rva - $s.VA + $s.RawPtr
      }
    }
    return -1
  }
  $names = @()
  $off = RvaToOff $impRva
  if ($off -lt 0) { return $names }
  $i = 0
  while ($true) {
    $d = $off + ($i * 20)
    if ($d + 20 -gt $b.Length) { break }
    $nameRva    = [BitConverter]::ToUInt32($b, $d + 12)
    $firstThunk = [BitConverter]::ToUInt32($b, $d)
    if ($nameRva -eq 0 -and $firstThunk -eq 0) { break }
    $no = RvaToOff $nameRva
    if ($no -lt 0) { break }
    $end = $no
    while ($b[$end] -ne 0) { $end++ }
    $names += [System.Text.Encoding]::ASCII.GetString($b, $no, $end - $no)
    $i++
  }
  return $names
}

$failed = $false
$exes = Get-ChildItem -Path $BinDir -Filter *.exe
if (-not $exes) { throw "no .exe found in $BinDir" }

foreach ($exe in $exes) {
  Write-Output ("--- " + $exe.Name + " ---")
  $missing = @()
  foreach ($dll in (Get-ImportDlls $exe.FullName)) {
    $inSys = Test-Path (Join-Path $env:SystemRoot ("System32/" + $dll))
    $inBin = Test-Path (Join-Path $BinDir $dll)
    if ($inSys -or $inBin) {
      Write-Output ("  ok       " + $dll)
    } else {
      Write-Output ("  MISSING  " + $dll)
      $missing += $dll
    }
  }
  if ($missing.Count -gt 0) {
    $failed = $true
    Write-Output ("!! " + $exe.Name + " needs DLLs that are not shipped: " + ($missing -join ", "))
  }
}

$ase = Join-Path $BinDir "aseprite.exe"
if (Test-Path $ase) {
  $vfile = Join-Path $env:TEMP "aseprite-version.txt"
  $p = Start-Process -FilePath $ase -ArgumentList "--version" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $vfile
  $v = (Get-Content $vfile -Raw -ErrorAction SilentlyContinue)
  Write-Output ("aseprite.exe --version -> exit " + $p.ExitCode + " output: [" + ([string]$v).Trim() + "]")
  if ($p.ExitCode -ne 0) { Write-Output "!! aseprite.exe exited with an error"; $failed = $true }
  if ([string]::IsNullOrWhiteSpace($v)) { Write-Output "!! aseprite.exe printed no version"; $failed = $true }
}

if ($failed) { throw "runtime dependency check FAILED" }
Write-Output "runtime dependency check OK"