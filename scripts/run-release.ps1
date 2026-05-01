$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "target\release\badvpn-client.exe"

if (-not (Test-Path -LiteralPath $exe)) {
  Write-Host "Release executable is missing. Building BadVpn release..."
  Push-Location $root
  try {
    npx --prefix apps/badvpn-client tauri build --no-bundle
  } finally {
    Pop-Location
  }
}

if (-not (Test-Path -LiteralPath $exe)) {
  throw "Release executable was not produced at $exe"
}

$devExe = Join-Path $root "target\debug\badvpn-client.exe"
$debugProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Name -eq "badvpn-client.exe" -and
    $_.ExecutablePath -and
    [string]::Equals($_.ExecutablePath, $devExe, [System.StringComparison]::OrdinalIgnoreCase)
  }

if ($debugProcesses) {
  Write-Warning "A debug BadVpn process is still running from target\debug. Close it if you still see localhost:5173."
}

Write-Host "Starting BadVpn release: $exe"
Start-Process -FilePath $exe -WorkingDirectory $root
