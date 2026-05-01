param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $TauriArgs
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$appDir = Join-Path $root "apps\badvpn-client"

if ($TauriArgs.Count -gt 0 -and $TauriArgs[0] -eq "build") {
  & (Join-Path $PSScriptRoot "stage-tauri-resources.ps1")
}

Push-Location $appDir
try {
  & npx tauri @TauriArgs
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
} finally {
  Pop-Location
}
