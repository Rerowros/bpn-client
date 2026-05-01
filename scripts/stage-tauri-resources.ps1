$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$srcTauri = Join-Path $root "apps\badvpn-client\src-tauri"
$resourceRoot = Join-Path $srcTauri "resources"
$agentResourceDir = Join-Path $resourceRoot "agent"

Write-Host "Building badvpn-agent for installer resources..."
Push-Location $root
try {
  cargo build -p badvpn-agent --release
} finally {
  Pop-Location
}

$agentSource = Join-Path $root "target\release\badvpn-agent.exe"
if (-not (Test-Path -LiteralPath $agentSource)) {
  throw "badvpn-agent release binary was not produced at $agentSource"
}

New-Item -ItemType Directory -Path $agentResourceDir -Force | Out-Null
Copy-Item -LiteralPath $agentSource -Destination (Join-Path $agentResourceDir "badvpn-agent.exe") -Force

Write-Host "Tauri resources staged at $resourceRoot"
