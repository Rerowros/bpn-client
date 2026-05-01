# BadVpn Bundled Resources

This directory is packaged into the Tauri installer.

`scripts/stage-tauri-resources.ps1` refreshes generated release-only resources before `tauri build`, including the current `badvpn-agent` binary. Do not commit generated executables, downloaded cores, WinDivert files, logs, or runtime caches here.
