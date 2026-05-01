# BPN Client Agent Rules

This repository is for **BPN Client**, a Windows-first desktop VPN client for the BPN VPN service.

Read [docs/BADVPN_IMPLEMENTATION_PLAN.md](docs/BADVPN_IMPLEMENTATION_PLAN.md) before making product, architecture, routing, installer, service, or update changes.

## Operating Rules

- Keep the first release Windows-first unless the implementation plan is explicitly changed.
- Do not change the architecture stack without a dedicated architecture decision.
- Default stack: Tauri v2, React/TypeScript, Rust workspace, Mihomo core, zapret/winws direct bypass, and a Rust privileged Windows service named `badvpn-agent`.
- Do not run the GUI as administrator. Privileged operations must go through `badvpn-agent`.
- Do not touch unrelated dirty files. If the working tree is dirty, preserve user changes and scope edits tightly.
- Use `rg` or `rg --files` for repository searches.
- Keep generated configs, downloaded cores, lists, logs, and cache files outside tracked source unless the file is an intentional fixture or template.
- Do not log subscription URLs, access tokens, generated secrets, or raw user credentials.
- Prefer structured parsers for YAML/JSON/TOML instead of ad hoc string manipulation.

## Open Source Workflow

- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for branches, PRs, AI-assisted work, architecture proposals, and review expectations.
- Follow [TRADEMARKS.md](TRADEMARKS.md) for official service-link and brand attribution rules.
- Keep PRs focused and reviewable. Split unrelated product, runtime, docs, and CI changes unless a maintainer explicitly asks for one combined PR.
- AI tools are allowed. Disclose meaningful AI assistance in the PR template. The human contributor owns the result and is fully responsible for correctness, security, testing, and docs. Do not treat AI output as trusted authority without verification.
- Security-sensitive changes require maintainer review even if generated tests pass.

## Mandatory Research Gate

Before implementing or changing Tauri or Rust code, verify current documentation with Context7 MCP:

1. Call `resolve_library_id`.
2. Call `query_docs` with the resolved library ID and the specific implementation question.
3. Use `researchMode: true` only if the normal answer is insufficient.

Primary Context7 library IDs:

- Tauri docs: `/tauri-apps/tauri-docs`
- Rust: `/rust-lang/rust`

For crate-specific work, resolve/query the exact crate or docs source through Context7 where available. Examples: `tokio`, `serde`, `serde_yaml`, `serde_json`, `anyhow`, `thiserror`, `tracing`, Windows service crates, and named-pipe/IPC crates.

## Documentation Links

### Tauri v2

- Start: https://v2.tauri.app/start/
- Prerequisites: https://v2.tauri.app/start/prerequisites/
- Configuration: https://v2.tauri.app/reference/config/
- IPC concepts: https://v2.tauri.app/concept/inter-process-communication/
- Capabilities and permissions: https://v2.tauri.app/security/capabilities/
- Shell plugin and sidecars: https://tauri.app/develop/sidecar/
- Updater: https://tauri.app/plugin/updater/
- Windows distribution/signing: https://v2.tauri.app/distribute/sign/windows/
- macOS signing for later ports: https://tauri.app/distribute/sign/macos/

### Rust

- Rust standard library: https://doc.rust-lang.org/std/
- Process management: https://doc.rust-lang.org/std/process/
- Cargo: https://doc.rust-lang.org/cargo/
- Rust Book: https://doc.rust-lang.org/book/
- Tokio docs: https://tokio.rs/
- Crate docs: https://docs.rs/

### Mihomo

- Configuration index: https://wiki.metacubex.one/en/config/
- General configuration and external controller: https://wiki.metacubex.one/en/config/general/
- API: https://wiki.metacubex.one/en/api/
- TUN inbound: https://wiki.metacubex.one/en/config/inbound/tun/
- Routing rules: https://wiki.metacubex.one/en/config/rules/
- Rule providers: https://wiki.metacubex.one/en/config/rule-providers/
- DNS: https://wiki.metacubex.one/en/config/dns/

### zapret / winws

- Main zapret repository: https://github.com/bol-van/zapret
- Releases: https://github.com/bol-van/zapret/releases
- Windows documentation: https://github.com/bol-van/zapret/blob/master/docs/windows.en.md
- Windows quick start: https://github.com/bol-van/zapret/blob/master/docs/quick_start_windows.md
- Windows bundle releases: https://github.com/bol-van/zapret-win-bundle/releases
- Existing local Flowseal-style reference: check `service.bat` from the local zapret-win-bundle if available on the workstation.

## Architecture Constraints

- `badvpn-agent` owns all privileged actions: service installation, service control, Mihomo lifecycle, winws lifecycle, WinDivert cleanup, DNS/routing/firewall changes, updater writes, and rollback.
- The Tauri app communicates with `badvpn-agent` through named pipe or equivalent local IPC with ACL limited to the current user/session.
- Mihomo and winws binaries must be verified by hash/signature before use.
- Component updates must be signed or hash-pinned, atomic, and rollback-capable.
- A zapret/winws failure must not prevent the VPN from starting. It should degrade to VPN-only mode and show an actionable diagnostic state.
- Generated Mihomo configs must set a local external controller with a secret and must not expose controller access beyond localhost unless the plan is explicitly changed.
- Use `DIRECT + zapret` for Flowseal targets in `Smart Hybrid`: Discord, YouTube/Googlevideo, and configured game traffic. Non-target traffic stays on Mihomo VPN.

## Validation Expectations

- Rust changes: run `cargo fmt --check`, `cargo check`, and relevant `cargo test` when a Rust workspace exists.
- Tauri changes: run `cargo tauri info` and the narrowest build/check command that validates the touched area.
- Docs-only changes: verify links/paths for obvious typos and run `git status --short`.
- Installer/service changes: include a manual Windows QA checklist covering install, connect, disconnect, reboot recovery, update, rollback, and uninstall.
