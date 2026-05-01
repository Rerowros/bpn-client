# BPN Client Implementation Plan

BPN Client is a Windows-first desktop VPN client for the BPN VPN service. The first release must provide a simple, reliable desktop flow around a Clash/Mihomo subscription, Mihomo TUN routing, and local zapret/winws bypass for Discord, YouTube/Googlevideo, and configured games that should not go through VPN servers.

For agent-driven development, this file is the product and architecture contract. Keep task status in `docs/PLAN.MD`, runtime mechanics in `docs/runtime-mihomo-zapret.md`, update rules in `docs/update-release.md`, and manual QA in `docs/qa-win-mvp.md`.

## Product Goal

BPN Client should let a user install the app, add a Clash/Mihomo subscription URL, press connect, and get a working desktop connection without manually editing configs, running batch files, or choosing technical routing options.

The first public routing model has two modes. **Smart** is the default:

- VPN targets are handled by Mihomo.
- Discord, YouTube/Googlevideo, and configured game traffic use `DIRECT + zapret/winws` so they do not travel through VPN servers.
- Safe direct targets and provider overrides are decided by Smart Routing Core and must be explainable in diagnostics.
- `VPN Only` is the safety mode for routing external traffic through VPN without zapret.
- Advanced routing controls stay hidden until the baseline flow is reliable.

## Implementation Defaults

- Product name: `BPN Client`
- First platform: Windows 10/11
- Later platform targets: macOS and Linux after the Windows service/routing model is stable
- UI stack: Tauri v2 + React + TypeScript
- Backend stack: Rust workspace
- Privileged service: Rust Windows service named `badvpn-agent`
- VPN core: Mihomo, app-managed and updateable
- DPI bypass: zapret `winws.exe` with WinDivert on Windows
- Subscription input: Clash/Mihomo-compatible URL
- UI-to-agent IPC: named pipe or equivalent local IPC with ACL scoped to the current user
- Managed runtime assets: `mihomo`, `winws`, WinDivert files, route lists, generated configs, logs, state, and backups

## Feature Groups

### FG1. Windows Desktop Shell

Build a native-feeling desktop shell that stays simple for non-technical users.

- Tauri v2 app with React/TypeScript UI.
- First-run onboarding for subscription URL import and connect readiness.
- Main screen with connection state, selected profile, selected node/group, traffic, and route mode.
- Tray menu with connect, disconnect, reconnect, current state, and diagnostics.
- Settings for subscription refresh, startup behavior, route mode, logs, diagnostics, and updates.
- Installer/uninstaller flow with one controlled elevation path for installing `badvpn-agent`.

Acceptance:

- Clean Windows install launches the UI without requiring administrator mode.
- User can complete onboarding and reach a connected or actionable error state.
- Tray actions work after closing the main window.

### FG2. Mihomo Core Integration

Mihomo is the only VPN/TUN core for the first release.

- Download or bundle a verified Mihomo binary.
- Generate an app-owned Mihomo home directory and config.
- Enable TUN with safe Windows defaults.
- Configure local external controller with a generated secret.
- Use Mihomo API for status, version, traffic, logs, proxy groups, node selection, and connection visibility.
- Support reload/restart without corrupting the current working profile.
- Store previous working config for rollback.

Acceptance:

- `badvpn-agent` can start, stop, restart, and health-check Mihomo.
- Mihomo `/version`, `/traffic`, `/proxies`, `/connections`, and `/rules` are reachable locally with the generated secret.
- Bad configs do not overwrite the last known working config.

### FG3. Clash Subscription Management

The service integration starts with Clash/Mihomo subscription compatibility.

- Add, edit, remove, and refresh subscription URLs.
- Validate fetched profiles before applying them.
- Normalize provider configs into BPN Client-managed Mihomo config overlays.
- Preserve provider proxy groups while adding app routing, DNS, controller, and TUN settings.
- Detect duplicate subscriptions and failed refreshes.
- Keep refresh history and rollback to the previous valid profile.

Acceptance:

- At least one normal Clash-compatible subscription imports and connects.
- Expired, empty, malformed, or unreachable subscriptions produce clear errors.
- Refresh failure does not break the currently working connection.

### FG4. Smart Routing and zapret/winws Bypass

Discord, YouTube/Googlevideo, and configured games should avoid VPN servers when local DPI bypass can handle them.

- Public route modes: `Smart` and `VPN Only`.
- Legacy/internal aliases such as `Smart Hybrid`, `VPN All`, `DPI Only`, and `Manual` may exist only for migration compatibility.
- Add Mihomo `DIRECT` rules for Smart bypass targets so Discord, YouTube/Googlevideo, and game-bypass traffic do not use VPN nodes.
- Run zapret/winws for DPI circumvention on the direct path.
- Start from the proven local Flowseal-style strategy:
  - Discord domains and media hosts.
  - YouTube/Googlevideo domains and Google media hosts.
  - Discord/STUN UDP ranges.
  - Game filter modes: off, TCP, UDP, TCP+UDP.
  - Optional user include/exclude hostlists and ipsets.
- Detect and explain WinDivert/zapret conflicts.

Acceptance:

- In `Smart`, Discord, YouTube/Googlevideo, and game-bypass traffic is not sent through the selected VPN proxy.
- In `VPN Only`, external traffic must not escape through provider `DIRECT` rules or proxy groups that contain `DIRECT`.
- zapret failure degrades gracefully and does not prevent VPN startup.

### FG5. Rust Privileged Agent

`badvpn-agent` is the only component allowed to mutate privileged networking state.

- Install and manage itself as a Windows service.
- Own Mihomo and winws process lifecycle.
- Own WinDivert cleanup and conflict checks.
- Apply and revert DNS, route, firewall, service, and update changes atomically.
- Expose a narrow command API to the UI:
  - `status`
  - `start`
  - `stop`
  - `restart`
  - `set_subscription`
  - `refresh_subscription`
  - `select_proxy`
  - `set_route_mode`
  - `set_dpi_profile`
  - `run_diagnostics`
  - `update_components`
  - `rollback_component`
- Record audit logs for privileged actions without storing secrets.

Acceptance:

- UI never needs to run as administrator after the service is installed.
- Service crash or failed apply does not leave permanent broken routes/firewall rules.
- Reboot recovery restores the correct intended state or reports a clear safe-mode state.

Additional runtime hardening:

- `badvpn-agent` is the single control plane for all privileged runtime actions. The Tauri backend must not create, start, stop, or mutate separate VPN/zapret services directly.
- The legacy `BadVpnZapret` service is detect-only and cleanup-only. Normal Smart mode must launch winws through `badvpn-agent`.
- Preflight must run before starting winws or Mihomo and must cover mixed/controller ports, DNS port `1053` TCP/UDP, external Mihomo/Clash/sing-box/v2rayN processes, stale BadVpn TUN adapter state, and external winws/GoodbyeDPI conflicts.
- Mihomo controller secrets must be cryptographically random and non-derivable from timestamps.
- Named-pipe IPC must be scoped to LocalSystem, Administrators, and the installing/current user SID; blanket interactive-user pipe access is not acceptable for release.
- Clash/Mihomo provider rules, including `GEOIP` and `GEOSITE`, must be preserved unless a documented BadVpn overlay intentionally overrides a specific Smart direct target.

### FG6. Updates and Component Integrity

BPN Client must keep Mihomo and bypass assets current without blindly trusting remote release pages.

- Use signed app updates for the Tauri client.
- Use a BPN Client component manifest for Mihomo, winws, WinDivert, lists, and config templates.
- Verify each component by hash and, where possible, signature.
- Download into staging, verify, stop affected processes, atomically swap, test, then commit.
- Keep previous component versions for rollback.
- Show component versions and update status in diagnostics.

Acceptance:

- Failed update rolls back automatically.
- Update checks do not expose subscription credentials.
- Core/list updates can be separated from app updates.

### FG7. Diagnostics, Security, and Support

The product needs built-in support visibility because routing and DPI bypass failures are environment-specific.

- Structured logs for UI, agent, Mihomo lifecycle, winws lifecycle, updates, and diagnostics.
- Diagnostics checks for:
  - Mihomo health.
  - winws process/service state.
  - WinDivert service/driver state.
  - conflicting GoodbyeDPI/zapret services.
  - known software conflicts such as AdGuard, Killer, Intel Connectivity Network Service, Check Point, and SmartByte.
  - system proxy and DNS state.
- Exportable support bundle with redacted logs and versions.
- Secret storage through Windows DPAPI for subscription URLs, controller secrets, and local tokens.
- No plaintext secrets in logs, crash reports, or support bundles.

Acceptance:

- User can export a redacted diagnostic bundle.
- Diagnostics describe likely conflicts and next actions.
- Logs are useful for support without leaking credentials.

## Milestones

### M1. Foundation MVP

Deliver a working Windows app shell with one subscription and Mihomo lifecycle control.

Includes:

- Tauri app scaffold.
- Rust workspace scaffold.
- `badvpn-agent` install/start/status basics.
- Subscription import and validation.
- Generated Mihomo config.
- Mihomo start/stop/restart and health checks.
- Basic UI connection state.

Exit criteria:

- Clean Windows 11 install can import one subscription and connect through Mihomo.
- Disconnect and reconnect work without manual cleanup.
- Invalid subscription errors do not corrupt the working config.

### M2. Smart and zapret/winws

Deliver the first real differentiator: VPN plus direct DPI bypass for Discord, YouTube/Googlevideo, and games.

Includes:

- Managed winws/WinDivert assets.
- zapret/winws service/process lifecycle through `badvpn-agent`.
- `Smart` and `VPN Only` route modes.
- Discord direct rules.
- Game filter modes.
- Conflict diagnostics for existing DPI/VPN tools.

Exit criteria:

- Discord and selected game traffic avoid VPN proxy nodes in `Smart`.
- VPN still starts if zapret fails.
- Toggling route modes applies and reverts cleanly.

### M3. Production Readiness

Make the app safe to install, update, recover, and uninstall.

Includes:

- Installer/uninstaller.
- Signed app update path.
- Signed/hash-pinned component manifest.
- Atomic component updates and rollback.
- Reboot recovery.
- Redacted diagnostics export.
- Support-oriented logs.

Exit criteria:

- App survives reboot and reports the correct intended state.
- Failed component update rolls back.
- Uninstall removes only BPN Client-owned services, rules, files, and scheduled tasks.

### M4. Release Hardening

Polish the experience and harden the implementation for general availability.

Includes:

- Better onboarding and empty states.
- Proxy/group selection UI.
- Performance and memory tuning.
- Broader Windows 10/11 QA matrix.
- Security review of IPC, update flow, secret handling, and service permissions.
- Initial macOS/Linux architecture notes based on Windows lessons.

Exit criteria:

- Support team has install, troubleshooting, diagnostics, and rollback runbooks.
- QA covers first install, update, reconnect, crash recovery, and uninstall.
- No known blocker remains for a public Windows release.

## Global Acceptance Criteria

- BPN Client installs and runs on a clean Windows 10/11 machine.
- UI runs without administrator privileges after setup.
- User can add a Clash/Mihomo subscription and connect.
- Mihomo lifecycle is stable across connect, disconnect, reconnect, app restart, and system reboot.
- `Smart` keeps Discord and configured game-bypass traffic off VPN servers.
- zapret/winws failure does not block VPN startup.
- Updates are verified and rollback-capable.
- No secrets appear in plaintext logs or diagnostic bundles.
- Uninstall cleans BPN Client-owned services, route/firewall changes, managed assets, and scheduled tasks without touching unrelated VPN/DPI tools.
- Diagnostics can attest the installed `badvpn-agent.exe` path/version/hash and warn when the installed service binary differs from the staged build.

## Current Open Questions

- Exact first-release game target list beyond broad high-port game filter modes.
- Whether telemetry is local-only or opt-in remote reporting.
- Which distribution channel is first: direct signed installer only, or direct installer plus Microsoft Store later.
- How much advanced rule editing should be exposed in v1 versus kept in config files.
