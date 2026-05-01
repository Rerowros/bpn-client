# BadVpn Runtime Contract

This document owns runtime behavior: `badvpn-agent`, IPC, Mihomo/winws lifecycle, generated configs, logs, preflight, and fallback. Product scope lives in `docs/BADVPN_IMPLEMENTATION_PLAN.md`; update/signing rules live in `docs/update-release.md`; manual scenarios live in `docs/qa-win-mvp.md`.

## Runtime Ownership

- `badvpn-agent` owns privileged runtime work: Mihomo lifecycle, winws/zapret lifecycle, WinDivert cleanup, DNS/routing/firewall changes, generated runtime files, ProgramData assets, update swaps, rollback, and recovery.
- The Tauri backend keeps user-scoped state in `%APPDATA%\BadVpn` and sends commands to `badvpn-agent`.
- The GUI must not start `mihomo.exe`, `winws.exe`, or a separate zapret service in normal flows.
- `BADVPN_LEGACY_RUNTIME=1` is only a development/debug escape hatch.
- The legacy `BadVpnZapret` service is detect-only and cleanup-only. Normal Smart mode launches winws through `badvpn-agent`.

## IPC

- Primary Windows IPC: `\\.\pipe\badvpn-agent`.
- Pipe access must be limited to LocalSystem, Administrators, and the installing/current user SID. Blanket interactive-user write access is not release-safe.
- Localhost TCP `127.0.0.1:38790` is a development fallback only and requires `BADVPN_AGENT_TCP_FALLBACK=1`.
- Wire format: one JSON `AgentCommand` per line and one JSON response per line.

## Connect Flow

1. UI loads the active subscription profile, fetches the raw Clash/Mihomo body, and sends the body to the agent. The subscription URL itself is not sent.
2. The agent runs preflight before mutating runtime state.
3. The agent compiles one `CompiledPolicy` from subscription YAML, BadVpn presets, user overrides, game profiles, runtime facts, and selected proxy groups.
4. The same compiled policy renders:
   - Mihomo rules and overlay settings;
   - zapret hostlist, hostlist-exclude, ipset, and ipset-exclude;
   - DNS policy;
   - diagnostics expectations and suppressed-rule reasons.
5. In `Smart`, the agent starts winws when zapret coverage is required and safe. If winws cannot start, the agent recompiles a fresh `VPN Only` policy and degrades without blocking VPN startup.
6. In `VPN Only`, the agent stops winws, emits no zapret artifacts, and prevents external traffic from escaping through provider `DIRECT` rules or groups containing `DIRECT`.
7. The agent writes a draft Mihomo config, validates it with `mihomo -t` where available, promotes it atomically, and keeps `last-working.yaml` for rollback.
8. The agent starts Mihomo, verifies the local controller, and reports runtime state through IPC.

## Preflight

Preflight runs before winws or Mihomo starts.

| Severity | Runtime action | Examples |
|---|---|---|
| `block_vpn` | Do not start winws or Mihomo | occupied mixed/controller/DNS ports, missing Mihomo binary, external VPN/TUN core already running |
| `degrade_to_vpn_only` | Skip winws and start Mihomo with VPN Only policy | missing winws, external zapret/GoodbyeDPI conflict |
| `diagnostic_warning` | Continue and show diagnostics | stale BadVpn TUN adapter evidence, optional probe failure |

Preflight should cover mixed/controller ports, DNS port `1053` TCP/UDP, managed component paths, external Mihomo/Clash/sing-box/v2rayN processes, stale BadVpn TUN adapter state, external winws/GoodbyeDPI conflicts, and WinDivert state.

## Component Layout

- User downloads and subscription state: `%APPDATA%\BadVpn`.
- Service runtime assets/configs/logs: `%PROGRAMDATA%\BadVpn`.
- Agent service install/repair stages the current BadVpn runtime assets into ProgramData.
- Runtime update/repair should eventually download, verify, stage, swap, smoke-check, and rollback entirely inside `badvpn-agent`.

## Logs And Secrets

- GUI/Tauri backend log: `%APPDATA%\BadVpn\logs\badvpn.log`.
- Agent service log: `%PROGRAMDATA%\BadVpn\logs\badvpn-agent.log`.
- Logs must not contain subscription URLs, controller secrets, access tokens, raw generated YAML with credentials, or user credentials.
- Diagnostics bundles must redact the same data before export.

## Runtime Checks

BadVpn performs lightweight status checks in the background and full diagnostics on demand.

Checks include:

- agent service installed/running and IPC reachable;
- installed `badvpn-agent.exe` path/version/hash matching the staged build;
- running service process path matching the installed service image;
- Mihomo config/controller/process health through the agent;
- selected proxy groups visible through the Mihomo controller;
- policy expectations versus rendered Mihomo rules where available;
- winws/zapret health through the agent;
- legacy `BadVpnZapret` service state;
- WinDivert assets, BFE, driver state, and common conflict checks;
- optional HTTPS probes for key targets.

## Open Runtime Gaps

- Persist the installing user SID for named-pipe ACLs instead of relying on active-console-user discovery.
- Move final component update download/verify/swap ownership from GUI-assisted staging into `badvpn-agent`.
- Finish reboot recovery and reattach-to-existing-owned-process logic.
- Add late winws death auto-fallback policy if the product decision enables it.
