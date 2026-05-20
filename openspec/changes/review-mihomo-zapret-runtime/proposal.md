# Change: review-mihomo-zapret-runtime

## Why

Smart mode depends on two independent runtimes working as one system: Mihomo for TUN/routing and zapret/winws for DIRECT DPI bypass. The current implementation has several high-risk failure surfaces that can make zapret appear broken or make connect feel slow:

- UI/runtime readiness can treat user-scoped `%APPDATA%` components as ready while the service-owned `badvpn-agent` needs `%PROGRAMDATA%` components.
- Service-first startup still contains legacy GUI-owned runtime paths and component checks, increasing the chance of divergent behavior.
- winws startup is sensitive to Flowseal bundle layout, BAT profile parsing, generated list paths, WinDivert elevation/conflicts, and external `winws.exe`/GoodbyeDPI processes.
- connect currently performs blocking validation, process scans, winws startup wait, Mihomo readiness wait, and optional remote probes in sequence.
- fallback and rollback paths must keep VPN Only safe: no Smart DIRECT rules, no zapret artifacts, no provider `DIRECT` escape.

## What Changes

This change adds a focused runtime review and fix track for Mihomo + zapret:

- Audit and fix service-owned component readiness/staging so the agent only starts with assets it can actually read.
- Audit and test winws/Flowseal argument generation, list generation, selected profile fallback, and WinDivert conflict diagnostics.
- Keep Smart failure degraded to VPN Only when Mihomo can still start.
- Auto-degrade an already-running Smart session to VPN Only if owned winws dies after startup.
- Remove or cap blocking remote probe behavior from the critical connect path.
- Add focused Rust tests for service component readiness, fallback policy invariants, zapret list/path generation, and startup timing guards.
- Document Windows manual QA for missing assets, AppData-only assets, ProgramData staging, external conflicts, slow probes, and fallback.

## Affected Capabilities

- `smart-routing-runtime`
- `diagnostics-security`
- `component-updates`

## Out of Scope

- Running the GUI as administrator.
- Reintroducing the legacy `BadVpnZapret` service as the normal Smart mode owner.
- Changing public route modes beyond `Smart` and `VPN Only`.
- Shipping unsigned/unverified component update trust as a release-ready solution.
- Replacing the current sequential IPC command model with cancellable background operations.

## Rollback

- Runtime fixes must preserve current AppData component cache and only mirror/stage into ProgramData.
- If zapret startup fails, Mihomo startup should continue with a freshly compiled VPN Only policy.
- If Mihomo validation/start fails, current run config must roll back to last working config and winws must be stopped.
- OpenSpec documentation can be reverted independently from code fixes.
