# Reference Client Feature Audit

This audit summarizes local source review of cloned reference clients under `tmp/reference-clients`. It is product research only; BPN Client must not copy GPL/AGPL code from these projects.

Reviewed clients:

- Koala Clash (`coolcoala/koala-clash`)
- Clash Verge Rev (`clash-verge-rev/clash-verge-rev`)
- FlClash (`chen08209/FlClash`)
- Hiddify App (`hiddify/hiddify-app`)

## Executive Summary

Clash Verge Rev is the closest architectural reference for a Tauri/Rust desktop client with a helper/service UX. Koala Clash and FlClash are strongest references for subscription/profile ergonomics, provider metadata, proxy groups, and operator screens. Hiddify is useful for panel metadata, profile lifecycle, and readable failure states.

None of the reviewed clients directly solves BPN Client's main differentiator: Windows-first `badvpn-agent` ownership of privileged networking with Mihomo VPN and zapret/winws direct bypass running in parallel. BPN should borrow UX and validation patterns, not runtime authority.

## Feature Matrix

| Area | Reference behavior | BPN decision |
|---|---|---|
| Profiles and subscriptions | Remote/local import, drag-and-drop, deep links, update all, auto-refresh, metadata headers, quota/expire display, duplicate detection. | Keep Clash/Mihomo URL import as baseline. Add provider metadata, classified failures, last-known-good rollback, safe local import/deep link, and per-profile lifecycle history. |
| Provider metadata and panels | Profile title, update interval, support/account URL, announcement, user info. Hiddify-style panel metadata is useful; panel-specific announcements are not trusted app announcements. | Show provider links and announcements as read-only metadata. Keep BPN-signed announcements as a separate future channel. |
| Core lifecycle | Core sidecar/service modes, restart/reload, validation before apply, service install/repair UX. | Production runtime is service-first through `badvpn-agent`. GUI sidecar fallback is allowed only for development/diagnostics, not release architecture. |
| TUN and DNS | Rich controls for TUN stack, auto-route, strict-route, DNS hijack, fake-ip/redir-host, nameserver policy, exclusions. | Use safe Windows defaults. Hide broad editors behind advanced diagnostics. Validate before replacing the last working runtime config. |
| Rules and providers | Provider list/update, runtime rules, YAML diff, geodata update, overlay cleanup, invalid proxy reference cleanup. | Preserve provider groups and providers. BPN policy compiler remains authority. Show suppressed/overridden provider rules and zapret artifacts. |
| Routing modes | Rule/global/direct, system proxy, TUN, bypass/private route controls, per-app/process routing in some clients. | Public modes stay `Smart` and `VPN Only`. Smart means Mihomo VPN plus `DIRECT + zapret` for Discord/YouTube/games. VPN Only must suppress external provider `DIRECT` leakage. |
| Proxy groups | Selected group/node persistence, latency tests, group sorting, provider group visibility. | Show selected profile/node and provider groups. Persist selected proxies per profile. Full provider group editing stays out of MVP. |
| Connections | Traffic, memory, process-aware connections, close flow, connection detail cards. | Keep process-aware connection view as advanced/support surface. Add route explanation and override creation where safe. |
| Logs | Core log stream, app/service logs, filters, export, rotation. | Structured logs by UI, agent, Mihomo, winws, updates, diagnostics. Always redact subscription URLs, secrets, and credentials before rendering/export. |
| Diagnostics | System info, ports, network interfaces, service mode, open log/core dirs, support bundle. | Extend with BPN-specific WinDivert, winws/zapret, conflicting DPI/VPN tools, DNS/route/firewall ownership, Mihomo API, and policy expectations. |
| Updates | App updater, core/geodata update, staged downloads, hash checks, rollback UX. | BPN component manifest is authority for Mihomo, winws, WinDivert, lists, and templates. Use hash/signature verification, atomic swap, smoke check, rollback. |
| Backup | Settings/profile backup, local/WebDAV backup in some clients. | Backup non-secret settings, selected proxies, local overrides, game profiles, and profile metadata. Keep URLs/secrets DPAPI-protected or redacted. |

## OpenSpec Follow-Ups

The audit produced two implementation tracks:

1. `add-zapret-operator-tools`: advanced operator surfaces for local overrides, process-aware connections, policy trace, logs, runtime config/diff, zapret checks, game profiles, resources, import, and support bundles.
2. `add-subscription-panel-intelligence`: subscription provider classification, HWID/device-limit errors, panel metadata, provider links, refresh history, and Remnawave/Pasarguard compatibility fixtures.

## Non-Goals

- Universal Clash IDE parity.
- Arbitrary JavaScript profile scripts.
- GUI-owned privileged networking.
- Trusting provider announcements as signed BPN announcements.
- Insecure certificate verification bypass as normal subscription import behavior.

