# Tasks: Zapret Operator Tools

## 0. Planning

- [x] Confirm first implementation slice: local overrides vs logs vs resource manager.
- [x] Keep `current-product-functions` as baseline for already implemented behavior.
- [x] Do not implement universal Clash editor parity in this change.
- [x] For every slice, list affected Rust/Tauri/UI files before editing.

## 1. Local App & Rule Overrides

- [x] Add versioned `local_overrides` model or extend `routing_policy` with typed rules.
- [x] Support rule fields: id, enabled, title, path, target kind, value, executable path, process name, source, timestamps.
- [x] Implement migration from existing `force_vpn_*`, `force_zapret_*`, `force_direct_*`.
- [x] Add UI route selector: `DIRECT`, `VPN`, `zapret`.
- [x] Add UI target selector: domain, CIDR, process, `.exe`, TCP port, UDP port.
- [x] Add native `.exe` picker.
- [x] Extract process name from selected executable path.
- [x] Show warning that `.exe` currently compiles to process-name rule if path-specific enforcement is unavailable.
- [x] Add create/edit/disable rule UI for current routing policy arrays.
- [x] Add per-rule delete and enable/disable controls after versioned `local_overrides` model lands.
- [x] Add conflict badges against provider rules and Smart presets.
- [x] Add preview of generated Mihomo/zapret policy target.
- [x] Show saved local override summary including process and port rules.
- [x] Show duplicate warning before saving an already existing local override.
- [x] Add emergency switch to disable all local overrides.
- [x] Ensure subscription refresh cannot overwrite local overrides.
- [x] Add Rust policy tests for local override priority.
- [x] Add settings serialization/migration tests.
- [x] Add frontend unit tests for local override normalization when a test runner is introduced.
- [ ] Add manual Windows QA with a real `.exe`.

## 2. Process-Aware Connections

- [x] Extend connections model if needed with process name/path/source rule.
- [x] Add process grouping mode.
- [x] Add detailed connection card.
- [x] Add route path explanation per connection.
- [x] Add "Create override from this process/domain" action.
- [x] Add "Create override from this policy rule" action.
- [x] Add close all by process/path actions using existing per-flow Mihomo close command.
- [x] Add search by host, process, rule and chain.
- [x] Preserve existing active/closed tabs and path filters.
- [x] Add UI tests or browser QA for grouped and ungrouped views.

## 3. Runtime Rules and Trace

- [x] Add search field for policy/rules.
- [x] Add filters by path: VPN, zapret, DIRECT, blocked.
- [x] Add filters by source: provider, preset, local override, safety.
- [x] Add read-only list for rule providers from generated runtime config.
- [x] Add read-only list for proxy providers from generated runtime config.
- [x] Show provider update status if Mihomo/runtime exposes it.
- [ ] Add manual provider update action only if it can be validated and rolled back.
- [x] Show which provider rules are changed by Smart/zapret overlay.
- [x] Show which provider nodes/groups participate in selected VPN path.
- [x] Explicitly forbid direct provider content editing in first implementation slice.
- [x] Add suppressed-rule explanation panel.
- [x] Add policy trace view: original provider rule -> overlay decision -> final Mihomo rule -> zapret artifact.
- [x] Add rule copy action with redaction.
- [x] Keep provider editing read-only in first slice.

## 4. Live Logs

- [x] Add backend command or stream for redacted agent logs.
- [x] Add Mihomo log stream/view.
- [x] Add winws/zapret log stream/view.
- [x] Add source filters.
- [x] Add level filters.
- [x] Add pause/resume.
- [x] Add auto-scroll toggle.
- [x] Add clear view.
- [x] Add copy selected redacted lines.
- [x] Add first redaction tests for subscription URL leakage.
- [x] Add redaction tests for controller secret and local credentials.

## 5. Runtime YAML and Diff

- [x] Add command to read redacted source profile.
- [x] Add command to read redacted generated runtime YAML.
- [x] Add source-vs-runtime diff generator.
- [x] Highlight changed rules, DNS, TUN, proxy groups and zapret artifacts.
- [x] Mark viewer as read-only.
- [x] Add copy/export redacted output.
- [x] Add tests that redaction runs before rendering/export.

## 6. Zapret Health and Media Checks

- [x] Add check definitions for YouTube, Discord voice/CDN, OpenAI/ChatGPT, Claude, Gemini.
- [x] Add custom domain check input.
- [x] For each check, show route path, DNS result class, probe result and recovery action.
- [x] Show whether target is present in generated zapret hostlist/ipset.
- [x] Add batch check action.
- [x] Add diagnostics history for last check.
- [x] Ensure probes have timeout and cannot hang connect/disconnect.

## 7. Game/App Bypass Profiles

- [x] Expose built-in known profiles in UI.
- [x] Expose detected running game/app candidates.
- [x] Expose learned profiles.
- [x] Add manual profile creation from `.exe`.
- [x] Add editable domains/CIDRs/TCP ports/UDP ports per profile.
- [x] Add filter mode selector: UDP-first, TCP+UDP, aggressive.
- [x] Add risk level display.
- [x] Add enable/disable per profile.
- [x] Add generated rule preview.
- [x] Add tests for disabled games preset and manual profile behavior.

## 8. Resource Manager

- [x] List resource types: geosite, geoip, mmdb, ASN, Flowseal/zapret lists, BPN curated lists.
- [x] Show installed version/date/source.
- [x] Show last check/update time.
- [x] Add manual update action per resource.
- [x] Add update all action.
- [x] Add auto-update interval setting for safe resources.
- [x] Verify digest/signature before activation.
- [x] Activate atomically with rollback.
- [x] Show rollback action if previous resource exists.
- [x] Add tests for failed update preserving previous resource.

## 9. Local Profile Import

- [x] Add local file import for YAML/JSON/TXT.
- [x] Add drag-and-drop import.
- [x] Add `bpn://` deep link import.
- [x] Validate imported profile before saving.
- [x] Show profile metadata preview before activation.
- [x] Do not store raw local file path if not needed.
- [x] Add HWID/provider error-specific messaging where detected.

## 10. Subscription Fetch and Profile Lifecycle

- [x] Add per-profile fetch user-agent setting.
- [x] Add per-profile proxy mode: direct, system proxy, custom proxy.
- [x] Add per-profile fetch timeout.
- [x] Protect custom proxy credentials at rest.
- [x] Add refresh all subscriptions.
- [x] Respect per-profile auto-update interval from provider headers.
- [x] Allow editing profile name.
- [x] Allow editing profile description/notes.
- [x] Show support/homepage/announce metadata without raw subscription URL.
- [x] Add provider/HWID-limit error classification tests.
- [x] Add tests that failed refresh preserves last working profile.

## 11. DNS, Sniffer and TUN Advanced Controls

- [x] Add advanced DNS mode controls only behind advanced section.
- [x] Add fake-ip range and fake-ip filter controls if supported by generator.
- [x] Add nameserver policy viewer/editor only with validation.
- [x] Add sniffer enable/disable.
- [x] Add sniffer protocol controls: HTTP, TLS, QUIC.
- [x] Add force/skip domain lists.
- [x] Add skip source/destination CIDR lists.
- [x] Add reset-to-safe-defaults action.
- [x] Add validation before applying DNS/sniffer changes.
- [x] Add TUN MTU setting if supported by Mihomo config generator.
- [x] Add DNS hijack controls if supported.
- [x] Add excluded route/CIDR controls.
- [x] Add Windows firewall/route reset recovery action through `badvpn-agent`.
- [x] Validate TUN/DNS/sniffer config before replacing last working runtime config.
- [x] Add rollback to last-known-good config if advanced network settings fail validation.

## 12. Backup and Support Bundle

- [x] Add backup export for settings, selected proxies, local overrides, game profiles and profile metadata.
- [x] Add backup import/restore with schema validation.
- [x] Add backup history.
- [x] Add copyable redacted support summary as the first support-bundle slice.
- [x] Add support bundle export.
- [x] Include redacted logs, policy summary, runtime readiness, resource versions and override summary.
- [x] Include system info.
- [x] Include app uptime.
- [x] Include service status.
- [x] Include admin/elevation status.
- [x] Include app/core/log directory paths only after redaction policy is defined.
- [x] Add UI actions to open app data, runtime and log directories.
- [x] Redact local filesystem paths that may contain usernames before export, unless user explicitly chooses raw local-only bundle.
- [x] Show bundle categories before export.
- [x] Add redaction tests.
- [x] Do not include raw subscription URLs, controller secrets, tokens or private credentials.

## 13. Safe File Retirement

- [x] Product cleanup flows must not destructively delete profiles, resources, logs or generated configs by default.
- [x] Retired files should be renamed to `.del`, quarantined or backed up.
- [x] Resource rollback must preserve previous resource until new resource is verified.
- [x] Profile removal must preserve recoverable backup or require explicit destructive confirmation in a future approved change.
- [x] Tests must cover rename/quarantine behavior for cleanup flows touched by this change.

## 14. Validation

- [x] `npm --prefix apps/badvpn-client run check`
- [x] `npm --prefix apps/badvpn-client run build`
- [x] `cargo test -p badvpn-common policy`
- [x] `cargo test -p badvpn-agent runtime`
- [x] Tauri command tests for settings/import/resource changes.
- [x] Browser QA for every new UI page.
- [ ] Manual Windows QA for `.exe` override, zapret health checks, resource update rollback and support bundle redaction.
