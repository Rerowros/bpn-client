# Tasks: Desktop UX and Runtime Readiness Fixes

## 0. Planning

- [ ] Confirm target minimum supported window sizes: 1280x720, 1024x700 and 900x650.
- [ ] Capture baseline screenshots for Overview, Settings Basic, Settings Advanced, Settings Operator, Settings Updates, Policy, Servers and Connections.
- [ ] Inventory all text clipping cases from current UI and screenshots.
- [ ] Define shared route label map for `VPN`, `zapret`, `DIRECT`, `Blocked`, `Unknown`.
- [ ] List touched files before implementation; expected UI files are `apps/badvpn-client/src/App.tsx` and `apps/badvpn-client/src/styles.css`.

## 1. Global Layout and Text Fixes

- [ ] Make app shell use viewport-bounded content: fixed header/sidebar, page body scroll only.
- [ ] Add responsive constraints for low-height and narrow desktop windows.
- [ ] Remove critical hard clipping from labels, status text, path badges, table cells and action buttons.
- [ ] Add tooltip/copy affordance for long paths, rules, provider names and error messages.
- [ ] Replace nested card layouts where they cause cramped or uneven surfaces.
- [ ] Verify collapsed sidebar does not break any page layout.

## 2. Overview

- [ ] Keep active profile, connect state, mode switch and primary action visible at low height.
- [ ] Convert provider and agent diagnostics into compact status rows.
- [ ] Collapse secondary diagnostics/details on compact height.
- [ ] Ensure connect/disconnect action remains reachable without scrolling at target sizes.

## 3. Settings

- [ ] Redesign Basic settings as compact rows with label, current value and trailing control.
- [ ] Redesign Advanced settings as grouped disclosure sections.
- [ ] Redesign Operator settings as a bounded list/tab surface rather than full-page card grid.
- [ ] Redesign Updates & Diagnostics so install/repair/runtime preparation actions are easy to find.
- [ ] Keep dangerous network actions behind explicit advanced/disclosure sections.
- [ ] Ensure every settings value wraps or truncates safely with details available.

## 4. Operator and Advanced Lists

- [ ] Split Operator into bounded sections for Snapshot, Zapret checks, Rules & Providers, Resources, Logs and Backup.
- [ ] Add search/filter to rules/providers/resources where missing.
- [ ] Cap rules/providers/logs list height with internal scroll.
- [ ] Collapse providers/resources by category.
- [ ] Add virtualization if long lists still create performance or scroll issues.
- [ ] Verify a profile with many rules/providers does not make the page scroll excessively.

## 5. Policy

- [ ] Normalize Policy naming for modes, paths, sources and zapret effects.
- [ ] Replace uneven summary cards with compact responsive stats/list.
- [ ] Prevent main proxy group and final rule values from being clipped without detail access.
- [ ] Rework filter chips so they wrap cleanly or move into overflow.
- [ ] Make rules table stable on target sizes with aligned action buttons.
- [ ] Add rule detail drawer/popover for long Mihomo rule, source trace and zapret artifact.

## 6. Servers

- [ ] Redesign Servers as proxy group list inspired by Koala Clash K1.
- [ ] Show group name, group type badge, selected node/fallback and right-side actions in each header row.
- [ ] Add expandable group body for nodes/providers.
- [ ] Add search, sort and collapse controls.
- [ ] Make latency/test actions visible and aligned.
- [ ] Separate provider groups from special/local groups.
- [ ] Preserve selected proxy per profile and make fallback/selector naming consistent.

## 7. Connections

- [ ] Normalize route badges and subtitles for `VPN`, `zapret` and `DIRECT`.
- [ ] Rework connection rows to show process, host, destination, traffic, source rule and path consistently.
- [ ] Add or refine grouping by process/domain/path.
- [ ] Move long route/rule details into a drawer or popover.
- [ ] Align close/copy/create override actions across active and closed connections.

## 8. Agent Readiness on Connect

- [ ] Add connect preflight that checks `badvpn-agent` installed/running/version/path readiness.
- [ ] If missing or broken, show inline install/repair action instead of only an error toast.
- [ ] Reuse controlled elevation for install/repair; do not elevate the GUI.
- [ ] After successful repair, retry status/start or show one clear `Start VPN` action.
- [ ] Keep Settings > Updates & Diagnostics as the detailed diagnostics path.
- [ ] Add actionable error copy for missing service, stopped service, wrong binary and missing runtime components.

## 9. Zapret Startup Fix Track

- [ ] Compare managed zapret arguments with the proven Flowseal profile behavior.
- [ ] Verify extracted zapret zip layout, required BAT/profile files, `winws.exe`, WinDivert files and list paths.
- [ ] Verify AppData and ProgramData component discovery/mirroring.
- [ ] Verify selected profile, persisted profile and fallback profile order.
- [ ] Verify hostlist/ipset include/exclude paths and game TCP/UDP filters.
- [ ] Detect external winws/GoodbyeDPI conflicts before spawning.
- [ ] Make zapret failure degrade to VPN-only mode when Mihomo can still start.
- [ ] Surface zapret state as ready, needs components, conflict, started, failed-fallback or disabled-by-mode.

## 10. Validation

- [ ] `npm --prefix apps/badvpn-client run check`
- [ ] `npm --prefix apps/badvpn-client run build`
- [ ] Relevant Rust/Tauri tests for any agent/runtime command changes.
- [ ] Browser QA screenshots for Overview, Settings, Operator, Policy, Servers and Connections at 1280x720, 1024x700 and 900x650.
- [ ] Manual Windows QA: missing agent, stopped agent, repair install, connect retry, Smart with zapret, zapret missing assets, external winws conflict, VPN-only fallback.
- [ ] `git status --short`
