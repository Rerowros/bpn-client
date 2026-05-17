# Design: Desktop UX and Runtime Readiness Fixes

## Principles

- Main flow first: import profile, pick mode/server, connect, see state.
- Dense, readable operator UI: use compact rows, accordions, tabs and scroll containers instead of large card grids.
- Text must remain readable: no critical labels, paths, rule names, status messages or actions may disappear at common desktop window sizes.
- Keep BPN's service-first architecture: privileged install/repair/start remains owned by `badvpn-agent` and controlled elevation, not by an elevated GUI.
- Zapret failure is not VPN failure: Smart can fall back to VPN-only with diagnostics instead of blocking the whole connection.

## Responsive Layout Targets

Support at minimum:

- 1280x720 normal desktop window.
- 1024x700 compact desktop window.
- 900x650 narrow/low-height window.
- Collapsed sidebar state.

Every primary page must keep header/actions visible and make only the page body scroll. Nested scroll is allowed only for bounded long lists such as rules, providers, logs and connections.

## Visual System

Use a restrained desktop app model:

- one page header;
- one primary content region;
- compact rows for settings and server groups;
- cards only for repeated objects that benefit from framing;
- no card-inside-card layouts;
- consistent path colors and labels:
  - `VPN`: selected Mihomo proxy path;
  - `zapret`: DIRECT plus winws/zapret bypass;
  - `DIRECT`: direct route without zapret;
  - `Blocked`: rejected path;
  - `Unknown`: runtime could not classify.

Actions should be icon buttons or compact text+icon buttons when the command is clear. Long values should use middle ellipsis plus tooltip/copy action, not hard clipping.

## Page Plan

### Overview

Problems:

- low-height windows hide important connection/profile/provider content;
- status and diagnostics blocks compete vertically with the connect control.

Fix direction:

- keep active profile, connect control, mode switch and immediate diagnostics in the first viewport;
- make provider/service diagnostics a compact status list below;
- use responsive two-column layout only when it does not hide connect state;
- collapse secondary details behind disclosure on compact height.

### Settings

Problems:

- Basic, Advanced, Operator and Updates are heavy and visually overloaded.

Fix direction:

- replace large panels with a settings list pattern similar to Koala Clash;
- group settings into rows with label, current value, short status and trailing control;
- use disclosure sections for advanced DNS/TUN/sniffer/zapret options;
- show dangerous or advanced write actions only inside explicit advanced sections;
- keep Updates & Diagnostics discoverable for agent repair/runtime preparation.

### Operator and Advanced

Problems:

- rules/providers/resources/logs can extend the page far downward.

Fix direction:

- split into tabs or segmented sections: Snapshot, Checks, Rules & Providers, Resources, Logs, Backup;
- cap each long list height with internal scroll and search/filter;
- collapse providers/resources by category;
- virtualize long rule/provider/log lists if DOM size becomes a performance issue;
- keep top-level page height bounded to the viewport.

### Policy

Problems:

- inconsistent naming, uneven summary layout, clipped main proxy group/final rule values, visually noisy chips.

Fix direction:

- use one naming map for mode/path/source/zapret effect across Policy and Connections;
- make summary metrics a compact responsive grid/list;
- use filter chips only when they fit, otherwise wrap cleanly or move into menu;
- make rule table horizontally resilient with fixed actions column and copy/details controls;
- provide detail drawer for long Mihomo rule, source trace and zapret artifact.

### Servers

Problems:

- current page is visually crooked and does not match expected proxy group ergonomics.

Fix direction:

- redesign as proxy groups list using Koala Clash K1 reference:
  - group header row with name, type badges, selected node and right-side actions;
  - expandable group body with nodes/providers in compact rows;
  - latency/test action visible per node or group;
  - provider groups separated from local/special groups;
  - search, sort and collapse controls in the page toolbar.
- preserve selected proxy per profile and make fallback/selector semantics readable.

### Connections

Problems:

- layout and route labels are hard to scan; `vpn`, `zapret`, `direct` signatures look inconsistent.

Fix direction:

- normalize path badges and explanatory subtitles;
- show process, host, destination, speed/bytes, rule source and path in a stable row layout;
- group by process/domain/path with a compact switch;
- move long technical rule detail into drawer/popover;
- keep close/copy/override actions aligned.

## Startup Readiness Flow

Current behavior blocks connect with `badvpn-agent is not installed...` and requires the user to know where to go.

Expected flow:

1. User presses Connect.
2. UI asks runtime for service readiness.
3. If service is missing, stopped, wrong binary, or missing runtime components, UI shows an inline readiness action.
4. User can run install/repair/prepare through the existing controlled elevation path.
5. After success, UI retries status/start automatically or offers a single `Start VPN` action.
6. If repair fails, diagnostics show a precise reason and keep Settings > Updates & Diagnostics as the detailed route.

No connect path may require running the whole GUI as administrator.

## Zapret Flowseal Compatibility Fix Track

Investigate and fix Smart mode zapret startup around:

- extracted Flowseal zip layout and required BAT/profile files;
- `winws.exe`, WinDivert files and list path discovery;
- selected profile argument translation from Flowseal BAT to managed winws spawn;
- game TCP/UDP filters and hostlist/ipset include/exclude arguments;
- fallback profile order and persisted profile recovery;
- external winws/GoodbyeDPI conflicts;
- missing ProgramData/AppData component mirroring;
- errors that should be degraded to VPN-only rather than failing Mihomo startup.

The UI should surface zapret state as:

- Ready;
- Needs components;
- Conflict detected;
- Started;
- Failed, using VPN-only fallback;
- Disabled by VPN Only mode.

## Validation

UI:

- TypeScript check/build.
- Browser QA screenshots at the target window sizes.
- Text clipping scan for major labels, buttons, table cells and status messages.
- Manual pass for expanded/collapsed sidebar.

Runtime:

- Rust tests for service readiness classification where possible.
- Tauri command tests or narrow integration checks for agent install/repair/status flow.
- Manual Windows QA for missing agent, stopped agent, wrong agent binary, missing zapret assets, external winws conflict, Smart fallback and VPN-only connect.
