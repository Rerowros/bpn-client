# Gap Matrix: Other Clients vs BPN Zapret Scope

This matrix records functions observed in Clash Verge Rev / Koala Clash style clients, whether the current BPN Client already has them, and how they map to zapret/Smart routing work.

## High Priority: Directly Useful for BPN + zapret

| Feature | Current BPN state | Target change |
| --- | --- | --- |
| `.exe` local override | Core has process lists, UI lacks picker/model | Local Overrides MVP |
| Domain/CIDR/process/port typed overrides | Core partial, UI only domain textareas | Local Overrides MVP |
| Overrides survive subscription refresh | Likely via settings, not productized | Local Overrides MVP |
| Process-aware connections | Connections exist, process grouping/detail weak | Process-Aware Connections |
| Create override from connection | Missing | Process-Aware Connections |
| Runtime rules search/filter | Policy viewer exists, search/filter weak | Rules and Provider Trace |
| Provider rule trace | Suppressed/final rules exist, trace weak | Rules and Provider Trace |
| Rule providers read-only view | Missing | Rules and Provider Trace / Resource Manager |
| Proxy providers read-only view | Missing | Rules and Provider Trace / Resource Manager |
| Live Mihomo logs | Missing | Live Logs and Runtime Config |
| Live zapret/winws logs | Missing | Live Logs and Runtime Config |
| Runtime YAML viewer | Missing | Live Logs and Runtime Config |
| Source vs runtime diff | Missing | Live Logs and Runtime Config |
| YouTube/Discord/AI checks | Diagnostics partial, UI not dedicated | Zapret Health Checks |
| Game/app bypass UI | Runtime logic exists, UI weak | Game/App Bypass Profiles |
| Geodata/zapret list resource manager | Updates partial, resource UI weak | Resources and Providers |
| Verified resource rollback | Partial for components, not full resources | Resources and Providers |
| TUN recovery controls | Basic TUN settings exist, recovery weak | Advanced Network Controls |
| Support bundle with redaction | Planned, not implemented | Backup and Support Bundle |

## Medium Priority: Useful but Needs Product Boundaries

| Feature | Current BPN state | Product boundary |
| --- | --- | --- |
| Local profile import | Missing | Useful for recovery/testing; validate before save |
| Drag-and-drop import | Missing | Same validation as file picker |
| `bpn://` deep link | Missing | Requires confirmation before import |
| Refresh all subscriptions | Missing | Must preserve last working profile on failure |
| Per-profile fetch options | Missing | Credentials protected at rest |
| Edit profile name/notes | Missing | Local metadata only |
| Server search/sort/group | Missing/weak | Fits full redesign servers page |
| Latency test node/group | Missing/weak | Must avoid blocking UI/runtime |
| Auto-close connections after node switch | Missing/unclear | Needs explicit user setting |
| Tray/hide-to-tray | Missing | Windows-first VPN UX, separate shell slice |
| Autostart/silent start | Missing | Windows-first VPN UX, user opt-in |
| Open app/log/runtime dirs | Missing | Useful, but paths redacted in exports |

## Low Priority or Out of Scope for First Slices

| Feature | Decision |
| --- | --- |
| Full Monaco YAML editor | Separate future change only; risky for nontechnical BPN users |
| Visual editor for all proxies/proxy-groups | Future advanced tool, not first zapret slice |
| Arbitrary JavaScript script editor | Out of first scope; security/reliability risk |
| Universal Clash sysproxy workflow | Product decision required; not zapret-specific enough |
| macOS/Linux packaging | Out of Windows-first MVP scope |
| Theme marketplace/custom visual themes | Not relevant to zapret/Smart routing |
| WebDAV sync | Future backup change after encrypted credentials |

## Dependency Notes

- Local overrides should come before process-aware "create override from connection".
- Agent control-plane hardening should come before exposing service-first update/rollback buttons.
- Runtime config/diff viewer should come before any YAML editing.
- Resource manager update actions require digest/signature verification first.
- Tray/background UX should not stop runtime accidentally; quit semantics must be explicit.
