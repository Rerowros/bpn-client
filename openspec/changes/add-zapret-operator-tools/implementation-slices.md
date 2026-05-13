# Implementation Slices: Zapret Operator Tools

## Slice 1: Local Overrides MVP

Goal: solve the user pain of `.exe`/domain/process rules being overwritten by subscription refresh.

Tasks:

- typed local override model;
- migration from existing `force_*` arrays;
- `.exe` picker and process-name preview;
- persistence independent of subscription body;
- policy summary visibility;
- priority tests.

Acceptance:

- refresh subscription does not remove local overrides;
- selected `.exe` produces visible generated target;
- private/safety routes still win over unsafe overrides.

## Slice 2: Process-Aware Connections

Goal: make route decisions debuggable from live connections.

Tasks:

- process grouping;
- connection detail;
- route path/source display;
- create override from process/domain.

Acceptance:

- user can identify why a flow is VPN/zapret/DIRECT;
- override creation is prefilled but not auto-saved.

## Slice 3: Rules and Provider Trace

Goal: explain BPN overlay over provider rules.

Tasks:

- rule search/filter;
- provider read-only view;
- suppressed rule details;
- trace provider -> overlay -> final rule -> zapret artifact.

Acceptance:

- no provider content editing in first slice;
- policy trace can explain local override and Smart preset decisions.

## Slice 4: Live Logs and Runtime Config

Goal: provide safe operational observability.

Tasks:

- redacted live logs;
- source/runtime YAML viewer;
- source-vs-runtime diff;
- copy/export redacted text.

Acceptance:

- redaction tests cover URLs, controller secrets and credentials;
- raw config is not exposed before redaction.

## Slice 5: Zapret Health Checks

Goal: give user-facing checks for common blocked services.

Tasks:

- YouTube;
- Discord;
- OpenAI/ChatGPT;
- Claude;
- Gemini;
- custom domain;
- zapret list membership and route path.

Acceptance:

- probes have timeouts;
- result includes recovery action;
- failed probe does not block connect/disconnect.

## Slice 6: Game/App Bypass Profiles

Goal: expose current runtime game profile logic safely.

Tasks:

- known/detected/learned/manual profiles;
- `.exe` manual profile creation;
- domains/CIDRs/ports/filter mode;
- preview generated rules.

Acceptance:

- disabling games preset disables generated profile routes;
- manual profile can be disabled or removed from active use without deleting evidence.

## Slice 7: Resources and Providers

Goal: make route/zapret resource state visible and updateable safely.

Tasks:

- geosite/geoip/mmdb/ASN if used;
- Flowseal/zapret lists;
- BPN curated lists;
- rule providers/proxy providers read-only;
- verified update and rollback.

Acceptance:

- failed update preserves previous resource;
- update status is visible;
- provider editing remains out of scope.

## Slice 8: Profile Lifecycle

Goal: improve imports and refresh behavior.

Tasks:

- local file import;
- drag-and-drop;
- `bpn://`;
- refresh all;
- fetch UA/proxy/timeout;
- profile local name/notes;
- provider/HWID errors.

Acceptance:

- failed refresh preserves last working body;
- sensitive URLs remain redacted.

## Slice 9: Advanced Network Controls

Goal: expose DNS/sniffer/TUN only after validation and rollback are ready.

Tasks:

- DNS mode/policy/fake-ip controls;
- sniffer protocols and force/skip lists;
- TUN MTU/DNS hijack/excluded routes;
- route/firewall reset.

Acceptance:

- invalid config cannot replace last working config;
- reset-to-safe-defaults is available.

## Slice 10: Backup and Support Bundle

Goal: make support/debug portable without leaking secrets.

Tasks:

- backup settings/profiles/overrides/game profiles;
- restore with schema validation;
- support bundle with redacted logs/policy/resources/system info;
- directory open actions.

Acceptance:

- raw secrets are excluded;
- local filesystem usernames are redacted in exported bundle by default.
