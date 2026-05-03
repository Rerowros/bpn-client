# BPN Client Roadmap

_Last updated: 2026-05-01_

BPN Client is a Windows-first desktop client for the BPN service. The project combines Mihomo TUN routing, zapret/winws DPI bypass, a privileged Rust agent service, and a Tauri UI into one product aimed at predictable, low-latency access under restrictive network conditions.

This roadmap is intended for maintainers, contributors, and AI coding agents. It describes the product concept, architectural constraints, milestones, task queues, validation requirements, and areas that must not be changed casually.

Related documents:

- [`README.md`](README.md) — repository overview and contributor entry points.
- [`AGENTS.md`](AGENTS.md) — mandatory rules for AI agents and maintainers.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — PR, branch, review, and AI-assisted contribution rules.
- [`docs/PLAN.MD`](docs/PLAN.MD) — active implementation plan and current work queue.
- [`docs/runtime-mihomo-zapret.md`](docs/runtime-mihomo-zapret.md) — runtime ownership and connect flow.
- [`docs/qa-win-mvp.md`](docs/qa-win-mvp.md) — manual Windows QA matrix.
- [`docs/update-release.md`](docs/update-release.md) — update, release, signing, and rollback notes.

---

## 1. Product Concept

### 1.1. What BPN Client should become

BPN Client should feel like a one-button Windows application that knows when to use VPN, when to use direct routing, and when to use zapret/winws for DPI bypass.

The target user should not need to understand Mihomo, zapret, WinDivert, TUN adapters, fake-ip DNS, proxy groups, geosite rules, or provider subscriptions. They should be able to import a subscription, press **Connect**, and get a stable result:

```text
Smart mode:
  YouTube / Discord / selected games -> direct route + zapret, low latency.
  AI / social / blocked services      -> VPN proxy group.
  RU/local/bank/service domains       -> direct safe route.
  If zapret fails                     -> safe fallback to VPN Only.

VPN Only:
  External traffic                    -> VPN.
  zapret                              -> stopped.
  Private/LAN/safety traffic          -> direct.
```

The product goal is not to be a generic Clash/Mihomo GUI. BPN Client is a policy-driven application with a specific operating model for the BPN service and for users who need practical routing under network restrictions.

### 1.2. Public modes

Only two user-facing modes are allowed:

1. **Smart**
   - Default route is direct.
   - YouTube, Discord, and configured game targets go through `DIRECT + zapret`.
   - AI/social/provider-proxy targets go through VPN.
   - RU/local/safe targets remain direct.
   - If zapret is unavailable, the runtime safely recompiles and falls back to VPN Only.

2. **VPN Only**
   - External traffic goes through VPN.
   - zapret is disabled/stopped.
   - Provider external `DIRECT` rules are suppressed unless the user explicitly added `Force DIRECT`.
   - If the provider's main proxy group contains `DIRECT`, BPN creates a managed non-DIRECT group.

Do not add more public routing modes without a separate architecture proposal. Old values such as `smart_hybrid`, `zapret_first`, `vpn_all`, `dpi_only`, `manual`, and `unknown` may exist only as compatibility aliases for persisted settings and old runtime payloads.

### 1.3. Why the project needs policy core

A split implementation is unsafe:

```text
Mihomo rules decide one thing.
zapret hostlists decide another.
DNS policy decides a third thing.
Diagnostics guess expected behavior separately.
```

The correct model is:

```text
Subscription YAML
+ BPN presets
+ user overrides
+ game profiles
+ runtime facts
+ selected proxy groups
        ↓
Smart Routing Core
        ↓
CompiledPolicy
        ↓
Mihomo rules
zapret hostlist / exclude / ipset / ipset-exclude
DNS nameserver-policy
diagnostics expectations
suppressed provider rules
```

`CompiledPolicy` is the source of effective truth. Mihomo, zapret, DNS, and diagnostics are render targets of the same policy.

---

## 2. Architectural Principles

### 2.1. One source of truth

All routing decisions must be made by Smart Routing Core. Avoid scattered route decisions in UI, commands, runtime, or config rendering code.

Allowed:

```text
settings -> policy input
subscription YAML -> provider policy input
runtime facts -> policy input
policy core -> CompiledPolicy
renderers -> Mihomo/zapret/DNS/diagnostics outputs
```

Not allowed:

```text
mihomo_config.rs independently decides Smart/VPN routing
runtime.rs manually patches MATCH rules
commands.rs has separate fallback routing logic
UI generates route-specific config snippets
zapret list generation parses rendered Mihomo rules
```

### 2.2. Subscription YAML is input, not authority

Provider subscription rules are parsed and respected as input, but they are not blindly copied into the final runtime configuration.

Examples:

```yaml
GEOSITE,youtube,📺 YouTube и Discord
```

In Smart, this becomes:

```yaml
GEOSITE,youtube,DIRECT
```

And zapret receives concrete domain entries such as:

```text
youtube.com
youtu.be
googlevideo.com
ytimg.com
youtubei.googleapis.com
youtube-nocookie.com
```

The original provider rule should be recorded as a suppressed provider rule with an explanation.

### 2.3. DIRECT is not one thing

Mihomo only sees `DIRECT`, but BPN must distinguish these semantic paths:

| Policy path | Mihomo action | zapret output | Diagnostics |
|---|---|---|---|
| `DirectSafe` | `DIRECT` | none/exclude | direct route, winws not required |
| `ZapretDirect` | `DIRECT` | hostlist/ipset | direct route, winws required |
| `VpnProxy { group }` | provider or managed proxy group | exclude/no-op | proxy group expected in chain |
| `Reject` | `REJECT` | none | blocked expected |

A process-only rule can be `DIRECT` for Mihomo, but it is not automatically zapret-covered. zapret coverage requires domains, CIDRs, ports, or Broad coverage logic.

### 2.4. VPN Only must be strict

VPN Only should not accidentally route external traffic directly.

Required invariants:

```text
VPN Only final rule is MATCH,<main_proxy_group> or MATCH,<managed_non_direct_group>.
VPN Only never emits MATCH,DIRECT.
VPN Only emits no zapret artifacts.
VPN Only suppresses external provider DIRECT rules unless Force DIRECT exists.
Private/LAN/safety DIRECT rules may remain.
REJECT rules may remain.
Provider proxy group rules may remain.
If the selected provider group contains DIRECT directly or transitively, use a managed group without DIRECT.
If no non-DIRECT proxy nodes are available, fail cleanly.
```

### 2.5. zapret artifacts must be concrete

zapret/winws list files must contain only representable concrete entries.

Valid examples:

```text
youtube.com
discord.gg
googlevideo.com
149.154.160.0/20
2001:db8::/32
```

Invalid examples:

```text
GEOSITE,youtube
GEOIP,ru
RULE-SET,openai
PROCESS-NAME,game.exe
DOMAIN-KEYWORD,sberbank
MATCH,DIRECT
REJECT
📺 YouTube и Discord
```

If a provider rule cannot be represented in zapret artifacts, policy core should preserve/route it where possible and add a diagnostics warning.

### 2.6. Agent runtime is authoritative

Privileged runtime work must remain behind the BPN agent service.

The GUI must not require administrator privileges. The agent owns:

- Mihomo process lifecycle;
- zapret/winws process lifecycle;
- runtime config writing;
- zapret list writing;
- preflight checks;
- fallback logic;
- runtime diagnostics;
- privileged cleanup.

### 2.7. Security and redaction are non-negotiable

Never commit, log, or display sensitive data without redaction:

- subscription URLs;
- provider YAML bodies;
- UUIDs from real nodes;
- proxy credentials;
- `authentication` entries;
- generated runtime YAML;
- controller secrets;
- tokens;
- raw server credentials.

Every diagnostics bundle must pass redaction.

---

## 3. Current Baseline

### 3.1. Implemented baseline

The current implementation has moved toward the intended architecture:

- public route modes are `smart` and `vpn_only`;
- old route modes deserialize through compatibility aliases;
- Smart Routing Core exists in `policy.rs`;
- Mihomo rules, zapret artifacts, DNS policy, diagnostics expectations, and suppressed rules are produced from `CompiledPolicy`;
- Smart final rule is `MATCH,DIRECT`;
- VPN Only final rule is `MATCH,<main_proxy_group>` or a managed no-DIRECT group;
- zapret artifacts reject Mihomo-only tokens;
- GEOSITE YouTube/Discord expands to concrete zapret domains;
- process-only rules do not falsely claim zapret coverage;
- Smart zapret failure recompiles fresh VPN Only policy;
- Broad is marked experimental;
- late winws death is reflected in runtime snapshot;
- `commands.rs` was reduced back to a minimal semantic diff after EOL correction.

### 3.2. Checks expected for this baseline

The following checks should remain green before every merge touching policy/runtime:

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo check --manifest-path apps/badvpn-client/src-tauri/Cargo.toml
cargo test -p badvpn-common
cargo test --workspace
npm --prefix apps/badvpn-client run check
npm --prefix apps/badvpn-client run build
git diff --check
```

The frontend build may fail in restricted sandboxes on Vite spawn `EPERM`. If it passes outside the sandbox or with appropriate escalation, document the environment limitation in the PR.

---

## 4. Work Model for Humans and AI Agents

### 4.1. How to choose tasks

Tasks should be picked in this order:

1. release blockers;
2. runtime safety;
3. policy correctness;
4. one-click UX;
5. startup speed;
6. diagnostics clarity;
7. UI polish;
8. advanced filters and future features.

Do not start with new filter categories or new modes if basic startup, fallback, and UI are not stable.

### 4.2. Required task format

Each task should define:

```text
Goal
Scope
Files likely touched
Out of scope
Acceptance criteria
Tests/checks to run
Manual QA, if required
Security/redaction notes
```

### 4.3. AI agent rules

AI agents working from this roadmap must:

- read `AGENTS.md` first;
- inspect relevant files before editing;
- avoid broad rewrites;
- keep route decisions in policy core;
- avoid secrets in diffs, fixtures, logs, and comments;
- run targeted tests and report skipped checks;
- include a clear validation summary;
- avoid changing public modes without explicit approval;
- avoid reintroducing legacy route names into UI.

---

## 5. Milestone A — Stabilize Smart Routing Core

### Goal

Make the policy-driven architecture stable enough for staging and beta QA.

### Priority

Immediate.

### Tasks

#### A1. Add and maintain policy invariant validation

Ensure `CompiledPolicy::validate_invariants()` is called in the production compile path before returning policy.

Acceptance criteria:

```text
[ ] Smart policy cannot be returned without MATCH,DIRECT.
[ ] VPN Only policy cannot be returned with MATCH,DIRECT.
[ ] VPN Only policy cannot return zapret artifacts.
[ ] zapret artifacts cannot contain Mihomo-only tokens.
[ ] invalid policy compile returns a clear error.
```

Suggested tests:

```text
compiled_policy_validate_smart_tail
compiled_policy_validate_vpn_only_tail
compiled_policy_rejects_zapret_artifact_geosite
compiled_policy_rejects_vpn_only_zapret_artifacts
```

#### A2. Expand sanitized provider YAML fixtures

Create sanitized fixtures without credentials or real node secrets.

Required fixtures:

```text
provider_full_ru_split.yaml
provider_group_with_direct.yaml
provider_nested_group_with_direct.yaml
provider_only_direct.yaml
provider_no_match.yaml
provider_no_groups_with_proxies.yaml
provider_complex_rules.yaml
provider_geosite_ai_youtube_discord.yaml
```

Acceptance criteria:

```text
[ ] All fixtures compile in Smart and VPN Only or fail with expected error.
[ ] Rendered YAML reparses through serde_yaml.
[ ] No fixture contains real credentials, UUIDs, subscription URLs, or real node details.
```

#### A3. Validate Smart behavior on fixture set

Acceptance criteria:

```text
[ ] YouTube/Discord provider proxy rules become DIRECT + concrete zapret hostlist.
[ ] AI/social/provider proxy rules remain proxy group routes.
[ ] Telegram/provider group rules remain proxy group routes.
[ ] RU/Yandex/VK/bank provider DIRECT remains DirectSafe in Smart.
[ ] Provider MATCH is replaced by MATCH,DIRECT.
[ ] Suppressed provider rules include override reasons.
```

#### A4. Validate VPN Only behavior on fixture set

Acceptance criteria:

```text
[ ] External provider DIRECT rules are suppressed.
[ ] private/LAN/safety DIRECT remains.
[ ] REJECT remains.
[ ] provider proxy group rules remain.
[ ] main group with DIRECT creates managed no-DIRECT group.
[ ] nested group with DIRECT is detected transitively.
[ ] provider-only DIRECT config fails cleanly if no proxy exists.
```

#### A5. Verify Smart fallback

Acceptance criteria:

```text
[ ] zapret start failure triggers fresh VpnOnly compile.
[ ] fallback config has no MATCH,DIRECT.
[ ] fallback config has no YouTube/Discord DIRECT rules.
[ ] fallback zapret artifacts are empty.
[ ] phase is DegradedVpnOnly only when user requested Smart.
[ ] user-requested VPN Only is Running, not degraded.
```

---

## 6. Milestone B — One-Click Connect MVP

### Goal

Make the app usable by a non-technical user through a single primary action.

### Product target

A user should be able to:

```text
1. Install BPN Client.
2. Paste/import subscription.
3. Press Connect.
4. Get Smart mode automatically.
5. See a simple status and a clear fallback/error if needed.
```

### Tasks

#### B1. Single connect button

Implement one primary button on the Home screen:

```text
Connect / Disconnect
```

The button should orchestrate:

```text
subscription validation
agent availability
component availability
policy compile
zapret start for Smart
Mihomo start
runtime verification
fallback if needed
```

Acceptance criteria:

```text
[ ] A new user does not need to visit advanced settings to connect.
[ ] Button state reflects idle/connecting/connected/disconnecting/error.
[ ] Smart fallback is shown as fallback, not as silent success.
[ ] User gets one concise error message with a Details option.
```

#### B2. First-run setup flow

Acceptance criteria:

```text
[ ] App detects missing subscription.
[ ] App explains what subscription is needed.
[ ] App validates imported profile.
[ ] App detects missing agent/components.
[ ] App offers install/repair action.
[ ] GUI does not require admin privileges.
```

#### B3. Startup progress UI

Show high-level progress:

```text
Preparing policy
Starting zapret
Starting Mihomo
Verifying connection
Connected
```

Acceptance criteria:

```text
[ ] User sees progress within 500 ms of pressing Connect.
[ ] Long operations have status text.
[ ] Failures show which stage failed.
```

#### B4. Basic/Advanced settings split

Basic settings should expose only:

```text
Mode: Smart / VPN Only
Server selection
Smart preset toggles
```

Advanced settings should contain:

```text
Force VPN
Force Zapret
Force DIRECT
Coverage Curated/Broad Experimental
DNS/TUN/ports/logs
```

Acceptance criteria:

```text
[ ] Legacy low-level options are hidden from normal users.
[ ] Advanced section is clearly marked.
[ ] Existing settings continue to deserialize.
```

---

## 7. Milestone C — Startup Speed and Runtime Performance

### Goal

Make connection startup feel fast and predictable.

### Current suspected issue

Mihomo or winws startup may feel slow. Do not optimize blindly; first instrument the startup path.

### Tasks

#### C1. Startup timeline instrumentation

Record timing for:

```text
subscription_fetch_ms
policy_compile_ms
runtime_facts_ms
mihomo_config_render_ms
zapret_list_write_ms
zapret_start_ms
mihomo_validate_ms
mihomo_start_ms
mihomo_ready_ms
diagnostics_ms
total_connect_ms
```

Acceptance criteria:

```text
[ ] Timeline appears in diagnostics.
[ ] Timeline is redacted and safe to export.
[ ] Timeline works for Smart, VPN Only, and fallback.
```

#### C2. Warm start optimization

Avoid unnecessary work if nothing changed.

Potential optimizations:

```text
cache compiled policy fingerprint
skip Mihomo validation if rendered config hash unchanged
avoid winws restart if zapret artifacts unchanged
avoid component checks on every connect
run diagnostics after connection instead of blocking connection
resolve proxy node IPs in parallel
preflight while app is idle
```

Acceptance targets:

```text
Cold start: <= 8-12 seconds on normal machine
Warm start: <= 2-5 seconds
Reconnect without config changes: <= 1-3 seconds
```

#### C3. Runtime reload strategy

Investigate when Mihomo can reload config safely instead of full restart.

Acceptance criteria:

```text
[ ] Reload used only when safe.
[ ] Full restart remains fallback.
[ ] Connections are closed/reopened intentionally where needed.
[ ] Diagnostics explain reload vs restart.
```

#### C4. winws startup tuning

Investigate slow winws startup causes:

```text
WinDivert conflicts
antivirus/EDR
stale winws processes
oversized hostlist/ipset
Broad coverage
service permissions
file write overhead
```

Acceptance criteria:

```text
[ ] Startup timeline identifies winws start time.
[ ] Stale process cleanup is reliable.
[ ] Failures have actionable messages.
```

---

## 8. Milestone D — UI/UX Redesign

### Goal

Make BPN Client feel like a product, not an internal networking tool.

### Main screens

Recommended navigation:

```text
Home
Servers
Routing
Diagnostics
Settings
```

### Home screen target

Home should show:

```text
BPN status
Connect/Disconnect button
Current mode
Selected server/group
Smart route summary
Runtime health cards
Fallback badge if active
```

Example:

```text
BPN Smart is active
YouTube / Discord: DIRECT + zapret
AI / social: VPN
RU services: DIRECT
Server: Auto
```

### Tasks

#### D1. Home screen redesign

Acceptance criteria:

```text
[ ] Primary action is visually dominant.
[ ] Mode is understandable without technical terms.
[ ] Runtime status is short and actionable.
[ ] Fallback state is visible.
```

#### D2. Routing page

Display:

```text
Smart presets
Force VPN
Force Zapret
Force DIRECT
Effective policy preview
Suppressed provider rules
Warnings
```

Acceptance criteria:

```text
[ ] User can understand why a domain routes through VPN/zapret/direct.
[ ] Advanced raw controls are not mixed into Home.
[ ] Empty states are clear.
```

#### D3. Diagnostics page

Display:

```text
startup timeline
policy summary
runtime components
active connections
expected vs actual route
logs link/export
```

Acceptance criteria:

```text
[ ] Diagnostics is useful for support.
[ ] Sensitive values are redacted.
[ ] Warnings are grouped and prioritized.
```

#### D4. Visual design pass

Improve:

```text
spacing
typography
cards
buttons
badges
error states
dark theme
loading states
```

Acceptance criteria:

```text
[ ] UI is consistent across pages.
[ ] Primary/secondary/destructive actions are visually distinct.
[ ] Long technical text is behind Details/Advanced.
```

---

## 9. Milestone E — Better Diagnostics and Explainability

### Goal

BPN should explain what it is doing.

### Tasks

#### E1. Route explain tool

Add a tool where user enters a target:

```text
youtube.com
chatgpt.com
discord.com
yandex.ru
```

The app returns:

```text
Path: ZapretDirect / VpnProxy / DirectSafe / Reject
Mihomo rule
zapret effect
DNS policy
source rule
suppressed provider rule, if any
```

Acceptance criteria:

```text
[ ] Works for domains.
[ ] Works for CIDRs where possible.
[ ] Explains provider override reason.
[ ] Shows if target is only partially representable.
```

#### E2. Expected vs actual connections

Use Mihomo connections API to compare live traffic against policy expectations.

Acceptance criteria:

```text
[ ] YouTube expected Direct+zapret, actual DIRECT.
[ ] AI expected proxy, actual proxy chain.
[ ] Unexpected DIRECT in VPN Only produces warning.
[ ] Missing winws in Smart produces warning.
```

#### E3. Suppressed provider rules viewer

Acceptance criteria:

```text
[ ] List suppressed rules.
[ ] Show reason and winning rule.
[ ] Allow copy/export without secrets.
```

#### E4. Diagnostics bundle

Export safe bundle:

```text
app version
agent version
mihomo version
zapret version
settings without secrets
policy summary
suppressed rules
warnings
startup timeline
component status
recent logs redacted
```

Acceptance criteria:

```text
[ ] No subscription URL.
[ ] No authentication entries.
[ ] No UUIDs or raw node credentials.
[ ] Bundle is useful for support.
```

---

## 10. Milestone F — Smart Filters v2

### Goal

Improve filtering logic only after core UX and runtime are stable.

### Do not start here before milestones B/C/D are usable.

### Tasks

#### F1. Preset categories

Maintain curated presets:

```text
YouTube/Discord zapret
AI VPN
Social VPN
Telegram provider VPN
Games zapret
News VPN
Developer tools VPN/direct decisions
```

Acceptance criteria:

```text
[ ] Each preset compiles through policy core.
[ ] Each preset has tests.
[ ] Each preset has diagnostics explanation.
```

#### F2. Confidence model

Each policy rule can carry:

```text
source
priority
confidence
reason
```

Acceptance criteria:

```text
[ ] Diagnostics can explain uncertain/opaque rules.
[ ] User can distinguish provider/preset/user rules.
```

#### F3. Provider complex rule support

Handle more Mihomo rule grammar:

```text
RULE-SET
AND
OR
NETWORK
DST-PORT
SRC-IP-CIDR
PROCESS-PATH where supported
```

Acceptance criteria:

```text
[ ] Unknown proxy rules can be preserved safely.
[ ] Unknown external DIRECT in VPN Only is suppressed safely.
[ ] Complex rules do not enter zapret artifacts directly.
```

#### F4. Rule-provider support

Only after core stabilizes.

Requirements:

```text
local cache
hash verification or explicit unpinned warning
policy-core import
conflict diagnostics
no blind remote include
```

#### F5. privWL integration

Optional and explicit opt-in.

Acceptance criteria:

```text
[ ] Disabled by default.
[ ] Downloaded/cached safely.
[ ] Conflicts with Smart presets shown.
[ ] No silent overrides.
```

---

## 11. Milestone G — Game Support

### Goal

Support games without pretending process-only rules are enough.

### Rules

```text
process_names -> Mihomo DIRECT only
domains       -> Mihomo DIRECT + zapret hostlist
cidrs         -> Mihomo DIRECT + zapret ipset
ports         -> winws/Broad/Curated coverage logic
```

### Tasks

#### G1. Game profile model

Acceptance criteria:

```text
[ ] Profiles distinguish process/domain/CIDR/port rules.
[ ] Diagnostics warns about process-only coverage.
[ ] Profiles compile through policy core.
```

#### G2. Game diagnostics

Acceptance criteria:

```text
[ ] Shows which game rules are active.
[ ] Shows whether zapret actually covers game targets.
[ ] Shows risk level for Broad/UDP manipulation.
```

#### G3. Learned game profiles

Acceptance criteria:

```text
[ ] App can observe connections and suggest domains/CIDRs.
[ ] User must approve suggestions.
[ ] Learned data is local and export-safe.
```

#### G4. Anti-cheat compatibility

Acceptance criteria:

```text
[ ] Warn about Broad/WinDivert risks.
[ ] Prefer Curated for anti-cheat-sensitive games.
[ ] Document known safe/unsafe profiles.
```

---

## 12. Milestone H — Runtime Robustness

### Goal

Keep BPN connected and understandable under Windows edge cases.

### Tasks

#### H1. Runtime state machine

Use explicit states:

```text
Idle
PreparingPolicy
WritingConfig
StartingZapret
StartingMihomo
Verifying
Running
DegradedVpnOnly
Stopping
Error
```

Acceptance criteria:

```text
[ ] UI maps every state to clear text.
[ ] Logs include state transitions.
[ ] Errors include stage.
```

#### H2. Watchdogs

Acceptance criteria:

```text
[ ] Detect Mihomo controller death.
[ ] Detect winws death in Smart.
[ ] Detect stale TUN state.
[ ] Detect external VPN/zapret conflicts.
```

Future behavior:

```text
Smart winws death -> optional auto fresh VPN Only fallback.
Smart recovery -> optional restore Smart after zapret returns.
```

#### H3. Component management

Acceptance criteria:

```text
[ ] Component version shown.
[ ] Repair action exists.
[ ] Update action exists.
[ ] Rollback path exists.
[ ] Component verification is documented.
```

#### H4. Logs and redaction

Acceptance criteria:

```text
[ ] Separate logs for app/agent/mihomo/zapret/policy.
[ ] Logs are redacted.
[ ] Log paths visible in diagnostics.
[ ] No full subscription YAML in logs.
```

---

## 13. Milestone I — Branding and Repository Cleanup

### Goal

Move public identity from legacy BadVPN naming to BPN while preserving migrations.

### Current expected legacy names

The repository may still contain:

```text
crates/badvpn-common
crates/badvpn-agent
apps/badvpn-client
BadVpn
BadVPN
ProgramData\BadVpn
```

### Target names

```text
crates/bpn-common
crates/bpn-agent
apps/bpn-client
BPN
ProgramData\BPN
```

### Tasks

#### I1. Public naming cleanup

Acceptance criteria:

```text
[ ] UI says BPN.
[ ] README/docs say BPN Client.
[ ] Public binary/app names say BPN.
[ ] Internal legacy names only remain where migration requires them.
```

#### I2. Crate and directory rename

Do this as a separate PR. Do not mix with routing or runtime changes.

Acceptance criteria:

```text
[ ] Workspace builds after rename.
[ ] imports updated.
[ ] package metadata updated.
[ ] old paths migrated or documented.
```

#### I3. Data directory migration

Acceptance criteria:

```text
[ ] Existing ProgramData\BadVpn settings migrate to ProgramData\BPN.
[ ] Migration is idempotent.
[ ] No credentials lost.
[ ] Logs explain migration without leaking secrets.
```

---

## 14. Milestone J — Release and Update Pipeline

### Goal

Prepare BPN Client for beta and stable releases.

### Tasks

#### J1. GitHub Actions checks

Expected CI:

```text
cargo fmt
cargo check
cargo test
frontend check
frontend build
secret scan
artifact build
```

#### J2. Windows installer

Acceptance criteria:

```text
[ ] Installs app.
[ ] Installs/repairs agent service.
[ ] Does not require GUI as admin.
[ ] Can uninstall cleanly.
[ ] Leaves user data only when requested.
```

#### J3. Auto-update

Acceptance criteria:

```text
[ ] App update channel exists.
[ ] Runtime component update exists.
[ ] Rollback path exists.
[ ] Update errors are understandable.
```

#### J4. Signing and integrity

Acceptance criteria:

```text
[ ] Release artifacts are signed where possible.
[ ] Downloaded components have integrity metadata.
[ ] Component source/version visible.
```

#### J5. Release notes

Every release should include:

```text
new features
routing changes
known limitations
QA summary
checks run
security notes
```

---

## 15. Security Roadmap

### 15.1. Redaction system

Create a central redactor used by logs, diagnostics, UI errors, and support bundles.

Acceptance criteria:

```text
[ ] subscription URLs redacted.
[ ] UUIDs redacted.
[ ] authentication entries redacted.
[ ] controller secrets redacted.
[ ] node server details redacted where appropriate.
[ ] tests cover redaction.
```

### 15.2. Least privilege

Acceptance criteria:

```text
[ ] GUI never requires admin.
[ ] privileged actions go through agent.
[ ] IPC is local and authenticated/controlled.
[ ] service install/update actions are explicit.
```

### 15.3. Secret scans

Acceptance criteria:

```text
[ ] CI scans for subscription URLs.
[ ] CI scans for authentication entries.
[ ] CI scans for UUID-like node secrets.
[ ] CI scans generated configs if accidentally tracked.
```

---

## 16. Documentation Roadmap

### 16.1. User docs

Required pages:

```text
What is Smart mode?
What is VPN Only?
Why YouTube/Discord are DIRECT in Smart?
Why VPN Only suppresses provider DIRECT?
What are Force VPN / Force Zapret / Force DIRECT?
Why Broad is experimental?
How to read diagnostics?
How to export support bundle?
```

### 16.2. Developer docs

Required pages:

```text
Smart Routing Core architecture
CompiledPolicy invariants
Policy priority model
How provider YAML is parsed
How zapret artifacts are generated
How fallback works
How to add a preset
How to add a rule parser
How to safely handle secrets
```

### 16.3. Support docs

Required pages:

```text
Common connection failures
Mihomo config validation errors
zapret/winws errors
external VPN conflicts
DNS leak suspicion
slow startup troubleshooting
Broad compatibility warnings
```

---

## 17. Testing and QA Standards

### 17.1. Required automated checks before merge

For policy/runtime/UI changes:

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
npm --prefix apps/badvpn-client run check
npm --prefix apps/badvpn-client run build
git diff --check
```

If any check is skipped, the PR must explain why.

### 17.2. Manual Windows QA matrix

| Scenario | Smart expected | VPN Only expected |
|---|---|---|
| YouTube | DIRECT + zapret | proxy group |
| Discord | DIRECT + zapret | proxy group |
| ChatGPT/OpenAI | proxy group | proxy group |
| Telegram | provider proxy group | provider proxy group |
| Yandex/VK/RU | DIRECT safe | VPN unless Force DIRECT |
| Bank domains | DIRECT safe | VPN unless Force DIRECT |
| winws killed | fallback/degraded | not applicable |
| provider group has DIRECT | Smart unaffected where direct allowed | managed no-DIRECT group |
| no non-DIRECT proxies | error if VPN needed | clean error |
| Broad enabled | warning, experimental | normally not needed |

### 17.3. QA artifacts

QA reports should include:

```text
app version
agent version
Windows version
subscription fixture/profile type without secrets
mode tested
checks performed
observed routing chains
failures and logs redacted
```

---

## 18. Future Backlog

These are future items. Do not start before the MVP is stable unless explicitly approved.

### 18.1. External rule providers

- local cache;
- hash verification or explicit unpinned warning;
- policy-core import;
- conflict diagnostics;
- no blind remote include.

### 18.2. privWL opt-in

- disabled by default;
- explicit opt-in;
- cached locally;
- diagnostics for conflicts;
- safe failure mode.

### 18.3. Policy editor

- read-only effective policy first;
- then editable local overrides;
- avoid exposing raw Mihomo grammar to normal users.

### 18.4. Browser proxy mode

Optional future feature for users who do not want TUN.

Limitations must be clear:

```text
Does not cover all apps.
Does not reliably cover games/UDP.
May allow DNS/application bypasses.
```

### 18.5. Auto-learning

- learn game/domain candidates;
- suggest, never auto-apply;
- keep data local;
- include risk warnings.

### 18.6. Multi-subscription support

- multiple profiles;
- per-profile proxy selections;
- per-profile policy summary;
- safe switching without stale config.

---

## 19. Do-Not-Do List

Until beta is stable, do not:

- add a third public routing mode;
- reintroduce SmartHybrid/ZapretFirst/VpnAll into UI;
- copy provider rules blindly into final runtime config;
- use Broad as default;
- add external rule-provider auto-download;
- log raw subscriptions;
- require GUI admin privileges;
- rewrite `commands.rs` broadly;
- add aggressive blocklists without diagnostics;
- silently suppress provider rules without `suppressed_rules`;
- generate zapret artifacts from rendered Mihomo rules;
- treat process-only rules as zapret coverage;
- ship VPN Only that can select DIRECT through proxy groups.

---

## 20. Suggested Near-Term Task Queue

Recommended immediate order:

1. **Windows QA for Smart/VPN Only/fallback**
   - Verify real runtime behavior with current implementation.

2. **Startup timeline**
   - Measure where slow startup happens.

3. **One-click Connect UI**
   - Make the app usable without opening advanced settings.

4. **Home screen redesign**
   - Show Smart status and route summary.

5. **Basic/Advanced settings split**
   - Hide legacy and low-level runtime settings.

6. **Policy viewer / Route explain**
   - Make routing decisions understandable.

7. **Runtime optimization**
   - Use timeline data to reduce warm start time.

8. **BPN branding cleanup**
   - Rename public UI/docs first, internal crates later.

9. **Diagnostics bundle**
   - Support-friendly, redacted export.

10. **Beta release pipeline**
    - Installer, updates, QA gates, release notes.

---

## 21. Success Criteria

The project is moving in the right direction when:

```text
A user can connect with one button.
Smart mode reliably keeps YouTube/Discord/games low-latency through zapret.
VPN targets reliably use proxy groups.
VPN Only never leaks external DIRECT through provider rules or groups.
Fallback is safe and understandable.
Startup is measured and optimized.
UI explains what is happening.
Diagnostics can support real users without leaking secrets.
All route decisions stay in Smart Routing Core.
```

The final product should feel simple:

```text
Press Connect.
BPN chooses the right path.
If something breaks, BPN explains it and falls back safely.
```
