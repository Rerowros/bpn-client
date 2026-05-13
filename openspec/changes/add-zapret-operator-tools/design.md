# Design: Zapret Operator Tools

## Selection Rules

Из функций Clash Verge Rev и Koala Clash включаем только те, которые помогают BPN Smart routing и zapret:

- route/debug visibility;
- local rule override;
- app/process/game routing;
- runtime logs/config/rules;
- geodata/list resources;
- diagnostics/export;
- safe profile import.

Не включаем в этот change функции, которые превращают BPN в полный generic Clash client без прямой связи с zapret: full scripting IDE, arbitrary provider editing by default, macOS/Linux package flows, broad sysproxy management, UI theming marketplace.

## Product Model

### Simple Mode

Обычный пользователь видит:

- protected status;
- current node;
- Smart/VPN Only;
- local app rule list;
- zapret health;
- quick diagnostics.

### Advanced Mode

Advanced unlock показывает:

- runtime rules;
- resource manager;
- live logs;
- runtime YAML/diff;
- DNS/sniffer controls;
- import/export diagnostics and backup.

Advanced mode must explain risk before enabling write operations.

## Feature Area 1: Local App & Rule Overrides

Purpose:

- заменить ручное редактирование YAML/BAT на понятный local override layer;
- сохранить правила пользователя после subscription refresh;
- дать сценарий "выбрать `.exe` и отправить через DIRECT/VPN/zapret".

Data model:

- `local_overrides.version`
- `rules[]`
  - `id`
  - `enabled`
  - `title`
  - `path`: `direct | vpn | zapret`
  - `target_kind`: `domain | cidr | process | app | tcp_port | udp_port`
  - `value`
  - `executable_path`
  - `process_name`
  - `source`: `user | migrated_force_list | learned_game | preset`
  - `created_at`
  - `updated_at`
  - `last_applied_at`
  - `last_policy_trace_id`

Compiler adapter:

- app/process targets map to `PROCESS-NAME` until path-specific enforcement is implemented.
- domain maps to `DOMAIN-SUFFIX`.
- CIDR maps to `IP-CIDR`/`IP-CIDR6`.
- port maps to TCP/UDP policy target where supported.
- direct/vpn/zapret paths map to current `PolicyPath`.

## Feature Area 2: Process-Aware Connections

Current `connections` view shows flows, but not enough process-oriented debugging. Add:

- grouping by process;
- process executable name and path if runtime can provide it;
- route path and rule source;
- "Create override from this process/domain" action;
- close process group connections;
- clear closed connections by process/path.

This makes zapret/app bypass debuggable.

## Feature Area 3: Runtime Rules and Trace

Current policy viewer is read-only and useful, but needs operator filters:

- search by domain/process/CIDR/rule text;
- filter by path `VPN | zapret | DIRECT | blocked`;
- filter by source `provider | preset | local override | safety`;
- show why rule was suppressed;
- show trace: provider rule -> BPN overlay -> final Mihomo rule -> zapret artifact.

No direct provider rewrite in first slice.

Provider scope:

- show `rule-providers` and `proxy-providers` as read-only sources;
- show provider update status if available;
- allow manual provider update only after validation/rollback design exists;
- show which provider rules/nodes are consumed by BPN Smart/zapret overlay;
- do not allow direct provider content editing in the first slice.

## Feature Area 4: Live Logs

Add a log view for:

- `badvpn-agent`;
- Mihomo;
- winws/zapret;
- updater/resource manager.

Controls:

- pause/resume;
- auto-scroll;
- clear view;
- level/source filters;
- copy selected redacted lines.

Logs must be redacted before rendering.

## Feature Area 5: Runtime YAML and Diff

Add read-only viewers:

- source subscription profile;
- generated runtime YAML;
- diff source -> runtime.

Diff focus:

- rules changed by BPN overlay;
- suppressed provider direct rules;
- local overrides;
- DNS/sniffer/TUN changes;
- zapret hostlist/ipset artifacts.

Write editing stays out of first slice.

## Feature Area 6: Zapret Health and Media Checks

Add user-facing checks:

- YouTube;
- Discord voice/CDN;
- ChatGPT/OpenAI;
- Claude;
- Gemini;
- selected custom domain;
- zapret process/rule/list readiness.

Each check should show:

- route path used;
- DNS answer class if available;
- HTTP/TLS probe result if safe;
- whether zapret list contains expected target;
- recovery action.

## Feature Area 7: Game/App Bypass Profiles

Runtime already has learned/known game profile concepts. UI should expose:

- known profiles;
- detected running candidates;
- learned profiles;
- manual profile creation from `.exe`;
- domains/CIDRs/TCP/UDP ports per profile;
- risk level and filter mode;
- enable/disable per profile;
- preview generated rules.

## Feature Area 8: Resources

Add resource manager for:

- geosite;
- geoip;
- mmdb;
- ASN database if used;
- Flowseal/zapret lists;
- BPN curated rule lists.

Resource manager must show:

- current version/date;
- source;
- last update;
- update available;
- verification status;
- rollback availability.

## Feature Area 9: Profile Import

Add import sources relevant to zapret testing/recovery:

- local file import YAML/JSON/TXT;
- drag-and-drop import;
- `bpn://` deep link import.

Local imports must not bypass validation.

Profile lifecycle:

- add fetch options for user-agent, proxy mode and timeout;
- add refresh all subscriptions;
- respect provider update interval metadata;
- allow editing local display name and notes;
- classify provider/HWID-limit errors without exposing raw subscription URL;
- failed refresh must preserve last working profile.

## Feature Area 9.5: TUN Recovery

Smart routing depends on TUN stability, so advanced TUN controls should be explicit:

- MTU;
- DNS hijack;
- excluded routes/CIDRs;
- route/firewall reset recovery through `badvpn-agent`;
- last-known-good rollback if generated config validation fails.

## Feature Area 10: Backup and Support

Backup:

- settings;
- subscription profile metadata;
- local overrides;
- selected proxies;
- game profiles.

Support bundle:

- diagnostics summary;
- redacted logs;
- policy summary;
- runtime readiness;
- resource versions;
- local override summary without secrets.
- system info;
- app uptime;
- service status;
- admin/elevation status;
- redacted app/runtime/log directory paths.

File retirement:

- no product flow should destructively delete user/runtime evidence by default;
- prefer `.del` rename, quarantine, backup or explicit rollback point;
- any truly destructive cleanup needs a separate approved OpenSpec change.

## Validation Matrix

Every implementation slice must define:

- TypeScript check/build.
- Rust unit tests if policy/runtime changes.
- Tauri command tests if settings/import/update changes.
- Browser QA for UI changes.
- Manual Windows QA for service/runtime/zapret changes.
