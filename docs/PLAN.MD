# BadVPN Development Roadmap

Дата: 2026-04-30

## 1. Цель проекта

BadVPN должен стать единым Windows-клиентом для работы с ограничениями сети в РФ на связке:

- **Mihomo** — TUN, DNS, proxy-groups, маршрутизация, connections API;
- **zapret / winws** — DPI bypass для прямого трафика;
- **BadVPN Agent** — привилегированный runtime-сервис, который управляет Mihomo, zapret, конфигами, диагностикой и fallback-логикой;
- **Tauri UI** — пользовательский интерфейс без необходимости запускать GUI от администратора.

Публичная модель режимов должна оставаться простой:

1. **Smart** — умный режим для РФ: YouTube, Discord и игры идут напрямую через zapret; AI, соцсети, Telegram и provider proxy rules идут через VPN; остальное по умолчанию DIRECT.
2. **VPN Only** — весь внешний трафик через VPN; zapret выключен.

Главная архитектурная основа проекта — **Smart Routing Core**. Подписка не копируется вслепую, а парсится как входные данные. `CompiledPolicy` становится единственным источником effective routing policy и компилирует:

- Mihomo rules;
- zapret hostlist;
- zapret hostlist-exclude;
- zapret ipset;
- zapret ipset-exclude;
- DNS nameserver-policy;
- diagnostics expectations;
- suppressed provider rules.

---

## 2. Архитектурные принципы

### 2.1. Один источник истины

Нельзя допускать ситуацию, где Mihomo, zapret, DNS и diagnostics принимают разные решения. Любая маршрутизация должна проходить через policy core.

Правильный поток:

```text
Subscription YAML
+ BadVPN presets
+ user overrides
+ game profiles
+ runtime facts
+ selected proxy groups
        ↓
CompiledPolicy
        ↓
Mihomo + zapret + DNS + diagnostics
```

### 2.2. Два публичных режима

Не добавлять третий режим. Старые значения использовать только как compatibility aliases:

```text
smart_hybrid, zapret_first -> smart
vpn_all, dpi_only, manual, unknown -> vpn_only
```

### 2.3. Разделение DIRECT-семантики

Для Mihomo `DirectSafe` и `ZapretDirect` оба рендерятся как `DIRECT`, но для runtime это разные пути:

| Policy path | Mihomo | zapret | diagnostics |
|---|---|---|---|
| `DirectSafe` | `DIRECT` | не нужен | DIRECT без требования winws |
| `ZapretDirect` | `DIRECT` | hostlist/ipset | DIRECT + winws active |
| `VpnProxy` | proxy group | exclude/no-op | chain содержит VPN/proxy group |
| `Reject` | `REJECT` | no-op | blocked expected |

### 2.4. Provider YAML — input, не authority

Provider subscription rules важны, но не абсолютны. BadVPN может переопределять их, если они конфликтуют со Smart policy.

Пример:

```yaml
GEOSITE,youtube,📺 YouTube и Discord
```

В Smart это должно стать:

```yaml
GEOSITE,youtube,DIRECT
```

А в zapret hostlist должны попасть concrete domains:

```text
youtube.com
youtu.be
googlevideo.com
ytimg.com
youtubei.googleapis.com
```

В diagnostics надо сохранять suppressed provider rule и причину override.

### 2.5. Безопасный VPN Only

VPN Only не должен случайно обходить VPN через provider `DIRECT` rules или через proxy group, содержащую `DIRECT`.

Требования:

- external provider `DIRECT` подавляются, кроме explicit Force DIRECT;
- private/LAN/safety `DIRECT` сохраняются;
- если main proxy group содержит `DIRECT` напрямую или транзитивно, создаётся managed group `__BADVPN_VPN_ONLY__` без `DIRECT`;
- если non-DIRECT proxy nodes отсутствуют, runtime должен fail cleanly.

---

## 3. Текущее состояние

### 3.1. Реализовано

- Добавлен unified `policy.rs`.
- Публичные режимы сведены к `smart` и `vpn_only`.
- Старые route mode значения мигрируют через serde aliases.
- Mihomo rules, zapret artifacts, DNS policy и diagnostics строятся из `CompiledPolicy`.
- Smart рендерит `MATCH,DIRECT`.
- VPN Only рендерит `MATCH,<main_proxy_group>` или managed group без `DIRECT`.
- YouTube/Discord provider proxy rules в Smart переопределяются в `ZapretDirect`.
- zapret artifacts валидируются и не принимают `GEOSITE`, `GEOIP`, `RULE-SET`, `PROCESS-NAME`, `DOMAIN-KEYWORD`, `MATCH`, `DIRECT`, `REJECT` и complex rule tokens.
- GEOSITE YouTube/Discord разворачиваются в curated concrete domain hostlist.
- Process-only Force Zapret/Game rules не считаются zapret-covered.
- Smart fallback делает fresh compile в VPN Only, а не patch готового YAML.
- Late winws death отображается в agent snapshot.
- Broad помечен как Experimental.
- `commands.rs` semantic diff уменьшен до минимального объёма.

### 3.2. Пройденные проверки

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo check --manifest-path apps/badvpn-client/src-tauri/Cargo.toml`
- `cargo test -p badvpn-common`
- `cargo test --workspace`
- `npm --prefix apps/badvpn-client run check`
- `npm --prefix apps/badvpn-client run build` после escalation
- `git diff --check`
- secret/subscription scan

### 3.3. Не считать blocker

`npm --prefix apps/badvpn-client run build` в sandbox может падать на Vite spawn `EPERM`. Если build проходит вне sandbox/escalated, это environment limitation, не code blocker.

---

## 4. Ближайший этап: merge / staging

### 4.1. Цель

Зафиксировать Smart Routing Core как базовую архитектуру проекта и перевести дальнейшую разработку на policy-driven модель.

### 4.2. Перед merge

Проверить вручную в diff:

- `CompiledPolicy::validate_invariants()` вызывается в production compile path.
- `policy.rs` не рендерит zapret artifacts из готовых Mihomo rules.
- `mihomo_config.rs` заменяет `rules:` на `compiled_policy.mihomo_rules`.
- `runtime.rs` при Smart zapret failure делает fresh VPN Only compile.
- `commands.rs` изменён только семантически необходимыми строками.
- В diff нет subscription URL, credentials, real node UUID, server credentials, authentication entries, generated configs.

### 4.3. Acceptance criteria для merge

```text
[ ] UI показывает только Smart и VPN Only.
[ ] Старые route modes читаются и мигрируют.
[ ] Smart emits MATCH,DIRECT.
[ ] VPN Only emits MATCH,<safe_proxy_group>.
[ ] VPN Only не оставляет external provider DIRECT.
[ ] VPN Only не использует group с DIRECT напрямую или транзитивно.
[ ] Smart пишет concrete zapret hostlist для YouTube/Discord.
[ ] zapret artifacts не содержат Mihomo-only tokens.
[ ] Smart fallback recompiles VpnOnly policy.
[ ] diagnostics показывает suppressed provider rules.
[ ] commands.rs manual review completed.
```

---

## 5. Windows QA после merge в staging

### 5.1. Smart mode smoke

Проверить:

```text
Mihomo: running
zapret/winws: running
final rule: MATCH,DIRECT
YouTube: DIRECT + winws active
Discord: DIRECT + winws active
AI/OpenAI/Claude: proxy group
Telegram: provider group, например "Выбор сервера"
Yandex/VK/RU/banks: DIRECT safe
```

Проверить generated YAML:

```yaml
GEOSITE,youtube,DIRECT
DOMAIN-SUFFIX,googlevideo.com,DIRECT
GEOSITE,discord,DIRECT
GEOSITE,openai,🤖 AI
GEOSITE,telegram,Выбор сервера
MATCH,DIRECT
```

Проверить zapret hostlist:

```text
youtube.com
youtu.be
googlevideo.com
ytimg.com
discord.com
discord.gg
discordcdn.com
```

Не должно быть:

```text
GEOSITE,youtube
GEOSITE,discord
RULE-SET
PROCESS-NAME
DIRECT
REJECT
```

### 5.2. VPN Only smoke

Проверить:

```text
zapret/winws: stopped
zapret artifacts: empty
final rule: MATCH,<main_proxy_group> или MATCH,__BADVPN_VPN_ONLY__
external provider DIRECT: suppressed
private/LAN DIRECT: preserved
REJECT: preserved
provider proxy group rules: preserved
```

Не должно быть:

```yaml
MATCH,DIRECT
GEOSITE,youtube,DIRECT
GEOSITE,discord,DIRECT
DOMAIN-SUFFIX,ru,DIRECT
GEOIP,ru,DIRECT,no-resolve
GEOSITE,yandex,DIRECT
```

### 5.3. Smart fallback

Сценарий:

```powershell
taskkill /IM winws.exe /F
```

Ожидание:

```text
effective mode: VpnOnly fallback
phase: DegradedVpnOnly, только если пользователь хотел Smart
fallback config: no MATCH,DIRECT
fallback config: no YouTube/Discord DIRECT
zapret artifacts: empty
diagnostics: Smart requires zapret, but winws is not running
```

### 5.4. Managed VPN group

Проверить provider group с `DIRECT` напрямую и через вложенную group.

Ожидание:

```yaml
proxy-groups:
  - name: __BADVPN_VPN_ONLY__
    proxies:
      - <non-DIRECT safe leaf proxies>
rules:
  - MATCH,__BADVPN_VPN_ONLY__
```

Если non-DIRECT proxies отсутствуют:

```text
VPN Only cannot start: no non-DIRECT proxy nodes are available in subscription.
```

### 5.5. Broad Experimental

Проверить:

- UI label: `Broad (Experimental)`;
- runtime diagnostics содержит warning;
- GEOSITE/RULE-SET, которые нельзя представить в zapret exclude, дают warning;
- Curated остаётся default.

---

## 6. Release 0.1 Beta

### 6.1. Scope

Beta должна быть focused release вокруг Smart Routing Core.

Включить:

- Smart / VPN Only;
- subscription import/refresh;
- proxy selection persistence;
- agent runtime;
- Smart fallback;
- diagnostics expectations;
- suppressed provider rules display;
- basic connections view;
- runtime update/repair path.

Не включать в beta:

- external rule-providers;
- privWL pinning;
- автоматический broad tuning;
- сложный editor provider rules;
- новые публичные режимы;
- aggressive built-in blocklists.

### 6.2. Release gates

```text
[ ] Windows QA Smart passed.
[ ] Windows QA VPN Only passed.
[ ] Fallback QA passed.
[ ] Subscription refresh QA passed.
[ ] Agent service install/remove QA passed.
[ ] Runtime component update QA passed.
[ ] No admin GUI requirement.
[ ] No secrets in build artifacts/logs.
[ ] Crash-free smoke session >= 30 minutes.
```

### 6.3. Known limitations to document

- Broad coverage experimental.
- Process-only game rules do not guarantee zapret coverage.
- Some provider complex rules may be preserved as opaque proxy rules or suppressed with diagnostics.
- HTTP probe status is advisory; route chain is authoritative.

---

## 7. Diagnostics roadmap

### 7.1. Diagnostics v1

Цель: объяснять пользователю не только «работает/не работает», а почему route выбран именно так.

Добавить UI-блок:

```text
Policy summary:
- mode
- main proxy group
- final rule
- zapret status
- suppressed provider rules count
- warnings count
```

Для target diagnostics:

```text
youtube.com:
  expected: ZapretDirect
  Mihomo: DIRECT
  zapret: required
  source: BadVPN preset
  provider rule suppressed: GEOSITE,youtube,📺 YouTube и Discord
```

```text
chatgpt.com:
  expected: VpnProxy
  group: 🤖 AI or main proxy group
  DNS policy: trusted DoH
```

### 7.2. Diagnostics v2

- Compare expected policy vs Mihomo `/connections` real chain.
- Detect DNS leak suspicion.
- Detect winws down during Smart.
- Detect selected proxy dead.
- Detect proxy group resolves to `DIRECT` unexpectedly.
- Show active generated config path and policy id.

### 7.3. Diagnostics v3

- Export diagnostic bundle.
- Redact credentials automatically.
- Include policy summary, logs, version info, selected runtime paths.
- One-click support report.

---

## 8. zapret / winws roadmap

### 8.1. Curated coverage stabilization

Curated remains default.

Tasks:

- Maintain curated hostlist for YouTube/Discord.
- Keep game domains/CIDRs mapped to zapret artifacts.
- Ensure proxy node IPs are in ipset-exclude.
- Ensure VPN proxy targets are excluded from Broad/Curated where applicable.
- Validate winws command generation in agent runtime.

### 8.2. Broad coverage hardening

Broad stays Experimental until:

```text
[ ] hostlist-exclude works for all concrete VpnProxy domains.
[ ] ipset-exclude includes private CIDRs and proxy node IPs.
[ ] warnings shown for GEOSITE/RULE-SET that cannot be represented.
[ ] fallback to Curated or VPN Only is tested.
[ ] banks/RU services/game launchers QA passed.
```

### 8.3. Game support

Game profiles must distinguish:

```text
process_names -> Mihomo DIRECT only
domains       -> Mihomo DIRECT + zapret hostlist
cidrs         -> Mihomo DIRECT + zapret ipset
ports         -> winws profile/args
```

Future tasks:

- Game profile editor.
- Learned profiles from observed connections.
- Per-game diagnostics.
- Anti-cheat risk warnings.
- Broad/Curated recommendation per game.

---

## 9. Mihomo routing roadmap

### 9.1. Policy parser improvements

Current focus should stay on safe subset:

- `DOMAIN`;
- `DOMAIN-SUFFIX`;
- `DOMAIN-KEYWORD`;
- `GEOSITE`;
- `GEOIP`;
- `IP-CIDR` / `IP-CIDR6`;
- `PROCESS-NAME`;
- `RULE-SET` as opaque provider rule;
- `MATCH` / `FINAL`.

Next:

- better `AND` / `OR` handling;
- rule-provider support as opaque first, then parsed;
- provider rule conflict preview;
- generated rule order audit.

### 9.2. Proxy group management

Tasks:

- Display main proxy group chosen by policy core.
- Display managed group `__BADVPN_VPN_ONLY__` if created.
- Warn if provider group topology is unsafe.
- Preserve user selected proxy across subscription refresh.
- Avoid selecting dead proxies in fallback.

### 9.3. Config rendering safety

Every rendered YAML should:

- parse back through `serde_yaml`;
- pass `mihomo -t` validation where available;
- not contain credentials in logs;
- keep provider sections unless managed overlay intentionally changes them.

---

## 10. DNS roadmap

### 10.1. Smart DNS

Smart should keep:

```yaml
enhanced-mode: fake-ip
respect-rules: true
proxy-server-nameserver: trusted DoH
```

Add managed policy for VPN targets:

```text
AI/social/VpnProxy domains -> trusted DoH
BadVPN own domains -> trusted DoH
```

### 10.2. VPN Only DNS

VPN Only should not inherit provider DNS policies that imply local/direct split routing.

Tasks:

- Keep trusted default DoH.
- Keep proxy-server-nameserver.
- Remove provider external nameserver-policy unless explicitly safe.
- Add diagnostics if DNS policy was suppressed.

### 10.3. DNS diagnostics

- Check `respect-rules`.
- Check DNS hijack active.
- Check fake-ip mode.
- Warn if external DoH apps bypass system DNS.
- Show expected DNS policy per target.

---

## 11. UI/UX roadmap

### 11.1. Main UX

Keep public UI simple:

```text
Smart
VPN Only
```

Smart explanation:

```text
Умный режим для РФ: YouTube, Discord и игры идут напрямую через zapret для низкого ping. AI, соцсети и сайты из VPN-правил идут через VPN. Остальное — напрямую.
```

VPN Only explanation:

```text
Весь внешний трафик идёт через VPN. zapret выключен.
```

### 11.2. Advanced routing controls

Keep in collapsible advanced block:

- Force VPN;
- Force Zapret;
- Force DIRECT;
- Smart preset toggles;
- Coverage Curated/Broad Experimental.

### 11.3. Policy viewer

Add read-only page:

```text
Effective policy
- Target
- Path
- Source
- Rendered Mihomo rule
- zapret effect
- DNS effect
- Suppressed provider rule, if any
```

### 11.4. Error UX

Clear messages for:

- no non-DIRECT proxies available;
- winws missing;
- external VPN conflict;
- external zapret conflict;
- Mihomo config validation failure;
- subscription has no usable proxy group;
- Broad incomplete exclude coverage.

---

## 12. Agent/runtime roadmap

### 12.1. Agent authority

The agent runtime should remain authoritative for privileged work.

Rules:

- GUI must not require admin.
- Service owns winws/Mihomo process lifecycle.
- Service writes runtime configs/lists.
- Service performs fallback.
- Service redacts logs.

### 12.2. Runtime state machine

Improve states:

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

### 12.3. Recovery

- Late winws death -> diagnostics warning now.
- Future: automatic fresh VpnOnly fallback on late winws death, if enabled.
- Future: restore Smart after zapret recovery.
- Future: graceful Mihomo reload instead of restart when safe.

### 12.4. Logging

- Separate logs: agent, mihomo, zapret, policy.
- Redaction layer before writing logs.
- Config path and policy id included.
- No full subscription body in logs.

---

## 13. Security roadmap

### 13.1. Secrets handling

Never commit or log:

- subscription URLs;
- UUIDs;
- real node server names/IPs if sensitive;
- `authentication` entries;
- generated YAML;
- tokens;
- proxy credentials.

### 13.2. Redaction

Add central redactor:

```text
subscription URL -> <subscription-url-redacted>
UUID -> <uuid-redacted>
authentication -> <auth-redacted>
server -> <server-redacted> where appropriate
secret -> <secret-redacted>
```

Use it in:

- logs;
- diagnostics bundle;
- UI error messages;
- crash reports;
- tests snapshots.

### 13.3. Component integrity

- Verify downloaded mihomo/zapret binaries.
- Store component version metadata.
- Support rollback.
- Show component health in UI.

---

## 14. Testing roadmap

### 14.1. Unit tests

Core areas:

- policy compile;
- provider rule parser;
- proxy group resolver;
- managed VPN group;
- zapret artifact validation;
- DNS policy merge/suppression;
- serde migration.

### 14.2. YAML fixtures

Use sanitized fixtures only.

Required fixtures:

```text
provider_full_ru_split.yaml
provider_group_with_direct.yaml
provider_nested_group_with_direct.yaml
provider_only_direct.yaml
provider_no_match.yaml
provider_no_groups_with_proxies.yaml
provider_complex_rules.yaml
```

### 14.3. Integration tests

Where feasible:

- render YAML;
- parse back with `serde_yaml`;
- run `mihomo -t` if binary available;
- verify generated zapret files;
- verify fallback policy.

### 14.4. Windows manual QA matrix

| Scenario | Smart | VPN Only | Expected |
|---|---:|---:|---|
| YouTube | yes | yes | Smart DIRECT+zapret, VPN Only proxy |
| Discord | yes | yes | Smart DIRECT+zapret, VPN Only proxy |
| ChatGPT | yes | yes | proxy group |
| Telegram | yes | yes | provider proxy group |
| Yandex/VK/RU | yes | yes | Smart DIRECT, VPN Only proxy unless Force DIRECT |
| Bank domains | yes | yes | Smart DIRECT, VPN Only proxy unless Force DIRECT |
| winws killed | yes | no | Smart degraded/fallback |
| group with DIRECT | no | yes | managed no-DIRECT group |
| no non-DIRECT proxies | no | yes | clean error |
| Broad | yes | no | warning, experimental |

---

## 15. Documentation roadmap

### 15.1. User docs

- What is Smart mode?
- What is VPN Only?
- Why YouTube/Discord are DIRECT in Smart?
- Why VPN Only may ignore provider DIRECT rules?
- What are Force VPN / Force Zapret / Force DIRECT?
- Why Broad is experimental?
- How to read diagnostics?

### 15.2. Developer docs

- Smart Routing Core architecture.
- `CompiledPolicy` invariants.
- Policy priority model.
- How to add a new preset.
- How to add a new provider rule kind.
- Runtime fallback rules.
- Secret redaction policy.

### 15.3. Support docs

- Diagnostic bundle guide.
- Common errors.
- Mihomo validation failures.
- zapret conflicts.
- External VPN conflicts.
- DNS leak suspicion.

---

## 16. Future feature backlog

### 16.1. External rule providers

Do only after core stabilizes.

Requirements:

- local cache;
- SHA verification;
- clear diagnostics;
- no blind remote include;
- provider rules imported into policy core, not copied blindly.

### 16.2. privWL integration

- Disabled by default.
- Explicit opt-in.
- Hash pin or managed local cache.
- Diagnostics for conflicts with Smart presets.

### 16.3. Policy editor

- Read-only effective policy first.
- Then editable local overrides.
- Avoid exposing raw Mihomo grammar to normal users.

### 16.4. Auto-learning

- Learn game connections.
- Suggest Force Zapret domains/CIDRs.
- Suggest Force VPN for blocked resources.
- Never auto-apply without user consent.

### 16.5. Multi-subscription support

- Multiple profiles.
- Per-profile selected proxy group.
- Per-profile policy summary.
- Safe switching without stale runtime config.

---

## 17. Suggested milestones

### Milestone A — Merge Smart Routing Core

Target: immediate.

```text
[ ] Final review.
[ ] Merge to staging/main.
[ ] Windows QA smoke.
```

### Milestone B — Beta hardening

Target: next 1–2 development cycles.

```text
[ ] Policy viewer.
[ ] Better diagnostics page.
[ ] Runtime late winws fallback option.
[ ] Redaction layer.
[ ] More YAML fixtures.
[ ] Windows QA matrix.
```

### Milestone C — Release 0.1 Beta

Target: after QA.

```text
[ ] Signed installer/build.
[ ] Component install/update verified.
[ ] Agent service verified.
[ ] User docs.
[ ] Support diagnostics.
```

### Milestone D — Smart Routing v2

Target: after beta feedback.

```text
[ ] Rule-provider support.
[ ] privWL opt-in.
[ ] Policy editor.
[ ] Game profile improvements.
[ ] Broad hardening.
```

### Milestone E — Production polish

Target: after repeated successful beta sessions.

```text
[ ] Auto-recovery.
[ ] Component integrity verification.
[ ] Better update UX.
[ ] Crash/report tooling.
[ ] Localization polish.
```

---

## 18. Do-not-do list

До стабилизации beta не делать:

- третий публичный routing mode;
- blind copy provider rules into final config;
- broad as default;
- external rule-provider auto-download;
- raw subscription YAML logs;
- GUI admin requirement;
- large `commands.rs` rewrites;
- aggressive built-in blocklists without diagnostics;
- silent suppression of provider rules without `suppressed_rules`.

---

## 19. Project health metrics

Track during beta:

```text
Smart connect success rate
VPN Only connect success rate
zapret start failure rate
Mihomo config validation failure rate
fallback frequency
diagnostics warnings per session
number of suppressed provider rules
number of Broad users
support reports requiring manual config inspection
```

No telemetry should be added without explicit user consent and clear privacy boundaries.

---

## 20. Final target state

BadVPN should feel like this for the user:

```text
Smart:
  YouTube/Discord/games work with low ping through zapret.
  AI/social/blocked services work through VPN.
  RU/local services stay fast and direct.
  If zapret fails, app safely falls back to VPN Only.

VPN Only:
  Everything external goes through VPN.
  No accidental DIRECT via provider rules or proxy groups.
```

For developers:

```text
All routing decisions live in Smart Routing Core.
Mihomo, zapret, DNS and diagnostics are render targets of one CompiledPolicy.
New features extend policy inputs/outputs, not scattered if-else logic.
```
