# Change: add-zapret-operator-tools

## Why

Анализ Clash Verge Rev и Koala Clash показал много функций, но не все подходят BPN Client. Для BPN главная ценность не в превращении клиента в универсальный Clash IDE, а в том, чтобы пользователь мог управлять Smart routing, zapret/winws, локальными app overrides и диагностикой без ручного редактирования YAML/bat файлов.

Этот change собирает функции, которых сейчас нет или которые есть только частично, и которые прямо помогают работе с zapret:

- понять, почему конкретное приложение/домен пошел через `DIRECT`, `VPN` или `zapret`;
- закрепить `.exe`, process, domain, CIDR или port за нужным path;
- увидеть live logs and runtime config безопасно;
- обновлять geodata/route/zapret resources;
- импортировать local profiles для теста/восстановления;
- экспортировать диагностику без secrets.

## What Changes

Добавить zapret-focused operator layer поверх текущего service-first runtime:

- Local App & Rule Overrides.
- Process-aware Connections.
- Runtime Rules and Resource Viewer.
- Live Logs.
- Runtime Config Viewer and Diff.
- Media/AI/Zapret Health Checks.
- Game/App Bypass Profiles UI.
- Local Profile Import and Deep Link.
- DNS/Sniffer Advanced Controls relevant to Smart routing.
- Safe Diagnostics and Backup for overrides.
- Verified updates for geodata, Flowseal/zapret lists and runtime assets.

## Current Gaps Covered

Сейчас в `bpn-client` уже есть базовые connections, servers, policy viewer, subscription profiles, Smart presets, game bypass runtime logic and diagnostics. Но отсутствуют или частично отсутствуют:

- выбор `.exe` через UI и полноценная сущность local override;
- grouping connections by process and detailed connection card;
- searchable runtime rules view beyond current read-only policy summary;
- rule provider/proxy provider/resource management;
- live Mihomo/zapret logs viewer;
- runtime YAML viewer and source-vs-runtime diff;
- user-facing media/AI/zapret checks;
- UI for learned/known game profiles and manual app bypass;
- local file import, drag-and-drop import, `bpn://` import;
- geodata/list update management with integrity;
- backup/export of local overrides and diagnostics bundle.

## Affected Capabilities

- `smart-routing-runtime`
- `desktop-shell`
- `diagnostics-security`
- `subscription-management`
- `component-updates`

## Out of Scope

- Universal Clash editor parity.
- Arbitrary JavaScript script execution in normal UI.
- Full Monaco YAML editor in the first implementation slice.
- System-wide sysproxy feature, unless later tied to explicit BPN product decision.
- macOS/Linux packaging features from other clients.
- Insecure certificate verification disable in normal profile import.

## Prioritization

Recommended implementation order:

1. Local App & Rule Overrides.
2. Process-aware connections and policy trace.
3. Live logs and runtime YAML/diff viewer.
4. Zapret/game profile UI.
5. Resource/geodata/list update manager.
6. Local import/deep link.
7. Backup/support bundle.
8. Advanced DNS/Sniffer controls.

## Risks

- `.exe` path selection may imply path-specific enforcement while Mihomo may only enforce process-name rules.
- Rule/resource editing can break provider config if it writes directly into subscription content.
- Live logs and config viewers can leak secrets if redaction is incomplete.
- Geodata/list updates can break runtime if activation is not atomic.
- Advanced DNS/sniffer controls can break connectivity for nontechnical users.

## Rollback

- All new zapret operator tools must be disableable or read-only by default until stable.
- Local override changes must be reversible per rule.
- Generated runtime config must keep last-known-good rollback.
- Resource updates must use backup/restore and integrity checks.
- Diagnostics export must be cancellable before writing bundle.
