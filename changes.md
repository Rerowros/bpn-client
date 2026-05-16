# Изменения BPN Client

Дата: 2026-05-16, Asia/Novosibirsk.

Примечание по приватности: в этом файле намеренно нет сырых subscription URL, access tokens, controller secrets, credentials, приватных путей и реальных provider hostnames. Для примеров используются только санитизированные значения вроде `panel.example`.

## Исследование референсов

- Склонированы и изучены референсные VPN/client проекты в `tmp/reference-clients`:
  - Koala Clash.
  - Clash Verge Rev.
  - FlClash.
  - Hiddify.
- Добавлен документ `docs/reference-client-feature-audit.md` с санитизированным аудитом функций и заметками по реализации для BPN Client.

## OpenSpec

- Добавлен change `openspec/changes/add-subscription-panel-intelligence/`:
  - `proposal.md`.
  - `design.md`.
  - `tasks.md`.
  - `specs/subscription-management/spec.md`.
- Обновлен `openspec/changes/add-zapret-operator-tools/tasks.md`: отмечены закрытые пункты по lifecycle подписок, локальному импорту и safety resource manager.

## Subscription Panel Intelligence

- Добавлен общий классификатор ошибок подписки в `crates/badvpn-common/src/subscription.rs`.
- Поддержаны категории ошибок:
  - лимит устройств / HWID;
  - истекшая подписка;
  - исчерпанный лимит трафика;
  - unauthorized / invalid token;
  - rate limit;
  - not found;
  - maintenance панели провайдера;
  - provider error;
  - invalid profile format.
- Добавлен bounded parsing JSON/text error body без логирования сырых provider responses.
- Добавлены пользовательские тексты для UI по категориям ошибок подписки.
- Добавлены тесты классификации для HWID, expired, traffic exhausted, invalid profile body и panel variants.
- Добавлены санитизированные fixtures для Remnawave/Pasarguard-like панелей:
  - `crates/badvpn-common/tests/fixtures/subscription_panels/remnawave_hwid_limit.json`
  - `crates/badvpn-common/tests/fixtures/subscription_panels/pasarguard_expired.json`
  - `crates/badvpn-common/tests/fixtures/subscription_panels/generic_quota_exhausted.json`
  - `crates/badvpn-common/tests/fixtures/subscription_panels/remnawave_headers.txt`
- Добавлен provider hint detection без hard-code чувствительных hostnames.
- Добавлена зависимость `serde_json` в `badvpn-common`.
- Новые subscription APIs re-exported из `crates/badvpn-common/src/lib.rs`.

## Метаданные и объявления подписки

- Читаются распространенные Clash/Mihomo metadata headers.
- Добавлены безопасные aliases для Remnawave/Pasarguard-like panel headers.
- Provider announcement/account/support links отображаются как безопасные read-only external links.
- Добавлена отдельная provider announcement card с source label и timestamp.
- Канал BPN signed product announcements отделен от provider subscription announcements.
- Добавлены тесты, что provider links маскируются в support summary без утечки токенов.
- Mock subscription data обновлен на санитизированные provider links с `panel.example`.

## Lifecycle профилей подписки

- Для каждого профиля сохраняются:
  - время последнего успешного refresh;
  - время последнего неуспешного refresh;
  - последняя ошибка refresh;
  - следующий refresh из provider interval headers.
- Неуспешный refresh сохраняет предыдущий рабочий profile body и записывает redacted reason.
- Добавлены flow для `refresh all` и `refresh due`.
- Добавлены per-profile fetch options:
  - timeout;
  - proxy mode: direct, system proxy, custom proxy;
  - защищенный custom proxy URL;
  - custom user-agent.
- Custom proxy credentials защищаются at rest и наружу отдаются только в redacted view.
- Добавлена валидация custom proxy URL и control characters в user-agent.
- Зарегистрированы Tauri commands:
  - `refresh_due_subscription_profiles`;
  - `update_subscription_profile_fetch_options`;
  - `update_subscription_profile_metadata`.
- Добавлены profile notes/description: persistence, validation, TS model, mock и UI action.
- Profile row теперь показывает refresh status, fetch settings, custom UA indicator, notes и безопасные metadata.

## Локальный импорт профилей

- Добавлен preview-before-activation для локальных профилей:
  - `preview_local_profile_from_text`;
  - `preview_local_profile_from_path`.
- Preview показывает:
  - display name;
  - только safe source file name;
  - format;
  - node count;
  - decoded size;
  - import readiness;
  - warning, если не найдены supported nodes.
- Preview не пишет runtime config, subscription store и не сохраняет raw local file path.
- Добавлены TS client functions, mock responses, UI controls `Preview text` / `Preview path` и preview panel.
- Добавлен тест, что local profile preview возвращает metadata без persistence.

## Resource Manager Safety

- Resource update staging выполняется через `.next` перед activation.
- Structural verification выполняется до activation через minimum non-empty line checks.
- Существующий resource file сохраняется backup перед replacement.
- Для activated resources пишется `.hash` digest file.
- Добавлена post-activation readback digest verification.
- Resource catalog verification status теперь показывает:
  - verified digest;
  - digest mismatch;
  - missing activation digest;
  - missing resource state.
- Activation вынесен в helper для тестируемости.
- Добавлены тесты:
  - failed resource activation сохраняет предыдущий resource;
  - successful resource activation записывает verified digest.

## Runtime Config Safety

- Перед заменой `config.yaml` добавлена структурная валидация generated Mihomo YAML.
- Проверяются критичные advanced sections:
  - `tun`;
  - `dns`;
  - `sniffer`.
- Invalid advanced config удаляет staged `.next` и не заменяет текущий working config.
- При ошибке promote выполняется попытка restore из `config.yaml.last-good`.
- Добавлены Tauri-command unit tests для invalid advanced YAML и валидной структуры `tun/dns/sniffer`.
- В OpenSpec закрыты пункты по validation before replace, rollback к last-good и Tauri command tests.

## Safe File Retirement

- Cleanup после успешной установки компонентов больше не удаляет старый backup directory напрямую.
- Частично установленный target при ошибке update теперь quarantine-rename в `.del.*` перед rollback.
- Добавлен collision-safe helper для `.del.*` quarantine path.
- Добавлены тесты:
  - quarantine сохраняет содержимое directory;
  - collision получает deterministic suffix `.1`.
- В OpenSpec закрыты пункты по `.del` retirement и тестам rename/quarantine behavior.

## Windows Network Recovery

- Добавлена IPC-команда `RepairWindowsNetwork` для `badvpn-agent`.
- Добавлен Tauri command `repair_windows_network`.
- Operator UI получил кнопку `Repair network` в блоке Zapret health.
- Recovery выполняется через privileged agent:
  - останавливает owned runtime;
  - flush DNS cache;
  - очищает IPv4/IPv6 destination/neighbor cache;
  - удаляет только BPN-named firewall rules для Mihomo/winws.
- Глобальные операции вроде `advfirewall reset`, `winsock reset` и `route -f` намеренно не используются.
- Добавлен тест, что recovery plan scoped к cache reset и BPN firewall rules.
- В OpenSpec закрыт пункт Windows firewall/route reset recovery через `badvpn-agent`.

## Frontend Tests

- Добавлен frontend test runner `vitest`.
- Добавлен `npm test` script для `apps/badvpn-client`.
- Добавлены unit tests для `localOverrides`:
  - domain URL/wildcard normalization;
  - preview route rendering;
  - process path normalization;
  - duplicate detection across legacy lists and structured local override rules;
  - zapret UDP port patch generation.
- Тесты нашли и закрыли баг: quoted `.exe` path теперь корректно становится `target_kind=app`, а source path сохраняется без кавычек.
- В OpenSpec закрыт пункт frontend unit tests for local override normalization.

## Operator Tools и UI

- Обновлены UI models и service client wrappers для новых commands и fields.
- Обновлена регистрация Tauri commands в `apps/badvpn-client/src-tauri/src/lib.rs`.
- Обновлен `apps/badvpn-client/src/services/agentMock.ts` для новых profile, preview, metadata и provider-link flows.
- Расширены стили в `apps/badvpn-client/src/styles.css` для profile fetch controls, profile preview, provider announcements, provider links и связанных UI states.
- В `apps/badvpn-client/src/App.tsx` подключены:
  - provider announcement card;
  - разделение BPN announcement;
  - profile fetch controls;
  - profile notes;
  - local profile preview;
  - Windows network repair action;
  - support summary redaction details.

## Дизайн внутренних страниц

- Доделан единый рабочий стиль для внутренних разделов приложения помимо Overview:
  - Connections;
  - Servers;
  - Policy;
  - Settings Basic/Advanced/Operator/Updates.
- Внутренние страницы переведены на более плотную desktop control surface: нейтральный фон, компактные панели, ровные toolbar/search/filter controls, единые поля ввода, кнопки и статусы.
- Исправлено обрезание длинных страниц: `pagePanel` теперь прокручивается по содержимому, а не сжимает нижние блоки.
- Исправлен layout Settings Operator: панели больше не схлопываются и не перекрываются, нижние секции доступны прокруткой.
- Визуально проверены основные страницы через локальный браузер:
  - Connections;
  - Servers;
  - Policy;
  - Settings Basic;
  - Settings Operator;
  - Settings Updates с provider metadata links.
- Provider metadata links проверены на скриншоте: отображаются санитизированные Announcement/Account/Support links без raw subscription URL.
- Исправлена браузерная адаптация под узкие окна:
  - убраны жесткие `min-width` на root/app shell;
  - rail принудительно сжимается в icon-only режим на узких viewport;
  - Overview, Settings, Policy и табличные блоки теперь сжимаются/прокручиваются внутри контейнера, не расширяя страницу за пределы окна;
  - provider announcement и agent карточки на малой ширине переходят в одну колонку без наложения.

## Tauri / App Configuration

- `apps/badvpn-client/src-tauri/tauri.conf.json` изменен в рамках общей работы над клиентом.
- Зарегистрированы новые Tauri command handlers для subscription lifecycle и local profile preview.

## Проверки

- `cargo fmt --check`
- `cargo test -p badvpn-common subscription`
- `cargo test -p badvpn-client`
- `cargo test -p badvpn-client redaction_tests`
- `cargo test -p badvpn-client resource_activation`
- `cargo test -p badvpn-client retire_path_to_del`
- `cargo test -p badvpn-client invalid_advanced_mihomo_yaml_does_not_replace_last_working_config`
- `cargo test -p badvpn-client advanced_mihomo_yaml_structure_validator_accepts_generated_sections`
- `cargo test -p badvpn-client local_profile_preview_reports_metadata_without_persisting`
- `cargo test -p badvpn-agent windows_network_recovery_plan_is_scoped_to_cache_and_bpn_rules`
- `npm --prefix apps/badvpn-client test`
- `cargo check --workspace`
- `npm --prefix apps/badvpn-client run check`
- `npm --prefix apps/badvpn-client run build`
- `git diff --check`
- Browser DOM smoke для provider metadata links прошел.
- Browser visual screenshot QA для provider metadata links прошел.
- Browser visual QA для внутренних страниц приложения прошел: Connections, Servers, Policy, Settings Basic, Settings Operator, Settings Updates.
- Headless Edge responsive QA на узких viewport: горизонтальный overflow не найден, элементы не выходят за `documentElement.clientWidth`.

## Оставшиеся открытые пункты

### `add-zapret-operator-tools`

- Manual Windows QA с реальным `.exe`.
- Manual provider update action только после проверки, что обновление можно провалидировать и откатить через rollback.
- Manual Windows QA для `.exe` override, zapret health checks, resource update rollback и support bundle redaction.

## Измененные пути в стеке PR #17-#19

Список ниже описывает весь текущий стек изменений, а не только дизайн-PR.

- `Cargo.lock`
- `apps/badvpn-client/package-lock.json`
- `apps/badvpn-client/package.json`
- `apps/badvpn-client/src-tauri/src/commands.rs`
- `apps/badvpn-client/src-tauri/src/lib.rs`
- `apps/badvpn-client/src-tauri/src/settings.rs`
- `apps/badvpn-client/src-tauri/tauri.conf.json`
- `apps/badvpn-client/src/App.tsx`
- `apps/badvpn-client/src/localOverrides.ts`
- `apps/badvpn-client/src/localOverrides.test.ts`
- `apps/badvpn-client/src/services/agentClient.ts`
- `apps/badvpn-client/src/services/agentMock.ts`
- `apps/badvpn-client/src/styles.css`
- `crates/badvpn-agent/src/command.rs`
- `crates/badvpn-agent/src/main.rs`
- `crates/badvpn-agent/src/runtime.rs`
- `crates/badvpn-common/Cargo.toml`
- `crates/badvpn-common/src/ipc.rs`
- `crates/badvpn-common/src/lib.rs`
- `crates/badvpn-common/src/subscription.rs`
- `crates/badvpn-common/tests/fixtures/subscription_panels/*`
- `docs/reference-client-feature-audit.md`
- `openspec/changes/add-subscription-panel-intelligence/*`
- `openspec/changes/add-zapret-operator-tools/tasks.md`
