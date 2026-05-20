# Change: fix-desktop-ux-runtime-readiness

## Why

Текущий клиент уже содержит много operator/debug функций, но интерфейс стал тяжелым и на малых окнах теряет часть контента. На главной странице, Settings, Operator, Policy, Servers и Connections есть несколько повторяющихся проблем:

- часть текста и значений обрезается вместо нормального переноса, сжатия или disclosure;
- страницы выглядят перегруженными карточками и вложенными панелями;
- длинные rules/providers/resources делают Operator и Advanced чрезмерно высокими;
- Policy, Servers и Connections используют непоследовательный нейминг, бейджи и layout;
- старт VPN блокируется сообщением `badvpn-agent is not installed...` вместо понятного install/repair/start flow;
- Smart mode с zapret не стартует надежно, вероятно из-за расхождения с Flowseal-style zapret profile/assets.

Скриншот Koala Clash K1 принят как UX-reference для списка групп/провайдеров: компактные строки, раскрываемые секции, видимые действия справа, понятные бейджи типа `Selector`/`Fallback`, без тяжелой сетки карточек.

## What Changes

Добавить отдельный polish/fix track для desktop UX и runtime readiness:

- Responsive shell pass для главной страницы и всех внутренних страниц.
- Перевод Settings из тяжелых карточек в компактный list/disclosure layout по мотивам Koala Clash.
- Ограничение вертикального роста Operator/Advanced через списки с внутренней прокруткой, фильтры, collapse и virtualization при необходимости.
- Консистентный Policy viewer: единые названия paths/sources, аккуратные summary rows, таблица без обрезанных значений.
- Полная переделка Servers как proxy group/provider list, ближе к Koala Clash K1.
- Полировка Connections, включая читаемые подписи `VPN`, `zapret`, `DIRECT` и route explanation.
- Глобальное правило: текст не должен съедаться на поддерживаемых размерах окна.
- Startup readiness flow: при connect клиент проверяет наличие/состояние `badvpn-agent`, предлагает install/repair через controlled elevation, затем продолжает connect.
- Zapret startup fix track: проверить Flowseal assets/profile arguments, fallback profiles, list paths, WinDivert conflicts and graceful VPN-only fallback.

## Affected Capabilities

- `desktop-shell`
- `smart-routing-runtime`
- `diagnostics-security`

## Out of Scope

- Смена архитектуры Tauri/Rust/service-first runtime.
- Запуск GUI от администратора.
- Полный generic Clash editor.
- Новая тема/брендинг вне нужного layout polish.
- Скрытие operator/debug функций без замены на discoverable advanced/list UI.
- Небезопасный direct provider editing.

## Rollback

- UI changes must be revertible per page.
- Runtime startup changes must preserve existing explicit Settings > Updates & Diagnostics repair path.
- Zapret changes must degrade to VPN-only mode if winws cannot start.
- No migration may delete user settings, subscriptions, local overrides, rules, providers, logs, runtime assets or backups.
