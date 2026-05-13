# Спецификация Smart Routing Runtime - Zapret Operator Tools

## Требования

### Требование: Local App and Rule Overrides

Клиент ДОЛЖЕН позволять пользователю создавать локальные routing overrides, которые применяются поверх подписки и не затираются refresh.

#### Сценарий: Override для `.exe` через DIRECT

- GIVEN пользователь хочет отправить приложение напрямую
- WHEN пользователь выбирает `.exe` в UI
- THEN клиент сохраняет full executable path как provenance
- AND извлекает normalized process name
- AND показывает preview `PROCESS-NAME,<process>,DIRECT`
- AND compiled policy routes process through `DIRECT`
- AND subscription refresh does not remove this override

#### Сценарий: Override для domain через zapret

- GIVEN пользователь добавляет domain override with path `zapret`
- WHEN policy is compiled in Smart mode
- THEN final Mihomo rule uses `DIRECT`
- AND target enters generated zapret hostlist
- AND policy summary marks source as local override

#### Сценарий: Override для zapret в VPN Only

- GIVEN user has zapret override
- WHEN effective mode is `vpn_only`
- THEN override degrades to VPN path
- AND zapret artifacts remain empty
- AND diagnostics explains mode compatibility

#### Сценарий: Override conflicts with safety route

- GIVEN user override targets private/safety destination
- WHEN policy is compiled
- THEN private/safety rule wins
- AND local override is suppressed with visible reason

### Требование: Local Override Persistence

Local overrides ДОЛЖНЫ храниться отдельно от provider subscription body.

#### Сценарий: Provider profile refreshes

- GIVEN local overrides exist
- WHEN subscription body refreshes from server
- THEN local overrides remain unchanged
- AND generated runtime config is rebuilt with refreshed provider profile plus local overlay

#### Сценарий: App/component updates

- GIVEN app or runtime components are updated
- WHEN update completes
- THEN local overrides remain in user data
- AND no update process writes provider YAML over local override storage

### Требование: Process-Aware Routing Trace

Клиент ДОЛЖЕН объяснять route decision для process/domain connections.

#### Сценарий: Connection matched local override

- GIVEN active connection belongs to a process with local override
- WHEN user opens connection details
- THEN UI shows process, destination, route path and local override source
- AND user can open related policy rule

#### Сценарий: User creates override from connection

- GIVEN a connection has process or domain metadata
- WHEN user chooses create override from connection
- THEN override editor pre-fills target type and value
- AND user chooses path before saving

### Требование: Runtime Rule Search and Trace

Клиент ДОЛЖЕН давать searchable route/rule view for zapret diagnostics.

#### Сценарий: User searches rule by domain

- GIVEN policy summary contains compiled rules
- WHEN user searches domain
- THEN matching provider, preset, local override and final Mihomo rules are shown

#### Сценарий: User filters zapret rules

- GIVEN compiled policy has zapret targets
- WHEN user filters by path `zapret`
- THEN UI shows related Mihomo DIRECT rules
- AND related zapret hostlist/ipset artifacts

#### Сценарий: Rule was suppressed

- GIVEN provider rule was suppressed by BPN overlay
- WHEN user opens suppressed rule detail
- THEN UI shows original provider rule, suppression reason and final replacement where available

#### Сценарий: Provider source is inspected

- GIVEN generated runtime config includes rule providers or proxy providers
- WHEN user opens provider source view
- THEN provider is shown read-only
- AND update/status metadata is visible when available
- AND UI shows whether provider rules or nodes participate in Smart/zapret overlay
- AND direct provider editing is not available in first implementation slice

### Требование: Game/App Bypass Profiles

Клиент ДОЛЖЕН expose known, detected, learned and manual app/game profiles.

#### Сценарий: Known game detected

- GIVEN a known game process is running
- WHEN game bypass is in auto mode
- THEN UI shows detected profile
- AND generated process/domain/port rules are previewable

#### Сценарий: Manual profile from `.exe`

- GIVEN user selects executable for game/app bypass
- WHEN user saves manual profile
- THEN profile stores executable path, process name, domains, CIDRs, TCP ports, UDP ports and filter mode
- AND profile can be enabled, disabled or deleted

#### Сценарий: Game preset disabled

- GIVEN Smart preset `games_zapret` is disabled
- WHEN profile exists
- THEN generated policy does not apply game zapret rules
- AND UI shows disabled-by-preset state

### Требование: DNS, Sniffer and TUN Controls

Advanced DNS/sniffer/TUN controls ДОЛЖНЫ be validated before runtime apply.

#### Сценарий: User edits sniffer domains

- GIVEN advanced settings are unlocked
- WHEN user edits force/skip domains
- THEN invalid domains are rejected
- AND settings require runtime restart or reload

#### Сценарий: User edits DNS policy

- GIVEN user changes nameserver policy or fake-ip filters
- WHEN user saves settings
- THEN config validation runs before replacing last working runtime config
- AND failure preserves previous runtime config

#### Сценарий: User edits TUN advanced settings

- GIVEN advanced settings include MTU, DNS hijack or excluded routes/CIDRs
- WHEN user saves changes
- THEN values are validated before runtime config replacement
- AND failure preserves last-known-good config
- AND UI offers reset-to-safe-defaults

#### Сценарий: User runs route/firewall recovery

- GIVEN TUN/route/firewall state is suspected broken
- WHEN user runs recovery action
- THEN privileged reset is performed by `badvpn-agent`
- AND UI shows result and next action
