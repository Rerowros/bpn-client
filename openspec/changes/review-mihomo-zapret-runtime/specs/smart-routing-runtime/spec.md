# Specification: Smart Routing Runtime Review

## ADDED Requirements

### Requirement: Service-owned runtime components

When `badvpn-agent` is installed, connect readiness MUST be based on components available to the service, not only on user-scoped AppData cache.

#### Scenario: User cache exists but ProgramData is empty

- GIVEN Mihomo and zapret components exist only under `%APPDATA%\BadVpn`
- AND `badvpn-agent` is installed
- WHEN the user starts Smart mode
- THEN the Tauri backend stages required assets into `%PROGRAMDATA%\BadVpn`
- AND only then sends `Connect` to `badvpn-agent`
- AND the agent preflight sees `mihomo.exe` and `winws.exe`

#### Scenario: Staging fails

- GIVEN AppData components exist
- AND ProgramData staging fails
- WHEN the user starts Smart mode
- THEN connect does not claim runtime readiness
- AND the UI receives an actionable staging error
- AND no GUI process starts Mihomo or winws as administrator.

### Requirement: Smart zapret failure fallback

Smart mode MUST degrade to a fresh VPN Only policy if winws cannot start and Mihomo can still start.

#### Scenario: winws is missing

- GIVEN route mode is Smart
- AND `winws.exe` is missing from service-owned components
- WHEN connect runs
- THEN preflight marks zapret as `degrade_to_vpn_only`
- AND Mihomo starts with VPN Only policy
- AND generated zapret artifacts are empty
- AND diagnostics explain that zapret components must be repaired.

#### Scenario: external DPI tool conflict

- GIVEN route mode is Smart
- AND an external `winws.exe` or GoodbyeDPI process is already running
- WHEN connect runs
- THEN zapret is marked as conflict
- AND Mihomo starts with VPN Only policy
- AND the user receives an action to stop the external tool or stay in VPN Only.

### Requirement: Late zapret death safety

If owned winws exits after Smart mode has already started, the runtime MUST NOT leave Mihomo running with Smart DIRECT rules that expect zapret.

#### Scenario: winws exits after Smart connect

- GIVEN Smart mode is running
- AND Mihomo is healthy
- AND the owned winws process exits
- WHEN the agent handles runtime status
- THEN the agent recompiles a VPN Only policy using the existing controller secret
- AND reloads or restarts Mihomo with that VPN Only config
- AND closes existing Mihomo connections
- AND marks the runtime as degraded VPN Only with a clear zapret diagnostic.

### Requirement: Bounded startup diagnostics

External probes MUST NOT make basic connect feel hung.

#### Scenario: Discord and YouTube are unreachable

- GIVEN Mihomo and winws started successfully
- AND external Discord/YouTube probes are enabled
- WHEN probes time out
- THEN probe runtime is bounded by a short timeout
- AND diagnostics record the failure
- AND disconnect/reconnect remains responsive.

#### Scenario: Probes are disabled

- GIVEN external probes are disabled
- WHEN the user connects
- THEN connect does not wait for Discord or YouTube HTTP checks
- AND on-demand zapret health checks remain available from diagnostics.

### Requirement: Runtime operation race handling

Runtime lifecycle commands MUST avoid orphaning owned child processes and must report in-progress operations clearly.

#### Scenario: Duplicate connect

- GIVEN a connect is already in `Preparing`, `StartingZapret`, `StartingMihomo`, `Verifying`, or `Stopping`
- WHEN another connect command arrives
- THEN the agent returns the current snapshot with an in-progress diagnostic
- AND does not start another Mihomo or winws process.

#### Scenario: Mihomo fails after winws starts

- GIVEN winws started successfully
- WHEN Mihomo start or readiness fails
- THEN winws is stopped
- AND config is rolled back to last working where available
- AND snapshot enters `Error` with the Mihomo failure.
