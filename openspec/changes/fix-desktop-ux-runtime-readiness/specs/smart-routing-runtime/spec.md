## ADDED Requirements

### Requirement: Connect Preflight Handles Agent Readiness

BPN Client SHALL check `badvpn-agent` readiness when the user starts VPN and guide repair from the connect flow.

#### Scenario: Agent service is missing

- **GIVEN** `badvpn-agent` is not installed
- **WHEN** the user presses Connect
- **THEN** the UI shows an inline install/repair action
- **AND** the action uses the controlled elevation path for service installation
- **AND** the GUI itself is not relaunched as administrator
- **AND** the user is not required to discover Settings > Updates & Diagnostics manually

#### Scenario: Agent service is stopped

- **GIVEN** `badvpn-agent` is installed but not running
- **WHEN** the user presses Connect
- **THEN** BPN Client attempts or offers service start through the approved service control path
- **AND** after success the connect flow continues or offers a single `Start VPN` action

#### Scenario: Agent binary is wrong or runtime components are missing

- **GIVEN** the installed service path, binary version, binary hash or runtime components are not ready
- **WHEN** the user presses Connect
- **THEN** BPN Client reports the specific readiness problem
- **AND** offers repair or component preparation where supported
- **AND** does not log subscription URLs, controller secrets or credentials

### Requirement: Zapret Failure Does Not Block VPN Startup

BPN Client SHALL allow Mihomo VPN startup to continue when zapret/winws fails in Smart mode, unless the failure also makes VPN unsafe.

#### Scenario: winws cannot start

- **GIVEN** Smart mode is enabled and Mihomo can start
- **WHEN** winws/zapret startup fails
- **THEN** BPN Client starts or keeps VPN-only routing active
- **AND** marks zapret state as failed with VPN-only fallback
- **AND** diagnostics explain the zapret failure and next action

#### Scenario: zapret assets are missing

- **GIVEN** zapret runtime assets, lists or Flowseal profile files are missing
- **WHEN** Smart mode connect is requested
- **THEN** BPN Client offers component preparation or repair
- **AND** if Mihomo is otherwise ready, VPN-only fallback remains available

#### Scenario: external DPI tool conflicts

- **GIVEN** external `winws.exe`, GoodbyeDPI or conflicting WinDivert state is detected
- **WHEN** Smart mode connect is requested
- **THEN** BPN Client explains the conflict before spawning managed winws
- **AND** does not kill unrelated external processes without explicit user action
- **AND** can still offer VPN-only fallback

### Requirement: Flowseal Zapret Profile Compatibility Is Verified

BPN Client SHALL keep managed zapret/winws startup compatible with the selected Flowseal-style profile assumptions.

#### Scenario: Managed arguments are generated

- **WHEN** BPN Client translates the selected Flowseal profile to `winws.exe` arguments
- **THEN** required hostlist, ipset, include/exclude, game TCP/UDP and WinDivert arguments are present when enabled
- **AND** paths point to the active app-managed component/list directories
- **AND** missing required profile assets produce actionable diagnostics

#### Scenario: Preferred profile fails

- **GIVEN** auto profile fallback is enabled
- **WHEN** the preferred zapret profile fails to start
- **THEN** BPN Client tries the configured fallback order
- **AND** persists only a profile that actually starts
- **AND** reports all failed profile attempts in diagnostics
