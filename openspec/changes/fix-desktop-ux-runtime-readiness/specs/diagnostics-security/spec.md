## ADDED Requirements

### Requirement: Runtime Readiness Diagnostics Are Actionable

Diagnostics SHALL classify service and runtime readiness failures into user-actionable states.

#### Scenario: Connect readiness fails

- **WHEN** connect preflight fails
- **THEN** diagnostics classify the failure as missing agent, stopped agent, wrong service binary, missing runtime component, missing zapret assets, external conflict, permission failure or unknown error
- **AND** the UI shows the next supported action
- **AND** detailed diagnostics remain available in Settings > Updates & Diagnostics

#### Scenario: Repair action fails

- **WHEN** install, repair, service start or component preparation fails
- **THEN** diagnostics show the failing step, sanitized command/result category and next action
- **AND** no raw secrets are shown or copied

### Requirement: Zapret Diagnostics Preserve VPN Context

Diagnostics SHALL distinguish zapret failure from VPN/Mihomo failure.

#### Scenario: Smart mode falls back

- **GIVEN** Smart mode requested zapret but VPN-only fallback is active
- **WHEN** diagnostics are viewed
- **THEN** the UI states that Mihomo VPN is running or ready
- **AND** zapret is shown separately as failed, disabled, missing assets or conflict
- **AND** support summary includes both states without implying the whole VPN is disconnected

### Requirement: UX QA Evidence Is Captured

Each implementation slice for this change SHALL include visual QA evidence for the affected page.

#### Scenario: Page layout changes

- **WHEN** Overview, Settings, Operator, Policy, Servers or Connections layout is changed
- **THEN** browser QA captures the page at the supported target sizes
- **AND** the reviewer can verify that text is not clipped and primary actions are reachable
