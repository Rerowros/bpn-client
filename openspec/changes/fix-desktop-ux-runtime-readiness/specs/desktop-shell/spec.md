## ADDED Requirements

### Requirement: Responsive Shell Keeps Primary Content Reachable

BPN Client SHALL keep primary page content and primary actions reachable at supported desktop window sizes without critical clipping.

#### Scenario: Overview is opened in a low-height window

- **GIVEN** the app window is 1024x700 or 900x650
- **WHEN** the user opens Overview
- **THEN** active profile, connection state, route mode and connect/disconnect action are visible without vertical scrolling
- **AND** secondary diagnostics are collapsed or moved below the primary flow
- **AND** no primary action text is clipped

#### Scenario: Interior page body overflows

- **GIVEN** an interior page contains more rows than fit in the viewport
- **WHEN** content overflows
- **THEN** the page body scrolls inside the available app content area
- **AND** the sidebar and page header remain stable
- **AND** controls do not overlap each other

### Requirement: Text Is Not Eaten

BPN Client SHALL avoid losing critical text on Overview, Settings, Operator, Policy, Servers and Connections.

#### Scenario: Long values are shown

- **WHEN** a profile name, provider name, Mihomo rule, local path or diagnostic message exceeds the available row width
- **THEN** the UI uses wrapping, middle ellipsis, tooltip, detail drawer or copy action
- **AND** the user can inspect the full value without resizing the window

#### Scenario: Route badges render

- **WHEN** a path label is rendered
- **THEN** `VPN`, `zapret`, `DIRECT`, `Blocked` and `Unknown` use the same labels, colors and casing across pages
- **AND** labels fit within their badge at supported sizes

### Requirement: Settings Uses Compact List Layout

Settings SHALL use compact row/disclosure layout instead of heavy card grids for normal configuration.

#### Scenario: Basic settings render

- **WHEN** the user opens Settings Basic
- **THEN** settings are shown as rows with label, current value/status and trailing control
- **AND** rows remain readable at 1024x700

#### Scenario: Advanced settings render

- **WHEN** the user opens advanced network, operator or update settings
- **THEN** advanced groups are collapsed into disclosure sections or tabs
- **AND** risky actions remain discoverable but not visually mixed with normal settings

### Requirement: Operator Lists Are Bounded

Operator and Advanced pages SHALL not grow excessively when many rules, providers, resources or logs exist.

#### Scenario: Many rules and providers exist

- **GIVEN** the active profile has many rules and providers
- **WHEN** the user opens Operator
- **THEN** rules/providers are shown inside a bounded list with search/filter
- **AND** categories can be collapsed
- **AND** the full page does not require excessive top-level scrolling

#### Scenario: Many log lines exist

- **GIVEN** live logs contain many entries
- **WHEN** the user opens logs
- **THEN** log entries scroll inside the log viewport
- **AND** filters and pause/clear/copy controls remain visible

### Requirement: Policy Viewer Is Consistent

Policy SHALL present routing state with consistent naming, stable layout and accessible details.

#### Scenario: Policy summary renders

- **WHEN** Policy is opened
- **THEN** mode, main proxy group, rules, suppressed rules, zapret domains and warnings use consistent labels
- **AND** long main proxy group and final rule values have details available

#### Scenario: Policy filters render

- **WHEN** path/source filter chips do not fit in one row
- **THEN** they wrap cleanly or move into an overflow control
- **AND** they do not cover the rule table

### Requirement: Servers Uses Proxy Group List

Servers SHALL present provider and proxy groups as a compact expandable group list inspired by the Koala Clash K1 reference.

#### Scenario: Proxy groups render

- **WHEN** the user opens Servers
- **THEN** each group header shows group name, type badge, selected node or fallback and right-aligned actions
- **AND** group bodies expand to show nodes/providers in compact rows
- **AND** latency/test controls are visible and aligned

#### Scenario: User scans many groups

- **GIVEN** many proxy/provider groups exist
- **WHEN** the user searches, sorts or collapses groups
- **THEN** the page remains stable and readable at supported desktop sizes

### Requirement: Connections Shows Clear Route Context

Connections SHALL make active and closed flows scannable and explain the selected route path.

#### Scenario: Connection rows render

- **WHEN** active connections are shown
- **THEN** each row shows process, host, destination, traffic, source rule and path badge in a stable layout
- **AND** `VPN`, `zapret` and `DIRECT` subtitles explain what the path means

#### Scenario: Technical route detail is long

- **WHEN** route rule, chain or source detail is too long for the row
- **THEN** the row opens a detail drawer or popover instead of clipping critical text
