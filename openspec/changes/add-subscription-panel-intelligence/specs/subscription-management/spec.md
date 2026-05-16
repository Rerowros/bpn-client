## ADDED Requirements

### Requirement: Provider Failures Are Actionable

BPN Client SHALL classify subscription provider failures into actionable categories when the HTTP status or response body makes the cause clear.

#### Scenario: HWID or device limit is reached

- **WHEN** the provider returns a response mentioning HWID, hardware ID, device limit, maximum devices, or equivalent localized wording
- **THEN** BPN Client reports a device/HWID limit failure
- **AND** the message tells the user to reset allowed devices in the provider panel or contact support
- **AND** the raw subscription URL is not logged or displayed

#### Scenario: Provider returns a non-profile body

- **WHEN** subscription fetch succeeds but the body is not Clash YAML and is not a supported URI list
- **THEN** BPN Client reports an invalid subscription format
- **AND** the previous active profile remains usable

### Requirement: Provider Metadata Is Read Only

BPN Client SHALL read safe provider metadata headers and expose them as read-only subscription metadata.

#### Scenario: Provider sends announcement and support headers

- **WHEN** a subscription response includes profile title, announcement, support URL, account URL, user info, or update interval headers
- **THEN** BPN Client stores the metadata with the subscription profile
- **AND** displays support/account links without treating them as trusted commands
- **AND** support bundles redact raw subscription URLs and credentials

### Requirement: Refresh Does Not Break Smart Runtime

BPN Client SHALL keep the last-known-good profile active when a refresh fails, including failures caused by panel errors.

#### Scenario: Subscription refresh fails during Smart mode

- **WHEN** the active profile is refreshed and the provider returns an error
- **THEN** BPN Client preserves the current Mihomo profile and selected proxy state
- **AND** Smart mode continues using the current zapret/Mihomo routing until the user reconnects or imports a valid profile
- **AND** diagnostics show that the failure belongs to subscription refresh, not zapret runtime startup

