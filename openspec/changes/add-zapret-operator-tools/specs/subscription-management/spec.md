# Спецификация Subscription Management - Zapret Operator Tools

## Требования

### Требование: Local Profile Import

Клиент ДОЛЖЕН support local profile imports for recovery and zapret testing.

#### Сценарий: File import

- GIVEN user has YAML/JSON/TXT profile file
- WHEN user imports local file
- THEN file is parsed and validated
- AND user sees metadata preview before activation
- AND import does not require remote subscription URL

#### Сценарий: Drag-and-drop import

- GIVEN user drops a profile file onto app window
- WHEN file type is supported
- THEN same validation flow runs as file picker import

#### Сценарий: Deep link import

- GIVEN OS opens `bpn://` link
- WHEN link contains import payload
- THEN app asks for confirmation
- AND payload is validated before saving

### Требование: Fetch Options for Remote Profiles

Клиент ДОЛЖЕН support safe advanced fetch options.

#### Сценарий: User configures fetch options

- GIVEN advanced profile settings are open
- WHEN user sets user-agent, proxy mode or timeout
- THEN subsequent import/refresh uses those options
- AND proxy credentials are protected at rest

#### Сценарий: User wants insecure certificate disable

- GIVEN user requests certificate verification disable
- WHEN normal UI is used
- THEN option is not available
- AND any future advanced debug option must require explicit warning and separate OpenSpec change

### Требование: Profile Lifecycle

Клиент ДОЛЖЕН поддерживать lifecycle подписок без потери last working profile.

#### Сценарий: User refreshes all profiles

- GIVEN multiple remote subscription profiles exist
- WHEN user starts refresh all
- THEN each profile refreshes with its own fetch options
- AND failed profiles keep their last working cached body
- AND result summary shows success/failure per profile

#### Сценарий: Provider update interval exists

- GIVEN provider metadata includes update interval
- WHEN profile is saved
- THEN auto-refresh schedule uses provider interval unless user overrides it

#### Сценарий: User edits profile display data

- GIVEN profile exists
- WHEN user edits local name, description or notes
- THEN edits are stored locally
- AND remote refresh does not overwrite local display fields unless user chooses provider metadata

#### Сценарий: Provider returns HWID-limit error

- GIVEN import or refresh fails with provider/HWID-limit pattern
- WHEN UI displays error
- THEN user sees provider-specific explanation
- AND raw subscription URL remains redacted

### Требование: Profile Metadata for Debugging

Profile list ДОЛЖЕН preserve metadata useful for route/zapret debugging.

#### Сценарий: Metadata exists

- GIVEN subscription headers include title, traffic, expire, support URL, homepage, announce or update interval
- WHEN profile is shown
- THEN metadata is visible without exposing raw subscription URL
