# Спецификация Desktop Shell - Zapret Operator Tools

## Требования

### Требование: Advanced Operator Navigation

UI ДОЛЖЕН дать доступ к zapret operator tools без перегруза обычного пользователя.

#### Сценарий: Simple mode

- GIVEN advanced tools are not unlocked
- WHEN user opens settings or diagnostics
- THEN UI shows local overrides, zapret health and basic recovery actions
- AND hides risky editors and raw config views behind advanced unlock

#### Сценарий: Advanced mode

- GIVEN user enables advanced mode
- WHEN operator tools render
- THEN live logs, runtime config, rule trace, resource manager and DNS/sniffer controls become available
- AND UI labels these tools as advanced

### Требование: Process-Aware Connections UI

Connections view ДОЛЖЕН support process-oriented zapret debugging.

#### Сценарий: Group by process

- GIVEN connections include process metadata
- WHEN user selects process grouping
- THEN connections are grouped by process
- AND each group shows count, upload/download and route path distribution

#### Сценарий: Connection detail

- GIVEN user opens a connection detail
- WHEN metadata is available
- THEN detail shows process name/path, destination, host, rule source, route path and close action

### Требование: Local Override UI

Settings or dedicated rule view ДОЛЖЕН include local override editor.

#### Сценарий: User adds override

- GIVEN user opens local overrides
- WHEN user clicks add
- THEN UI asks for path, target type and target value
- AND `.exe` target uses file picker
- AND generated rule preview is visible before save

#### Сценарий: User manages overrides

- GIVEN local overrides exist
- WHEN list renders
- THEN each rule can be enabled, disabled, edited or deleted
- AND conflict/suppression state is visible when known

### Требование: Runtime Observability UI

UI ДОЛЖЕН expose logs, runtime config and rule trace safely.

#### Сценарий: User opens live logs

- GIVEN logs are available
- WHEN logs view opens
- THEN user can filter by source and level
- AND pause, resume, clear and copy redacted lines

#### Сценарий: User opens runtime config

- GIVEN generated runtime YAML exists
- WHEN config viewer opens
- THEN config is read-only
- AND sensitive values are redacted

#### Сценарий: User opens source-vs-runtime diff

- GIVEN source profile and generated runtime config exist
- WHEN diff viewer opens
- THEN overlay changes, suppressed rules, local overrides and zapret artifacts are highlighted

### Требование: Zapret Checks UI

UI ДОЛЖЕН expose checks for services affected by Smart/zapret routing.

#### Сценарий: User runs checks

- GIVEN runtime is ready or connected
- WHEN user runs YouTube/Discord/AI checks
- THEN UI shows pass/fail/unknown per check
- AND route path and recovery action are visible

### Требование: Resource Manager UI

UI ДОЛЖЕН show and update routing/zapret resources.

#### Сценарий: User opens resources

- GIVEN resource manager is available
- WHEN user opens resources view
- THEN resource versions, last update, source, verification and rollback status are visible

#### Сценарий: User updates resource

- GIVEN resource update is available
- WHEN user starts update
- THEN progress and verification result are visible
- AND failure offers rollback or keeps current resource active

### Требование: Provider Lifecycle UI

UI ДОЛЖЕН expose subscription/provider lifecycle actions relevant to routing.

#### Сценарий: User refreshes profiles

- GIVEN multiple profiles exist
- WHEN user opens profile management
- THEN refresh active and refresh all actions are available
- AND each profile shows last refresh result

#### Сценарий: User edits profile display metadata

- GIVEN profile exists
- WHEN user edits local name or notes
- THEN UI saves local display metadata
- AND remote refresh does not overwrite it unexpectedly

### Требование: Directory Actions

UI МОЖЕТ provide safe actions to open local diagnostic directories.

#### Сценарий: User opens log directory

- GIVEN app/core/log directory exists
- WHEN user clicks open directory
- THEN OS file explorer opens directory
- AND UI does not copy or export sensitive path unless user explicitly exports diagnostics
