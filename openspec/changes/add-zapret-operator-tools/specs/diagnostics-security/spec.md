# Спецификация Diagnostics Security - Zapret Operator Tools

## Требования

### Требование: Redacted Live Logs

Live logs ДОЛЖНЫ render only redacted data.

#### Сценарий: Log line contains subscription URL

- GIVEN a log line includes subscription URL or token
- WHEN UI renders logs
- THEN sensitive part is replaced with redacted marker
- AND copy/export uses the redacted text

#### Сценарий: Log line contains controller secret

- GIVEN a log line includes controller secret
- WHEN logs are rendered or exported
- THEN secret is redacted

### Требование: Safe Runtime Config Viewer

Runtime config viewer ДОЛЖЕН redact sensitive fields before UI receives content.

#### Сценарий: Config includes secret

- GIVEN generated Mihomo config includes controller secret
- WHEN viewer opens
- THEN secret is redacted before render
- AND raw config path is not exposed as copyable sensitive data

### Требование: Support Bundle

Support bundle ДОЛЖЕН help debug zapret without exposing secrets.

#### Сценарий: User exports support bundle

- GIVEN user confirms export
- WHEN support bundle is created
- THEN it includes diagnostics summary, redacted logs, policy summary, resource versions and local override summary
- AND excludes raw subscription URLs, tokens, controller secrets and private credentials
- AND UI shows included categories before writing bundle

#### Сценарий: Bundle includes local evidence

- GIVEN user exports support bundle
- WHEN bundle is assembled
- THEN it MAY include system info, app uptime, service status, admin/elevation status and app/runtime/log directory paths
- AND local filesystem paths that contain usernames are redacted unless user explicitly chooses a raw local-only bundle

### Требование: Backup Redaction and Validation

Backup ДОЛЖЕН protect sensitive fields and validate schema on restore.

#### Сценарий: User exports backup

- GIVEN backup includes settings, profiles, selected proxies, local overrides and game profiles
- WHEN backup is written
- THEN sensitive credentials are encrypted or excluded
- AND backup schema version is included

#### Сценарий: User restores backup

- GIVEN backup file is selected
- WHEN restore starts
- THEN schema and required fields are validated
- AND invalid backup cannot overwrite current settings

### Требование: Non-Destructive File Retirement

Product flows НЕ ДОЛЖНЫ destructively delete user/runtime evidence by default.

#### Сценарий: Profile or resource is retired

- GIVEN a profile, generated config, log or downloaded resource must be retired
- WHEN product flow removes it from active use
- THEN file is renamed to `.del`, quarantined or backed up
- AND user or recovery flow can inspect it later unless a separate approved destructive cleanup exists

#### Сценарий: Cleanup would expose sensitive data

- GIVEN retired file contains sensitive content
- WHEN cleanup/quarantine happens
- THEN file is not printed in logs or UI
- AND redaction policy still applies to any diagnostic export
