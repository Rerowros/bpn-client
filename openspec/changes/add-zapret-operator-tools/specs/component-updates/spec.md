# Спецификация Component Updates - Zapret Operator Tools

## Требования

### Требование: Routing Resource Manager

Клиент ДОЛЖЕН manage routing and zapret resources with integrity checks.

#### Сценарий: User checks resources

- GIVEN resource manager is available
- WHEN user checks updates
- THEN UI shows geosite, geoip, mmdb, ASN if used, Flowseal/zapret lists and BPN curated lists
- AND current version/date/source/verification status are visible

#### Сценарий: User updates zapret list

- GIVEN zapret list update is available
- WHEN update is downloaded
- THEN digest or signature is verified before activation
- AND existing active list remains available for rollback

#### Сценарий: Update fails

- GIVEN resource activation fails
- WHEN error occurs
- THEN previous resource remains active
- AND diagnostics explain failure without exposing secrets

### Требование: Provider Resource Visibility

Клиент ДОЛЖЕН показывать provider resources that affect routing decisions.

#### Сценарий: Rule providers exist

- GIVEN generated runtime config includes `rule-providers`
- WHEN user opens resource manager
- THEN rule providers are listed read-only
- AND update status is shown if available
- AND user can see whether provider contributes to Smart/zapret overlay

#### Сценарий: Proxy providers exist

- GIVEN generated runtime config includes `proxy-providers`
- WHEN user opens resource manager
- THEN proxy providers are listed read-only
- AND selected groups/nodes are linked to server view where possible

#### Сценарий: Provider update requested

- GIVEN provider manual update is supported safely
- WHEN user starts provider update
- THEN update is validated before use
- AND failure preserves previous provider data
- AND direct provider content editing remains unavailable in first implementation slice

### Требование: Automatic Resource Refresh

Automatic refresh ДОЛЖЕН be safe and observable.

#### Сценарий: Auto refresh enabled

- GIVEN user enables auto refresh for safe resources
- WHEN interval triggers
- THEN update check runs in background
- AND activation occurs only after verification
- AND user can see last update result

### Требование: Runtime Component Verification

Runtime component updates ДОЛЖНЫ remain signed/hash verified before use.

#### Сценарий: Mihomo/zapret component update

- GIVEN new runtime component is available
- WHEN user starts update
- THEN component is verified before activation
- AND previous component can be restored if activation fails
