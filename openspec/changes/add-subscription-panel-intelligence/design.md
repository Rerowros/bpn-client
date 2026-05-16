# Design: Subscription Panel Intelligence

## Runtime Model

Subscription handling stays in the unprivileged Tauri backend for import and metadata, while `badvpn-agent` remains the only owner of privileged networking. The pipeline is:

1. Fetch subscription with BPN user-agent, timeout, and redacted logging.
2. Read safe metadata headers.
3. If HTTP status is non-success, classify the error body/status and stop.
4. If status is success, summarize and validate the body as Clash YAML or URI list.
5. Generate/validate the BPN-managed Mihomo overlay before committing.
6. Commit profile metadata/body only after validation succeeds.
7. On refresh failure, keep the previous active profile and expose a redacted actionable reason.

## Provider Metadata

Supported header families:

- Standard Clash/Mihomo style: `profile-title`, `subscription-userinfo`, `profile-update-interval`, `announce`, `announce-url`, `support-url`, `profile-web-page-url`.
- Safe aliases used by custom panels: `subscription-title`, `profile_title`, `announcement`, `profile-announce`, `support_url`, `profile_web_page_url`, `profile_update_interval`.

Remote text is displayed as provider metadata only. URLs are opened externally by the user and must be redacted in diagnostics.

## Failure Classification

Classification reads HTTP status and a bounded body text. JSON bodies are reduced to string fields such as `error`, `message`, `detail`, `code`, and `status`. Categories:

- `hwid_limit`: device/HWID limit reached.
- `expired`: account or subscription expired.
- `traffic_exhausted`: quota depleted.
- `unauthorized`: invalid token or access denied.
- `rate_limited`: refresh too frequent.
- `not_found`: profile/user not found.
- `provider_maintenance`: temporary panel outage.
- `invalid_format`: body is not a supported Clash/Mihomo profile.

## Security Rules

- Never log the raw subscription URL.
- Never include raw provider body in support bundles when it may contain credentials.
- Do not treat subscription announcements as signed BPN announcements.
- Do not send local HWID automatically. If HWID reset/registration is later added, it needs a separate security review.
