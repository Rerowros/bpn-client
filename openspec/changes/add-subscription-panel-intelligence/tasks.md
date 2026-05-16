# Tasks: Subscription Panel Intelligence

## 1. Error Classification

- [x] Add common Rust classifier for provider/HWID/expired/quota/unauthorized/rate-limit/not-found/maintenance/invalid-format failures.
- [x] Parse bounded JSON/text error bodies without logging raw provider responses.
- [x] Use classifier for HTTP error responses during subscription fetch.
- [x] Use classifier for successful HTTP responses that contain no supported nodes.
- [x] Add unit tests for HWID limit, expired, traffic exhausted, and invalid profile body classification.
- [x] Add integration tests that failed refresh preserves the previous working profile body.
- [x] Add UI-specific copy for each failure category.

## 2. Panel Metadata and Announcements

- [x] Read common Clash/Mihomo metadata headers.
- [x] Add safe aliases for custom panel headers used by Remnawave/Pasarguard-like deployments.
- [x] Display provider announcement/account/support links as safe external read-only links.
- [x] Normalize provider announcement metadata into a dedicated UI card with source label and timestamp.
- [x] Keep BPN-signed product announcements separate from provider subscription announcements.
- [x] Add tests that provider links are redacted in support summaries.

## 3. Profile Lifecycle

- [x] Store per-profile last successful refresh timestamp and last failed refresh reason.
- [x] Store next refresh time from provider interval headers.
- [x] Add per-profile fetch timeout setting.
- [x] Add per-profile fetch proxy mode: direct, system proxy, custom proxy.
- [x] Protect custom proxy credentials at rest.
- [x] Respect provider interval for auto-refresh while allowing manual refresh.

## 4. Remnawave and Pasarguard Compatibility

- [x] Capture known response/header conventions in sanitized fixtures.
- [x] Add adapter tests for panel error JSON variants.
- [x] Add provider type hint detection without hard-coding sensitive hostnames.
- [x] Add user-facing troubleshooting text for HWID reset flows.

## 5. Validation

- [x] `cargo test -p badvpn-common subscription`
- [x] `cargo test -p badvpn-client`
- [x] `cargo check --workspace`
- [x] `npm --prefix apps/badvpn-client run check`
- [x] `npm --prefix apps/badvpn-client run build`
- [x] Browser DOM smoke for provider metadata links.
- [x] Browser visual screenshot QA for provider metadata links.
