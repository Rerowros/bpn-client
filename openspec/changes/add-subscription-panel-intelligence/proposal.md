# Change: add-subscription-panel-intelligence

## Why

BPN Client imports provider subscriptions, but provider failures are currently surfaced as generic fetch or format errors. Panels such as Remnawave, Pasarguard, Marzban-like deployments, and custom BPN endpoints can return useful metadata through headers or small JSON/text error bodies: account title, update interval, support link, account page, announcement, expired status, traffic exhaustion, and HWID/device-limit failures.

For BPN this matters because Smart mode depends on a valid Mihomo profile while zapret/winws is only the direct-bypass companion. Subscription refresh must never break the last working VPN profile, and panel messages must be shown safely without leaking subscription URLs or trusting remote content as executable instructions.

## What Changes

Add a provider-aware subscription intelligence layer:

- classify subscription fetch/validation failures into actionable categories;
- detect HWID/device-limit, expired, traffic-exhausted, unauthorized, not-found, rate-limited, maintenance, and invalid-format states;
- read common Clash/Mihomo panel metadata headers and safe aliases;
- show provider support/account/announcement links as read-only metadata;
- preserve last-known-good profile body and settings when refresh fails;
- record refresh history with redacted reason and provider type hints;
- add future adapter slots for Remnawave and Pasarguard-specific response conventions;
- keep all privileged runtime behavior under `badvpn-agent` and keep zapret failure independent from subscription failures.

## Out of Scope

- Executing panel-provided scripts or remote commands.
- Sending HWID/device identifiers to a provider without an explicit product decision.
- Storing raw subscription URLs in logs, diagnostics, or support bundles.
- Making provider announcements a trusted BPN announcement channel.
- Replacing Mihomo/Clash profile validation with panel-specific trust.

## Rollback

This change is safe to disable by treating all classified provider failures as generic subscription errors. Last-known-good profile behavior must remain active regardless of classification.
