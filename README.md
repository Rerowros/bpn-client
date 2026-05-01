# BPN Client

BPN Client is a Windows-first desktop VPN client for the BPN service. It is built around a Clash/Mihomo subscription workflow, a Rust privileged service, Mihomo TUN routing, and optional zapret/winws direct bypass for selected traffic.

This repository is in active MVP development. The current source of truth is the documentation set in [docs/](docs/) and the root [AGENTS.md](AGENTS.md) file.

## Development Model

BPN Client is a source-available project in active MVP development. Contributors with real engineering experience in Windows networking, Rust, Tauri, VPN routing, privileged services, installer and update systems, or security are especially welcome. Large redesign proposals are accepted when they clearly explain the current limitation, the proposed architecture, migration path, risk, and validation plan.

AI tools are allowed and encouraged, but the human contributor is fully responsible for the result. Meaningful AI assistance must be disclosed in the PR template.

## Start Here

- [AGENTS.md](AGENTS.md) - mandatory rules for AI agents and maintainers changing the repo.
- [CONTRIBUTING.md](CONTRIBUTING.md) - branches, PRs, AI-assisted contributions, architecture proposals, and review expectations.
- [docs/BADVPN_IMPLEMENTATION_PLAN.md](docs/BADVPN_IMPLEMENTATION_PLAN.md) - product scope, architecture constraints, and release acceptance.
- [docs/PLAN.MD](docs/PLAN.MD) - active roadmap and current work queue.
- [docs/runtime-mihomo-zapret.md](docs/runtime-mihomo-zapret.md) - runtime ownership, IPC, connect flow, preflight, and logs.
- [docs/update-release.md](docs/update-release.md) - app updates, component updates, signing, and rollback.
- [docs/qa-win-mvp.md](docs/qa-win-mvp.md) - manual Windows QA matrix.
- [LICENSE.md](LICENSE.md) - source-available license with attribution and official service-link requirements.
- [NOTICE.md](NOTICE.md) - required attribution notice.
- [TRADEMARKS.md](TRADEMARKS.md) - attribution and official service-link policy.
- [SECURITY.md](SECURITY.md) - how to report security issues.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - basic contributor conduct rules.

## Local Checks

```powershell
npm install
npm run check
npm --prefix apps/badvpn-client run build
cargo fmt --all -- --check
cargo test --workspace
```

Run narrower checks while iterating, but PRs should explain which relevant checks were run and why any check was skipped.

## License

This repository is published under the [BPN Client Source Available License 1.0](LICENSE.md).

This is not an OSI-approved open-source license. It allows source access, modification, forks, and redistribution under the license terms, but requires preserved attribution and a clearly available link or button to the official BPN VPN service in ready-to-use application distributions.
