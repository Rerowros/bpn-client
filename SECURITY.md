# Security Policy

BadVpn is security-sensitive because it manages VPN routing, privileged Windows service operations, runtime binaries, local IPC, update flows, and user subscription data.

## Supported Versions

BadVpn is currently pre-release. Security fixes are applied to the active development branch unless a release branch is explicitly announced.

## Reporting a Vulnerability

Do not open a public issue for vulnerabilities.

Preferred path:

1. Use GitHub private vulnerability reporting if it is enabled for the repository.
2. If it is not enabled, open a minimal public issue asking for a private security contact without sharing exploit details.

Include:

- Affected commit, release, or branch.
- Impact and affected component.
- Reproduction steps or proof of concept.
- Whether the issue requires local access, normal user access, administrator rights, or network attacker position.
- Any logs only after removing subscription URLs, tokens, controller secrets, and raw user credentials.

## Security-Sensitive Areas

Changes in these areas require stricter review:

- `crates/badvpn-agent/**`
- `crates/badvpn-common/src/ipc.rs`
- `apps/badvpn-client/src-tauri/**`
- Runtime binary download, verification, update, rollback, or install logic.
- Mihomo config generation, local controller secret handling, DNS/routing/firewall changes.
- zapret/winws process lifecycle and WinDivert cleanup.

## Disclosure

Maintainers should confirm receipt, triage privately, prepare a fix, and publish advisory details only after users have a reasonable upgrade path.
