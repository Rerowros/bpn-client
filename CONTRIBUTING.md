# Contributing to BPN Client

Thanks for helping improve BPN Client. This project is security-sensitive because it manages VPN routing, a privileged Windows service, runtime binaries, local controller secrets, and user subscription data.

BPN Client actively looks for contributors with real engineering experience: Windows networking, Rust, Tauri, VPN routing, privileged services, installer and update systems, or security. The codebase needs people who can challenge weak design with evidence, propose concrete alternatives, and own the outcome. If you see something wrong architecturally, open a proposal — that kind of input is especially valued.

AI tools are allowed and encouraged, but the human contributor is fully responsible for correctness, security, testing, and documentation. Meaningful AI assistance must be disclosed in the PR template. Do not treat AI output as trusted authority.

Before changing product behavior or architecture, read:

1. `AGENTS.md`
2. `docs/BADVPN_IMPLEMENTATION_PLAN.md`
3. The narrow docs file that owns the touched behavior.
4. `TRADEMARKS.md` when changing branding, official service links, or public attribution.

## Development Setup

Requirements:

- Windows 10/11 for full manual QA.
- Rust toolchain compatible with `Cargo.toml`.
- Node.js and npm compatible with the checked-in lockfiles.
- Tauri v2 prerequisites for GUI/runtime work.

Common checks:

```powershell
npm install
npm run check
npm --prefix apps/badvpn-client run build
cargo fmt --all -- --check
cargo test --workspace
```

For Rust or Tauri implementation changes, follow the Context7 research gate in `AGENTS.md` before editing code.

## Branches

- Use short topic branches: `feat/...`, `fix/...`, `docs/...`, `chore/...`, `security/...`.
- Keep one PR focused on one reviewable change.
- Do not force-push shared branches unless the maintainer explicitly approves a history rewrite.
- Do not commit generated runtime data, downloaded cores, logs, cache, or local secrets.

## Commits

Use clear scoped commits:

```text
feat(policy): explain Smart route fallback
fix(agent): keep VPN startup working when winws fails
docs(review): add release QA gate
```

Small fixup commits are fine during draft review. Squash or clean them before final merge if requested.

## Pull Requests

Open a draft PR early for non-trivial work. Mark it ready only when:

- The PR has a clear summary and risk section.
- The touched behavior has tests or an explicit manual QA plan.
- The relevant docs are updated next to the behavior they describe.
- AI-assisted changes are disclosed in the PR template.
- No subscription URLs, tokens, controller secrets, logs with credentials, or raw user data are included.

Review expectations are defined below and enforced through the pull request template.

## Architecture Proposals

Architecture changes are welcome. For large changes, open a proposal issue or draft PR before implementing. Explain:

- What current design choice is limiting or unsafe.
- What architecture should replace it.
- Which files and docs would change.
- How users migrate without breaking current installs.
- How the change is validated on Windows.

Use the GitHub architecture proposal issue template for larger rewrites before implementation.

## Review Expectations

Reviewers should prioritize:

1. Security and privacy regressions.
2. Privileged service boundary violations.
3. Routing, DNS, firewall, Mihomo, or zapret behavior regressions.
4. Update, verification, rollback, installer, and service lifecycle failures.
5. User-visible correctness, diagnostics, tests, and docs.

Merge should be blocked if the GUI performs privileged work directly, secrets are logged or committed, Mihomo controller access is exposed beyond localhost without an approved decision, Smart failure blocks VPN-only startup, or risky runtime/update/service changes skip manual Windows QA.

## AI-Assisted Contributions

AI tools are allowed and expected in this project, but the human author owns the result.

- Give agents a narrow task, file scope, and acceptance criteria.
- Keep agent outputs reviewable as normal code, not as trusted authority.
- Verify claims with repository code, current docs, tests, or manual QA.
- Mention meaningful AI assistance in the PR template.
- Do not paste private credentials, real subscription URLs, or private user logs into any external AI system.

## Reporting Bugs

Use the bug report issue form and include:

- BPN Client version or commit.
- Windows version.
- Route mode: `Smart` or `VPN Only`.
- Whether Mihomo, winws/zapret, or `badvpn-agent` is involved.
- Sanitized diagnostics only.

Security vulnerabilities must follow `SECURITY.md`, not public issues.
