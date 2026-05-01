# BadVpn Docs Index for Agents

This folder is the working context for BadVpn agent-driven development. Keep each decision in one canonical document, then link to it instead of copying the same checklist into every plan.

## Read Order

1. Root `AGENTS.md` for repository rules, dirty-tree handling, and mandatory Context7 gates for Tauri/Rust changes.
2. `docs/BADVPN_IMPLEMENTATION_PLAN.md` for product scope, architecture constraints, and release-level acceptance.
3. The narrow doc for the area you are changing:
   - [docs/PLAN.MD](PLAN.MD) - active roadmap and current work queue.
   - [docs/runtime-mihomo-zapret.md](runtime-mihomo-zapret.md) - runtime ownership, IPC, connect flow, preflight, and logs.
   - [docs/update-release.md](update-release.md) - app updates, component updates, signing, and runtime artifact attestation.
   - [docs/qa-win-mvp.md](qa-win-mvp.md) - manual Windows QA matrix.

## Source Of Truth

| Topic | Canonical doc | Do not duplicate |
|---|---|---|
| Product goal, first-release scope, platform stack | `BADVPN_IMPLEMENTATION_PLAN.md` | Full feature list, global acceptance, open product questions |
| Current priorities and next milestones | `PLAN.MD` | Detailed QA steps, release JSON, low-level runtime flow |
| Runtime control plane | `runtime-mihomo-zapret.md` | Product marketing, public release gates |
| Update and release integrity | `update-release.md` | Connect-flow details already covered by runtime doc |
| Manual Windows validation | `qa-win-mvp.md` | Architecture explanations |

## Agent Workflow

- Start every non-trivial task by identifying the single doc that owns the answer.
- Use root `CONTRIBUTING.md`, `TRADEMARKS.md`, `.github/PULL_REQUEST_TEMPLATE.md`, and `.github/ISSUE_TEMPLATE/architecture_proposal.yml` for PR preparation, AI-agent coordination, architecture proposals, and review handoff.
- If a Tauri or Rust implementation change is needed, complete the Context7 research gate from root `AGENTS.md` before editing code.
- Preserve user changes in the dirty working tree. Keep docs-only tasks out of unrelated code files.
- Update docs next to the behavior they describe. For example, a new runtime preflight belongs in `runtime-mihomo-zapret.md`, while the manual QA step belongs in `qa-win-mvp.md`.
- Prefer compact checklists and tables over duplicated prose.
- Record completed implementation checklists as dated notes; keep `PLAN.MD` focused on what remains actionable.
- Never include subscription URLs, raw generated configs, access tokens, controller secrets, or real user credentials in docs.

## Current Terminology

- Public routing modes: `Smart` and `VPN Only`.
- Legacy/internal aliases may still appear in code or older notes: `Smart Hybrid`, `VPN All`, `DPI Only`, `Manual`.
- Smart means Mihomo VPN for VPN targets and `DIRECT + zapret/winws` for configured DPI-bypass targets such as YouTube, Discord, and selected game traffic.
- VPN Only means external traffic must not accidentally escape through provider `DIRECT` rules or proxy groups containing `DIRECT`.

## Local Checks

Use the narrowest checks that validate the touched area.

```powershell
npm install
npm --prefix apps/badvpn-client run check
npm --prefix apps/badvpn-client run build
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

For docs-only changes, check links/paths for obvious typos and run:

```powershell
git status --short
git diff --check -- docs
```
