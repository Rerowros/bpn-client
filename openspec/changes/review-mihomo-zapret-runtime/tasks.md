# Tasks: Mihomo + zapret Runtime Review

## 0. Review Map

- [x] Read `docs/BADVPN_IMPLEMENTATION_PLAN.md` and `docs/runtime-mihomo-zapret.md`.
- [x] Verify current Rust/Tauri docs through Context7 before Rust/Tauri edits.
- [x] Inventory touched files before each implementation slice.
- [x] Record all findings with file/line references before final handoff.

## 1. Component Ownership And Staging

- [x] Check AppData vs ProgramData component discovery for `mihomo.exe`, `winws.exe`, WinDivert files, fake TLS/QUIC packets, Flowseal BAT profiles, and lists.
- [x] Fix readiness so a service-installed runtime requires ProgramData assets or stages AppData assets before connect.
- [x] Add tests for AppData-only assets not being treated as service-ready.
- [x] Verify update/repair stages lists and binaries into the layout expected by `badvpn-agent`.
- [x] Verify no generated configs, logs, downloaded binaries, or list caches are tracked in source.

Potential bugs to check separately:

- AppData assets marked ready while service cannot read them.
- ProgramData has binaries but missing lists or profiles.
- `BADVPN_MIHOMO_BIN` / `BADVPN_WINWS_BIN` env overrides work for dev but are not mistaken for release readiness.
- Component staging races with connect, update, repair, or service restart.
- ~~Robocopy mirror can delete service-owned files during update if source is incomplete.~~ Mitigated: staging uses `/E` + completeness gate.

## 2. Mihomo Policy And Config

- [x] Verify `CompiledPolicy::validate_invariants()` is called for every production compile path.
- [x] Verify Smart ends in `MATCH,<main_proxy_group>` and never `MATCH,DIRECT`.
- [x] Verify VPN Only suppresses external provider `DIRECT` and creates managed no-DIRECT groups when provider groups contain `DIRECT`.
- [x] Verify generated YAML reparses after overlay, selected proxy reordering, DNS/TUN/sniffer changes, and geodata stripping.
- [x] Verify `mihomo -t` validation failure preserves last working config.

Potential bugs to check separately:

- Provider `GEOSITE`/`GEOIP` rules stripped due missing geodata but policy summary still claims they exist.
- Managed no-DIRECT group missing if selected provider group contains nested `DIRECT`.
- Selected proxy persistence can reorder a group after managed group creation.
- Controller secret reused or logged accidentally.
- Mihomo validation can hang without a timeout.

## 3. zapret/winws Startup

- [x] Compare generated winws args with Flowseal BAT profiles for selected strategy.
- [x] Verify profile fallback order and persisted selected profile behavior.
- [x] Verify hostlist, hostlist-exclude, ipset, ipset-exclude, game hostlist, and game ipset paths exist before spawn.
- [x] Verify WinDivert DLL/SYS and fake packet files are present before spawn.
- [x] Verify external `winws.exe`/GoodbyeDPI conflicts degrade Smart to VPN Only instead of blocking Mihomo.
- [x] Verify legacy `BadVpnZapret` is detect/cleanup-only.

Potential bugs to check separately:

- BAT parser drops or corrupts quoted Flowseal args.
- `--ipset=ipset-all.txt` is not rewritten to effective ipset.
- Google QUIC/Youtube hostlist is not present in Flowseal parsed profile.
- Game UDP/TCP filter is off when a manual or detected profile should enable it.
- Process-only game rules are treated as zapret-covered even though winws needs domain/CIDR/port coverage.
- winws exits after the 900 ms startup check and is only reported later.

## 4. Startup Timing

- [ ] Measure and explain each connect phase: preflight, policy render, Mihomo validation, zapret list write, winws start, config promote, Mihomo start, controller ready, diagnostics.
- [x] Remove nonessential external network probes from the critical connect path or cap them to a short timeout.
- [x] Add tests for startup timeline redaction and phase-keyed output.
- [x] Ensure diagnostics probes have bounded timeout and cannot block disconnect/reconnect.

Potential bugs to check separately:

- Remote Discord/YouTube probes can add many seconds or trigger VPN-only fallback despite local runtime being healthy.
- `mihomo -t` or process inventory commands can block startup.
- Service IPC wait can add repeated 4 second delays when service is installed but pipe ACL/startup is broken.
- Sequential fallback profile attempts multiply the 900 ms winws wait.

## 5. Race Conditions And Recovery

- [x] Review duplicate connect/stop/restart handling in UI, Tauri backend, agent IPC, and `RuntimeManager`.
- [x] Verify stop while connect is preparing cannot leave Mihomo/winws orphaned.
- [x] Verify stale managed process cleanup only kills BPN-owned binaries by exact path.
- [x] Verify rollback stops winws when Mihomo start/readiness fails.
- [x] Verify late winws death is surfaced clearly and triggers VPN Only fallback while Mihomo stays running.

Potential bugs to check separately:

- ~~Single-threaded agent IPC blocks status/stop while a long connect is running.~~ Mitigated: background Connect + status progress snapshot.
- `Runtime operation is already in progress` returns a snapshot instead of a queued/cancelable operation.
- Child state can be stale if process exits after `is_running()` but before snapshot is returned.
- Stop/restart can use an old controller secret/port when config changed.
- ~~File writes use timestamp temp names that can collide inside the same second.~~ Mitigated: random temp suffixes.

## 6. Diagnostics And UX Contract

- [x] Verify runtime readiness messages distinguish missing agent, stopped agent, IPC failure, missing Mihomo, missing zapret, and VPN Only not needing zapret.
- [x] Verify diagnostics do not leak subscription URLs, controller secrets, raw YAML credentials, or local usernames where redaction is expected.
- [x] Surface zapret states as ready, needs components, conflict, started, failed-fallback, or disabled-by-mode.
- [x] Keep UI public modes to Smart and VPN Only.

Potential bugs to check separately:

- `zapret_ready=true` when VPN Only is selected can hide missing zapret assets after switching back to Smart.
- ~~Agent `VerifyInstalledAgent` can print absolute ProgramData path/hash into support output without redaction policy review.~~ Mitigated: `%PROGRAMDATA%` path redaction.
- Logs may include full process paths in conflict diagnostics.

## 7. Validation

- [x] `cargo fmt --all -- --check`
- [x] `cargo test -p badvpn-common`
- [x] `cargo test -p badvpn-agent`
- [x] `cargo test -p badvpn-client`
- [x] `cargo check --workspace`
- [x] direct TypeScript check: `apps/badvpn-client/node_modules/.bin/tsc.cmd --noEmit`
- [x] `git diff --check`
- [ ] `pnpm --dir apps/badvpn-client check` without package-manager lock contention
- [ ] Manual Windows QA: AppData-only components, ProgramData staging, missing winws, missing Mihomo, external winws, external Mihomo, Smart fallback, VPN Only, stopped agent, agent repair, reboot recovery.
