# BadVpn Update And Release Contract

This document owns app update, component update, signing, rollback, and artifact attestation rules. Runtime startup details live in `docs/runtime-mihomo-zapret.md`; manual release QA lives in `docs/qa-win-mvp.md`.

## Channels

BadVpn has two update channels:

- App updates through the Tauri updater and GitHub Releases.
- Runtime component updates for Mihomo, zapret/winws, WinDivert, route lists, and templates through a BadVpn manifest.

GitHub release checks may show availability, but replacing runtime binaries must go through the verified component flow below.

## App Updates

The app currently checks:

```text
https://github.com/Rerowros/bpn-client/releases/latest/download/latest.json
```

Before the first public release:

1. Generate the Tauri updater key pair outside the repository.
2. Store the private key only in CI secrets.
3. Replace `BADVPN_UPDATER_PUBLIC_KEY_REPLACE_BEFORE_RELEASE` in `apps/badvpn-client/src-tauri/tauri.conf.json` with the public key.
4. Build release bundles with updater artifacts enabled.
5. Attach bundles, signatures, and `latest.json` to the GitHub Release.

Never commit the private signing key.

## Tauri `latest.json`

Release assets should follow the Tauri updater format:

```json
{
  "version": "0.1.1",
  "notes": "BadVpn update notes",
  "pub_date": "2026-04-28T00:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "signature": "SIGNATURE_FROM_TAURI_BUILD",
      "url": "https://github.com/Rerowros/bpn-client/releases/download/v0.1.1/BadVpn_0.1.1_x64-setup.nsis.zip"
    }
  }
}
```

## Component Updates

Runtime component replacement must be manifest-driven:

1. Fetch the BadVpn component manifest.
2. Verify manifest signature or pinned hash chain.
3. Download components into a staging directory.
4. Verify SHA256 and signature where available.
5. Stop affected BadVpn-owned processes through `badvpn-agent`.
6. Atomically swap files.
7. Smoke-check the new component, for example `mihomo -t` for config compatibility or a winws launch check.
8. Commit the version metadata.
9. Roll back automatically on any failed verification or smoke check.

Current GitHub checks for `MetaCubeX/mihomo` and `bol-van/zapret` are version discovery only. They must not directly replace runtime files.

## Runtime Artifact Attestation

Before trusting runtime logs or Smart/VPN Only status, diagnostics must compare:

| Artifact | Expected check |
|---|---|
| staged `badvpn-agent.exe` | path, version/build id, SHA256 |
| installed service `ImagePath` | points to BadVpn-owned ProgramData path |
| installed service binary | SHA256 matches expected staged build |
| running service process | image path matches installed service binary |

If attestation fails, the UI should show Install / Repair instead of treating runtime state as authoritative.

## Release Gates

Before a public Windows release:

```text
[ ] Tauri updater key pair generated outside the repo.
[ ] Private signing key exists only in CI secrets.
[ ] Public updater key is committed in Tauri config.
[ ] Windows installer/bundle is signed.
[ ] `latest.json` points to signed artifacts.
[ ] Component manifest is signed or hash-pinned.
[ ] Component update rollback is tested.
[ ] Runtime artifact attestation passes after install/repair.
[ ] No subscription URLs, generated controller secrets, tokens, or raw credentials are present in artifacts/logs.
```
