# BadVpn Windows MVP QA Matrix

This document owns manual Windows validation. Keep architecture in `docs/BADVPN_IMPLEMENTATION_PLAN.md`, runtime mechanics in `docs/runtime-mihomo-zapret.md`, and release/update gates in `docs/update-release.md`.

## Test Setup

- Clean Windows 10 and Windows 11 machines or VMs.
- No GUI elevation after the controlled `badvpn-agent` install/repair prompt.
- Sanitized Clash/Mihomo subscription fixture with at least one non-DIRECT proxy.
- Optional conflict tools for negative scenarios: another Mihomo/Clash/sing-box/v2rayN client, winws/GoodbyeDPI, occupied DNS/controller ports.
- Support log review must confirm no subscription URLs, controller secrets, tokens, or raw credentials.

## Install And First Run

```text
[ ] Installer completes on clean Windows 10.
[ ] Installer completes on clean Windows 11.
[ ] UI starts without administrator privileges.
[ ] Release build starts as a normal GUI app without an extra console window.
[ ] `tauri dev` console is present only in development mode.
[ ] First launch shows a real dashboard/onboarding state, not a blank white/dark window.
[ ] One controlled elevation prompt is used only for installing or repairing `badvpn-agent`.
[ ] Empty or invalid subscription URL produces a clear error.
[ ] Existing external Mihomo/Clash process does not prevent UI launch; diagnostics show conflict/port details.
```

## Connection Lifecycle

```text
[ ] Connect sends runtime work through `badvpn-agent`.
[ ] Disconnect stops BadVpn-owned Mihomo/winws and restores owned route/DNS changes.
[ ] Restart performs stop then start without manual cleanup.
[ ] App restart shows the correct current state.
[ ] Windows reboot restores intended state or enters safe mode with an actionable message.
[ ] Occupied TCP/UDP `1053` blocks before winws starts and shows a DNS conflict.
[ ] External Mihomo/Clash/sing-box/v2rayN TUN client blocks before runtime mutation.
```

## Smart Mode

```text
[ ] UI exposes `Smart`, not legacy route-mode clutter.
[ ] YouTube/Googlevideo resolves to Mihomo `DIRECT` and requires active winws.
[ ] Discord resolves to Mihomo `DIRECT` and requires active winws.
[ ] Configured game-bypass traffic avoids VPN proxy nodes when covered by domain/CIDR/port policy.
[ ] AI/social/provider VPN targets use the selected proxy group.
[ ] RU/local safe targets use `DirectSafe` only where policy allows.
[ ] Missing or failed winws degrades to VPN Only without blocking VPN startup.
[ ] External winws/GoodbyeDPI conflict degrades or reports a clear conflict without creating `BadVpnZapret`.
[ ] Normal GUI actions never create or start legacy `BadVpnZapret`.
```

## VPN Only Mode

```text
[ ] UI exposes `VPN Only`.
[ ] winws/zapret is stopped.
[ ] Generated zapret artifacts are empty.
[ ] Final Mihomo rule is a safe proxy group, not `MATCH,DIRECT`.
[ ] Provider external `DIRECT` rules are suppressed unless explicit Force DIRECT exists.
[ ] Private/LAN safety DIRECT and REJECT rules are preserved where expected.
[ ] Provider group with direct `DIRECT` creates managed `__BADVPN_VPN_ONLY__` group or fails cleanly.
[ ] Subscription with no non-DIRECT proxy nodes fails with a clear message.
```

## Diagnostics

```text
[ ] Agent service installed/running and IPC reachable.
[ ] Installed `badvpn-agent.exe` path/version/hash matches the staged expected build.
[ ] Running service image path matches installed service `ImagePath`.
[ ] Mihomo controller health is visible through the agent.
[ ] Proxy groups are visible through the Mihomo controller.
[ ] winws/zapret state is visible through the agent.
[ ] Legacy `BadVpnZapret` service state is reported if present.
[ ] WinDivert assets, BFE, and driver state are reported.
[ ] External VPN/DPI conflicts are reported with next actions.
[ ] Suppressed provider rules are visible in diagnostics.
[ ] Broad coverage shows an experimental warning.
[ ] Logs and exported diagnostics redact secrets.
```

## Update, Repair, Rollback, Uninstall

```text
[ ] Install / Repair refreshes the installed service binary and ProgramData assets.
[ ] Runtime artifact attestation fails visibly when staged and installed agent binaries differ.
[ ] Component update stages files before swap.
[ ] Failed component smoke check rolls back automatically.
[ ] App update artifacts are signed before public release.
[ ] Uninstall removes only BadVpn-owned services, files, routes, firewall rules, and scheduled tasks.
[ ] Uninstall does not remove unrelated VPN/DPI tools.
```
