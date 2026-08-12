use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use badvpn_common::{
    generate_mihomo_config_from_subscription_with_options, AgentRuntimeSnapshot, AppRouteMode,
    CompiledPolicy, ConnectRequest, PolicyTargetKind, PreflightCheck, PreflightSeverity,
    PreflightStatus, RuntimeComponentSnapshot, RuntimeComponentState, RuntimeGameProfile,
    RuntimeMode, RuntimePhase, SubscriptionState,
};
use serde_yaml::Value as YamlValue;
use tokio::time::sleep;

const MIHOMO_READY_TIMEOUT: Duration = Duration::from_secs(12);
const MIHOMO_VALIDATE_TIMEOUT: Duration = Duration::from_secs(15);
const MIHOMO_CONTROLLER_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const LOCALHOST: &str = "127.0.0.1";
const BADVPN_DNS_PORT: u16 = 1053;
const POLICY_DIAGNOSTIC_SAMPLE_LIMIT: usize = 5;

#[derive(Debug)]
pub struct RuntimeManager {
    snapshot: AgentRuntimeSnapshot,
    last_request: Option<ConnectRequest>,
    config_store: RuntimeConfigStore,
    component_store: ComponentStore,
    mihomo: MihomoManager,
    zapret: ZapretManager,
    pub active_policy: Option<CompiledPolicy>,
}

impl RuntimeManager {
    pub fn new() -> Self {
        let component_store = ComponentStore::default();
        Self {
            snapshot: AgentRuntimeSnapshot::default(),
            last_request: None,
            config_store: RuntimeConfigStore::default(),
            component_store,
            mihomo: MihomoManager::default(),
            zapret: ZapretManager::default(),
            active_policy: None,
        }
    }

    pub fn snapshot(&mut self) -> AgentRuntimeSnapshot {
        self.refresh_process_state();
        self.handle_late_mihomo_death();
        self.record_late_zapret_death_if_needed();
        self.snapshot.clone()
    }

    pub async fn status_snapshot(&mut self) -> AgentRuntimeSnapshot {
        self.refresh_process_state();
        self.handle_late_mihomo_death();
        if self.late_zapret_death_requires_fallback() {
            if let Err(error) = self.fallback_to_vpn_only_after_late_zapret_death().await {
                tracing::error!(%error, "failed to apply VPN-only fallback after late zapret death");
                self.set_error(format!(
                    "Late zapret death fallback failed; Smart DIRECT rules may still be active: {error}"
                ));
            }
        }
        self.record_late_zapret_death_if_needed();
        self.snapshot.clone()
    }

    pub fn active_policy(&self) -> Option<&CompiledPolicy> {
        self.active_policy.as_ref()
    }

    pub fn remembered_selected_proxy(&self) -> Option<String> {
        let request = self.last_request.as_ref()?;
        if let Some(group) = self
            .active_policy
            .as_ref()
            .map(|policy| policy.main_proxy_group.as_str())
        {
            if let Some(proxy) = request.selected_proxies.get(group) {
                return Some(proxy.clone());
            }
        }
        request.selected_proxies.values().next().cloned()
    }

    pub fn last_connect_request(&self) -> Option<ConnectRequest> {
        self.last_request.clone()
    }

    pub async fn connect(&mut self, request: ConnectRequest) -> Result<AgentRuntimeSnapshot> {
        self.connect_with_cancel(request, None).await
    }

    pub async fn connect_with_cancel(
        &mut self,
        mut request: ConnectRequest,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<AgentRuntimeSnapshot> {
        let cancelled = || {
            cancel
                .map(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
                .unwrap_or(false)
        };
        let check_cancel = |phase: &str| -> Result<()> {
            if cancelled() {
                Err(anyhow!("connect cancelled during {phase}"))
            } else {
                Ok(())
            }
        };
        let mut timeline = StartupTimeline::new();
        tracing::info!(
            route_mode = ?request.route_mode,
            mixed_port = request.settings.mihomo.mixed_port,
            controller_port = request.settings.mihomo.controller_port,
            zapret_enabled = request.settings.zapret.enabled,
            zapret_strategy = %request.settings.zapret.strategy,
            "runtime connect requested"
        );
        self.refresh_process_state();
        if matches!(
            self.snapshot.phase,
            RuntimePhase::Preparing
                | RuntimePhase::StartingZapret
                | RuntimePhase::StartingMihomo
                | RuntimePhase::Verifying
                | RuntimePhase::Stopping
        ) {
            return Err(anyhow!(
                "Runtime operation is already in progress (phase={:?}).",
                self.snapshot.phase
            ));
        }

        let owned_runtime_was_running = self.mihomo.is_running() || self.zapret.is_running();
        if owned_runtime_was_running {
            let secret = self.config_store.controller_secret().unwrap_or_default();
            if !secret.is_empty() {
                let _ = self
                    .mihomo
                    .close_connections(self.last_controller_port(), &secret)
                    .await;
            }
            self.mihomo.stop()?;
            self.zapret.stop()?;
        }

        self.snapshot = AgentRuntimeSnapshot {
            phase: RuntimePhase::Preparing,
            desired_mode: request.route_mode,
            effective_mode: request.route_mode,
            diagnostics: Vec::new(),
            last_error: None,
            ..AgentRuntimeSnapshot::default()
        };
        let game_plan = apply_game_bypass_to_request(&mut request);
        self.snapshot.diagnostics.extend(game_plan.diagnostics);
        if owned_runtime_was_running {
            self.snapshot.diagnostics.push(
                "Owned runtime was already running; restarted to apply the latest connect request."
                    .to_string(),
            );
        }
        self.last_request = Some(request.clone());

        let preflight = match self.preflight(&request) {
            Ok(preflight) => preflight,
            Err(error) => {
                tracing::warn!(%error, "runtime preflight failed");
                self.set_error(error.to_string());
                return Ok(self.snapshot.clone());
            }
        };
        timeline.mark("preflight_ms");
        if let Err(error) = check_cancel("preflight") {
            let _ = self.mihomo.stop();
            let _ = self.zapret.stop();
            return Err(error);
        }

        let mut effective_mode = request.route_mode;
        if preflight.force_vpn_only && effective_mode == RuntimeMode::Smart {
            effective_mode = RuntimeMode::VpnOnly;
            self.snapshot.effective_mode = effective_mode;
            self.snapshot.phase = RuntimePhase::DegradedVpnOnly;
            self.snapshot.zapret = RuntimeComponentSnapshot::new(
                RuntimeComponentState::Unhealthy,
                Some("preflight forced VPN-only fallback before starting winws".to_string()),
            );
            self.snapshot.diagnostics.push(
                "Smart preflight forced VPN-only fallback before starting winws.".to_string(),
            );
        }

        let should_start_zapret = request.route_mode == RuntimeMode::Smart
            && request.settings.zapret.enabled
            && !preflight.force_vpn_only;
        if !should_start_zapret {
            let _ = self.zapret.stop();
            effective_mode = RuntimeMode::VpnOnly;
            self.snapshot.effective_mode = effective_mode;
            if !preflight.force_vpn_only {
                self.snapshot.zapret = RuntimeComponentSnapshot::new(
                    RuntimeComponentState::Stopped,
                    Some("zapret is disabled for VPN Only.".to_string()),
                );
            }
        }

        self.snapshot.phase = RuntimePhase::Preparing;
        let mut runtime_config = self
            .build_runtime_config(&request, effective_mode)
            .context("failed to build Mihomo runtime config")?;
        self.prepare_runtime_config_for_local_mihomo(&mut runtime_config)?;
        self.record_policy_diagnostics(&runtime_config.policy);
        timeline.mark("policy_render_ms");
        tracing::info!(
            effective_mode = ?effective_mode,
            config_id = %runtime_config.config_id,
            "mihomo runtime config built"
        );
        let draft_path = self
            .config_store
            .write_draft(&runtime_config.yaml)
            .context("failed to write Mihomo draft config")?;
        let mihomo_bin = self.component_store.mihomo_bin()?;
        self.mihomo
            .validate(&mihomo_bin, &draft_path, self.config_store.home_dir())
            .context("Mihomo rejected generated config")?;
        timeline.mark("mihomo_validate_ms");
        if let Err(error) = check_cancel("mihomo_validate") {
            let _ = self.zapret.stop();
            return Err(error);
        }

        if should_start_zapret {
            write_compiled_zapret_lists(&self.component_store, &runtime_config.policy)
                .context("failed to write compiled zapret policy lists")?;
            timeline.mark("zapret_list_write_ms");
            self.snapshot.phase = RuntimePhase::StartingZapret;
            self.snapshot.zapret =
                RuntimeComponentSnapshot::new(RuntimeComponentState::Starting, None);
            if let Err(error) = stop_legacy_zapret_service() {
                self.snapshot.diagnostics.push(format!(
                    "Legacy BadVpnZapret service cleanup warning: {error}"
                ));
            }
            match self
                .zapret
                .start(&self.component_store, &request.settings.zapret)
            {
                Ok(message) => {
                    timeline.mark("zapret_start_ms");
                    tracing::info!(message, "zapret started");
                    self.snapshot.zapret = RuntimeComponentSnapshot::new(
                        RuntimeComponentState::Running,
                        Some(message),
                    );
                }
                Err(error) => {
                    timeline.mark("zapret_start_ms");
                    tracing::warn!(%error, "zapret failed; falling back to VPN-only");
                    let _ = self.zapret.stop();
                    effective_mode = RuntimeMode::VpnOnly;
                    self.snapshot.effective_mode = effective_mode;
                    self.snapshot.phase = RuntimePhase::DegradedVpnOnly;
                    self.snapshot.zapret = RuntimeComponentSnapshot::new(
                        RuntimeComponentState::Unhealthy,
                        Some(error.to_string()),
                    );
                    self.snapshot.diagnostics.push(format!(
                        "zapret is unavailable; starting Mihomo in VPN-only fallback: {error}"
                    ));
                    runtime_config = self
                        .build_runtime_config(&request, effective_mode)
                        .context("failed to build Mihomo VPN-only fallback config")?;
                    self.prepare_runtime_config_for_local_mihomo(&mut runtime_config)?;
                    ensure_vpn_only_fallback_policy(&runtime_config.policy)
                        .context("VPN-only fallback policy violated invariants")?;
                    self.write_zapret_lists_best_effort(
                        &runtime_config.policy,
                        "winws-start VPN-only fallback",
                    );
                    self.record_policy_diagnostics(&runtime_config.policy);
                    let fallback_draft = self
                        .config_store
                        .write_draft(&runtime_config.yaml)
                        .context("failed to write Mihomo VPN-only fallback draft config")?;
                    self.mihomo
                        .validate(&mihomo_bin, &fallback_draft, self.config_store.home_dir())
                        .context("Mihomo rejected VPN-only fallback config")?;
                    timeline.mark("fallback_render_validate_ms");
                }
            }
        }

        let run_path = self
            .config_store
            .promote_draft_to_run(&self.config_store.draft_path())
            .context("failed to promote Mihomo runtime config")?;
        timeline.mark("config_promote_ms");

        self.active_policy = Some(runtime_config.policy.clone());
        if let Err(error) = self
            .config_store
            .write_policy_summary(&runtime_config.policy)
        {
            tracing::warn!(%error, "failed to write policy summary JSON");
        }

        self.snapshot.phase = RuntimePhase::StartingMihomo;
        self.snapshot.mihomo = RuntimeComponentSnapshot::new(RuntimeComponentState::Starting, None);
        if let Err(error) = self.mihomo.start(
            &mihomo_bin,
            &run_path,
            self.config_store.home_dir(),
            request.settings.mihomo.controller_port,
        ) {
            tracing::error!(%error, "mihomo start failed");
            let _ = self.config_store.rollback_run();
            let _ = self.zapret.stop();
            self.set_error(error.to_string());
            return Ok(self.snapshot.clone());
        }
        timeline.mark("mihomo_start_ms");

        if let Err(error) = self
            .mihomo
            .wait_ready(
                request.settings.mihomo.controller_port,
                MIHOMO_READY_TIMEOUT,
                &runtime_config.secret,
            )
            .await
        {
            tracing::error!(%error, "mihomo controller readiness failed");
            let _ = self.mihomo.stop();
            let _ = self.config_store.rollback_run();
            let _ = self.zapret.stop();
            self.set_error(error.to_string());
            return Ok(self.snapshot.clone());
        }
        timeline.mark("mihomo_ready_ms");
        if let Err(error) = check_cancel("mihomo_ready") {
            let _ = self.mihomo.stop();
            let _ = self.zapret.stop();
            let _ = self.config_store.rollback_run();
            return Err(error);
        }

        self.snapshot.phase = RuntimePhase::Verifying;
        if let Err(error) = self
            .mihomo
            .verify_proxy_egress(
                &runtime_config.policy.main_proxy_group,
                request.settings.mihomo.controller_port,
                &runtime_config.secret,
            )
            .await
        {
            // Soft-fail: controller readiness already proved Mihomo is up. Remote
            // /delay probes can false-negative on networks that block the probe URLs.
            tracing::warn!(%error, "Mihomo proxy egress verification failed; continuing");
            self.snapshot.diagnostics.push(format!(
                "Proxy egress probe warning (connect continues): {error}"
            ));
        }
        timeline.mark("proxy_egress_ms");
        if request.settings.diagnostics.discord_youtube_probes
            && effective_mode == RuntimeMode::Smart
        {
            if let Err(error) = run_discord_youtube_probes().await {
                tracing::warn!(%error, "Smart probes failed");
                self.snapshot
                    .diagnostics
                    .push(format!("Smart probe warning: {error}"));
                let zapret_still_running = self.zapret.is_running();
                if request.settings.zapret.fallback_to_vpn_on_failed_probe && !zapret_still_running
                {
                    self.snapshot.diagnostics.push(
                        "Smart probes failed and winws is not running; falling back to VPN-only."
                            .to_string(),
                    );
                    effective_mode = RuntimeMode::VpnOnly;
                    self.snapshot.effective_mode = effective_mode;
                    self.snapshot.phase = RuntimePhase::DegradedVpnOnly;
                    let mut fallback = self.build_runtime_config_with_secret(
                        &request,
                        effective_mode,
                        runtime_config.secret.clone(),
                    )?;
                    self.prepare_runtime_config_for_local_mihomo(&mut fallback)?;
                    ensure_vpn_only_fallback_policy(&fallback.policy)
                        .context("VPN-only probe fallback policy violated invariants")?;
                    self.write_zapret_lists_best_effort(
                        &fallback.policy,
                        "probe VPN-only fallback",
                    );
                    self.record_policy_diagnostics(&fallback.policy);
                    let fallback_draft = self.config_store.write_draft(&fallback.yaml)?;
                    self.mihomo
                        .validate(&mihomo_bin, &fallback_draft, self.config_store.home_dir())
                        .context("Mihomo rejected VPN-only probe fallback config")?;
                    let fallback_run = self.config_store.promote_draft_to_run(&fallback_draft)?;
                    if let Err(reload_error) = self
                        .mihomo
                        .reload(
                            fallback_run.as_path(),
                            request.settings.mihomo.controller_port,
                            &runtime_config.secret,
                        )
                        .await
                    {
                        self.snapshot.diagnostics.push(format!(
                            "Mihomo reload failed during fallback; restarting: {reload_error}"
                        ));
                        let _ = self.mihomo.stop();
                        if let Err(start_error) = self.mihomo.start(
                            &mihomo_bin,
                            &fallback_run,
                            self.config_store.home_dir(),
                            request.settings.mihomo.controller_port,
                        ) {
                            let _ = self.config_store.rollback_run();
                            let _ = self.zapret.stop();
                            self.set_error(format!(
                                "Mihomo restart failed during VPN-only fallback: {start_error}"
                            ));
                            return Ok(self.snapshot.clone());
                        }
                        if let Err(ready_error) = self
                            .mihomo
                            .wait_ready(
                                request.settings.mihomo.controller_port,
                                MIHOMO_READY_TIMEOUT,
                                &fallback.secret,
                            )
                            .await
                        {
                            let _ = self.mihomo.stop();
                            let _ = self.config_store.rollback_run();
                            let _ = self.zapret.stop();
                            self.set_error(format!(
                                "Mihomo controller did not recover during VPN-only fallback: {ready_error}"
                            ));
                            return Ok(self.snapshot.clone());
                        }
                    }
                    if let Err(close_error) = self
                        .mihomo
                        .close_connections(
                            request.settings.mihomo.controller_port,
                            &fallback.secret,
                        )
                        .await
                    {
                        self.snapshot.diagnostics.push(format!(
                            "Mihomo connection cleanup warning after VPN-only fallback: {close_error}"
                        ));
                    }
                    let _ = self.zapret.stop();
                    self.snapshot.zapret = RuntimeComponentSnapshot::new(
                        RuntimeComponentState::Unhealthy,
                        Some("Smart probes failed; disabled for VPN-only fallback".to_string()),
                    );
                    runtime_config = fallback;
                } else {
                    let reason = if zapret_still_running {
                        "Keeping Smart because winws is still running; endpoint probes are diagnostics-only."
                    } else {
                        "Keeping Smart because VPN fallback on failed probes is disabled."
                    };
                    self.snapshot.diagnostics.push(reason.to_string());
                }
            }
        }
        timeline.mark("diagnostics_ms");

        self.config_store.commit_last_working()?;
        self.snapshot.effective_mode = effective_mode;
        self.snapshot.mihomo = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Running,
            Some(format!(
                "controller 127.0.0.1:{}",
                request.settings.mihomo.controller_port
            )),
        );
        self.snapshot.windivert = if effective_mode == RuntimeMode::Smart {
            RuntimeComponentSnapshot::new(
                RuntimeComponentState::Running,
                Some("owned by winws/WinDivert while zapret is active".to_string()),
            )
        } else {
            RuntimeComponentSnapshot::default()
        };
        self.snapshot.phase = runtime_phase_after_connect(request.route_mode, effective_mode);
        self.snapshot.active_config_id = Some(runtime_config.config_id);
        self.active_policy = Some(runtime_config.policy.clone());
        if let Err(error) = self
            .config_store
            .write_policy_summary(&runtime_config.policy)
        {
            tracing::warn!(%error, "failed to write final policy summary JSON");
        }
        self.snapshot.last_error = None;
        self.snapshot.diagnostics.push(timeline.summary());
        tracing::info!(
            phase = ?self.snapshot.phase,
            effective_mode = ?self.snapshot.effective_mode,
            "runtime connect finished"
        );
        Ok(self.snapshot.clone())
    }

    pub async fn restart(&mut self) -> Result<AgentRuntimeSnapshot> {
        let Some(request) = self.last_request.clone() else {
            self.set_error("Connect request is required before restart.".to_string());
            return Ok(self.snapshot.clone());
        };
        let _ = self.stop().await;
        self.connect(request).await
    }

    pub async fn stop(&mut self) -> Result<AgentRuntimeSnapshot> {
        tracing::info!("runtime stop requested");
        self.snapshot.phase = RuntimePhase::Stopping;
        self.snapshot.last_error = None;
        if self.mihomo.is_running() {
            let secret = self.config_store.controller_secret().unwrap_or_default();
            let _ = self
                .mihomo
                .close_connections(self.last_controller_port(), &secret)
                .await;
        }
        self.mihomo.stop()?;
        self.zapret.stop()?;
        self.active_policy = None;
        self.snapshot.phase = RuntimePhase::Idle;
        self.snapshot.effective_mode = self.snapshot.desired_mode;
        self.snapshot.mihomo = RuntimeComponentSnapshot::default();
        self.snapshot.zapret = RuntimeComponentSnapshot::default();
        self.snapshot.windivert = RuntimeComponentSnapshot::default();
        self.snapshot.active_config_id = None;
        self.snapshot
            .diagnostics
            .push("Stopped BadVpn-owned Mihomo and winws processes.".to_string());
        tracing::info!("runtime stop finished");
        Ok(self.snapshot.clone())
    }

    fn preflight(&mut self, request: &ConnectRequest) -> Result<PreflightDecision> {
        if request.profile_body.trim().is_empty() {
            return Err(anyhow!("subscription profile body is empty"));
        }
        let mut checks = Vec::new();
        if self.component_store.mihomo_bin().is_err() {
            self.snapshot.mihomo = RuntimeComponentSnapshot::new(
                RuntimeComponentState::Missing,
                Some("mihomo.exe was not found in managed assets".to_string()),
            );
            checks.push(preflight_failed(
                "mihomo_binary",
                PreflightSeverity::BlockVpn,
                "mihomo",
                "mihomo.exe is missing from managed assets.",
                "Install or repair BadVpn runtime components.",
            ));
        }
        if request.route_mode == RuntimeMode::Smart
            && request.settings.zapret.enabled
            && self.component_store.winws_bin().is_err()
        {
            self.snapshot.zapret = RuntimeComponentSnapshot::new(
                RuntimeComponentState::Missing,
                Some("winws.exe was not found in managed assets".to_string()),
            );
            checks.push(preflight_failed(
                "winws_binary",
                PreflightSeverity::DegradeToVpnOnly,
                "zapret",
                "winws.exe is missing from managed assets.",
                "Repair zapret components; BadVpn can still start in VPN-only mode.",
            ));
        }
        if request.route_mode == RuntimeMode::Smart
            && request.settings.zapret.enabled
            && self.component_store.winws_bin().is_ok()
        {
            let missing = self.component_store.missing_zapret_runtime_assets();
            if !missing.is_empty() {
                self.snapshot.zapret = RuntimeComponentSnapshot::new(
                    RuntimeComponentState::Missing,
                    Some(format!(
                        "WinDivert/Flowseal support assets missing: {}",
                        missing.join(", ")
                    )),
                );
                checks.push(preflight_failed(
                    "windivert_assets",
                    PreflightSeverity::DegradeToVpnOnly,
                    "zapret",
                    format!(
                        "WinDivert/Flowseal support assets are missing: {}.",
                        missing.join(", ")
                    ),
                    "Repair zapret components; BadVpn can still start in VPN-only mode.",
                ));
            }
        }

        let managed_mihomo = self.component_store.mihomo_bin().ok();
        if !self.mihomo.is_running() {
            let mihomo_processes = running_process_details(&["mihomo.exe"]);
            for message in
                cleanup_stale_managed_mihomo_processes(&mihomo_processes, managed_mihomo.as_deref())
            {
                checks.push(PreflightCheck::new(
                    "stale_managed_mihomo_process",
                    PreflightSeverity::DiagnosticWarning,
                    "mihomo",
                    PreflightStatus::Warning,
                    message.clone(),
                    Some(
                        "BadVpn cleaned up a stale managed mihomo.exe before starting.".to_string(),
                    ),
                ));
                self.snapshot.diagnostics.push(message);
            }
        }

        for (id, port) in [
            ("mihomo_mixed_port", request.settings.mihomo.mixed_port),
            (
                "mihomo_controller_port",
                request.settings.mihomo.controller_port,
            ),
        ] {
            if tcp_port_is_busy(port) {
                checks.push(preflight_failed(
                    id,
                    PreflightSeverity::BlockVpn,
                    "mihomo",
                    format!("Mihomo TCP port {port} is already occupied."),
                    "Stop the other Clash/Mihomo client or change BadVpn ports.",
                ));
            }
        }
        if tcp_port_is_busy(BADVPN_DNS_PORT) || udp_port_is_busy(BADVPN_DNS_PORT) {
            checks.push(preflight_failed(
                "mihomo_dns_port",
                PreflightSeverity::BlockVpn,
                "mihomo",
                format!("BadVpn DNS port {BADVPN_DNS_PORT} is already occupied."),
                "Stop the other DNS/TUN client before connecting BadVpn.",
            ));
        }

        let vpn_process_names = [
            "mihomo.exe",
            "clash.exe",
            "clash-meta.exe",
            "sing-box.exe",
            "v2rayn.exe",
        ];
        let vpn_processes = running_process_details(&vpn_process_names);
        let external_vpn = if vpn_processes.is_empty() {
            running_process_names(&vpn_process_names)
        } else {
            vpn_processes
                .iter()
                .filter(|process| !process_is_managed_mihomo(process, managed_mihomo.as_deref()))
                .map(process_label)
                .collect::<Vec<_>>()
        };
        if !external_vpn.is_empty() && !self.mihomo.is_running() {
            checks.push(preflight_failed(
                "external_vpn_core",
                PreflightSeverity::BlockVpn,
                "mihomo",
                format!(
                    "External VPN/TUN process is already running: {}.",
                    external_vpn.join(", ")
                ),
                "Stop external Clash/Mihomo/sing-box/v2rayN clients before connecting BadVpn.",
            ));
        }

        if request.settings.mihomo.tun_enabled && stale_badvpn_tun_adapter_present() {
            checks.push(PreflightCheck::new(
                "stale_badvpn_tun_adapter",
                PreflightSeverity::DiagnosticWarning,
                "mihomo",
                PreflightStatus::Warning,
                "A BadVpn TUN adapter is already present before runtime start.",
                Some(
                    "If connection fails, disconnect other clients or reboot to clear stale TUN state."
                        .to_string(),
                ),
            ));
        }

        if request.route_mode == RuntimeMode::Smart
            && request.settings.zapret.enabled
            && !self.zapret.is_running()
        {
            let zapret_processes = running_process_details(&["winws.exe", "goodbyedpi.exe"]);
            let managed_winws = self.component_store.winws_bin().ok();
            let (mut external_zapret, stale_cleanup_messages) =
                classify_zapret_preflight_processes(&zapret_processes, managed_winws.as_deref());

            if zapret_processes.is_empty() {
                external_zapret = running_process_names(&["winws.exe", "goodbyedpi.exe"]);
            }

            for message in stale_cleanup_messages {
                checks.push(PreflightCheck::new(
                    "stale_managed_zapret_process",
                    PreflightSeverity::DiagnosticWarning,
                    "zapret",
                    PreflightStatus::Warning,
                    message.clone(),
                    Some(
                        "BadVpn cleaned up a stale managed winws process before starting Smart."
                            .to_string(),
                    ),
                ));
                self.snapshot.diagnostics.push(message);
            }

            if !external_zapret.is_empty() {
                checks.push(preflight_failed(
                    "external_zapret",
                    PreflightSeverity::DegradeToVpnOnly,
                    "zapret",
                    format!(
                        "External DPI bypass process is already running: {}.",
                        external_zapret.join(", ")
                    ),
                    "Stop external zapret/GoodbyeDPI or run BadVpn in VPN-only fallback.",
                ));
            }
        }

        self.snapshot.preflight = checks;
        for check in &self.snapshot.preflight {
            if check.status != PreflightStatus::Passed {
                self.snapshot.diagnostics.push(format!(
                    "{} preflight {}: {}",
                    check.component, check.id, check.message
                ));
            }
        }

        if self.snapshot.preflight.iter().any(|check| {
            check.status == PreflightStatus::Failed && check.severity == PreflightSeverity::BlockVpn
        }) {
            self.snapshot.mihomo = RuntimeComponentSnapshot::new(
                RuntimeComponentState::Conflict,
                Some("Mihomo preflight found blocking conflicts.".to_string()),
            );
            return Err(anyhow!("{}", self.preflight_summary()));
        }
        Ok(PreflightDecision {
            force_vpn_only: self.snapshot.preflight.iter().any(|check| {
                check.status == PreflightStatus::Failed
                    && check.severity == PreflightSeverity::DegradeToVpnOnly
            }),
        })
    }

    fn build_runtime_config(
        &self,
        request: &ConnectRequest,
        mode: RuntimeMode,
    ) -> Result<RuntimeConfig> {
        self.build_runtime_config_with_secret(
            request,
            mode,
            badvpn_common::generate_controller_secret().map_err(|error| anyhow!(error))?,
        )
    }

    fn build_runtime_config_with_secret(
        &self,
        request: &ConnectRequest,
        mode: RuntimeMode,
        secret: String,
    ) -> Result<RuntimeConfig> {
        let mut options = request.settings.mihomo.clone();
        options.route_mode = mode.as_route_mode();
        options.selected_proxies = request.selected_proxies.clone();
        if mode == RuntimeMode::VpnOnly {
            options.zapret_direct_domains.clear();
            options.zapret_direct_cidrs.clear();
            options.zapret_direct_processes.clear();
            options.zapret_direct_tcp_ports.clear();
            options.zapret_direct_udp_ports.clear();
        }
        let generated = generate_mihomo_config_from_subscription_with_options(
            &request.profile_body,
            &secret,
            &options,
        )
        .map_err(|error| anyhow!(error))?;
        Ok(RuntimeConfig {
            secret,
            yaml: generated.yaml,
            config_id: format!("{:?}-{}-{}", mode, generated.proxy_count, now_unix()),
            policy: generated.policy,
        })
    }

    fn prepare_runtime_config_for_local_mihomo(
        &mut self,
        config: &mut RuntimeConfig,
    ) -> Result<()> {
        let home = self.config_store.home_dir();
        let geosite_available =
            badvpn_common::geodata_asset_exists(home, &["GeoSite.dat", "geosite.dat"]);
        let geoip_available =
            badvpn_common::geodata_asset_exists(home, &["GeoIP.dat", "geoip.dat"]);
        let messages = badvpn_common::strip_missing_geodata_rules(
            &mut config.yaml,
            geosite_available,
            geoip_available,
        )
        .map_err(|error| anyhow!(error))?;
        let (provider_messages, disabled_providers) = prepare_cached_rule_providers(
            &mut config.yaml,
            home,
            geosite_available,
            geoip_available,
        )?;
        if !messages.is_empty() {
            sync_policy_after_missing_geodata_strip(
                &mut config.policy,
                geosite_available,
                geoip_available,
            )?;
        }
        if !disabled_providers.is_empty() {
            sync_policy_after_rule_provider_strip(&mut config.policy, &disabled_providers)?;
        }
        for message in messages {
            tracing::warn!(message, "mihomo geodata rule disabled");
            self.snapshot.diagnostics.push(message);
        }
        for message in provider_messages {
            tracing::warn!(message, "mihomo provider geodata rule disabled");
            self.snapshot.diagnostics.push(message);
        }
        Ok(())
    }

    fn record_policy_diagnostics(&mut self, policy: &CompiledPolicy) {
        self.snapshot.diagnostics.push(format!(
            "Policy compiled: mode={:?} main_proxy_group={} rules={} suppressed={}",
            policy.mode,
            policy.main_proxy_group,
            policy.mihomo_rules.len(),
            policy.suppressed_rules.len()
        ));

        if !policy.suppressed_rules.is_empty() {
            let sample_count = policy
                .suppressed_rules
                .len()
                .min(POLICY_DIAGNOSTIC_SAMPLE_LIMIT);
            self.snapshot.diagnostics.push(format!(
                "Policy overrides: total={} samples={} raw provider rule values omitted from runtime diagnostics",
                policy.suppressed_rules.len(),
                sample_count
            ));
            for (index, suppressed) in policy
                .suppressed_rules
                .iter()
                .take(sample_count)
                .enumerate()
            {
                self.snapshot.diagnostics.push(format!(
                    "Policy override sample {}: original_kind={} chosen_kind={} reason={}",
                    index + 1,
                    diagnostic_rule_kind(&suppressed.original_rule),
                    diagnostic_rule_kind(&suppressed.chosen_rule),
                    suppressed.reason
                ));
            }
        }

        let message_count = policy.diagnostics_messages.len();
        for message in policy
            .diagnostics_messages
            .iter()
            .take(POLICY_DIAGNOSTIC_SAMPLE_LIMIT)
        {
            self.snapshot
                .diagnostics
                .push(format!("Policy warning: {message}"));
        }
        if message_count > POLICY_DIAGNOSTIC_SAMPLE_LIMIT {
            self.snapshot.diagnostics.push(format!(
                "Policy warnings truncated: shown={} total={}",
                POLICY_DIAGNOSTIC_SAMPLE_LIMIT, message_count
            ));
        }

        let zapret_expectations = policy
            .diagnostics_expectations
            .iter()
            .filter(|expectation| expectation.expected_zapret)
            .count();
        self.snapshot.diagnostics.push(format!(
            "Policy expectations: total={} zapret_expected={} non_zapret_expected={}",
            policy.diagnostics_expectations.len(),
            zapret_expectations,
            policy
                .diagnostics_expectations
                .len()
                .saturating_sub(zapret_expectations)
        ));
    }

    fn write_zapret_lists_best_effort(&mut self, policy: &CompiledPolicy, context: &str) {
        if let Err(error) = write_compiled_zapret_lists(&self.component_store, policy) {
            tracing::warn!(%error, context, "failed to update zapret policy lists");
            self.snapshot.diagnostics.push(format!(
                "zapret policy list cleanup warning during {context}: {error}"
            ));
        }
    }

    fn set_error(&mut self, message: String) {
        tracing::error!(message, "runtime entered error state");
        self.snapshot.phase = RuntimePhase::Error;
        self.snapshot.last_error = Some(message.clone());
        self.snapshot
            .diagnostics
            .push(format!("Runtime error: {message}"));
        self.active_policy = None;
        self.snapshot.active_config_id = None;
        self.refresh_process_state();
    }

    fn handle_late_mihomo_death(&mut self) {
        if !matches!(
            self.snapshot.phase,
            RuntimePhase::Running | RuntimePhase::DegradedVpnOnly
        ) || self.snapshot.mihomo.state == RuntimeComponentState::Running
        {
            return;
        }

        let detail = self
            .snapshot
            .mihomo
            .detail
            .clone()
            .unwrap_or_else(|| "Mihomo is no longer running.".to_string());
        if let Err(error) = self.zapret.stop() {
            self.snapshot
                .diagnostics
                .push(format!("Failed to stop winws after Mihomo exited: {error}"));
        }
        self.refresh_process_state();
        self.set_error(format!(
            "Mihomo stopped unexpectedly; VPN routing is no longer active. {detail} Reconnect to restore the connection."
        ));
    }

    fn preflight_summary(&self) -> String {
        let messages = self
            .snapshot
            .preflight
            .iter()
            .filter(|check| check.status == PreflightStatus::Failed)
            .map(|check| check.message.as_str())
            .collect::<Vec<_>>();
        if messages.is_empty() {
            "Runtime preflight failed.".to_string()
        } else {
            messages.join(" ")
        }
    }

    fn refresh_process_state(&mut self) {
        let mihomo_running = self.mihomo.is_running();
        self.snapshot.mihomo = if mihomo_running {
            RuntimeComponentSnapshot::new(
                RuntimeComponentState::Running,
                self.snapshot.mihomo.detail.clone(),
            )
        } else {
            RuntimeComponentSnapshot::new(
                RuntimeComponentState::Stopped,
                stopped_component_detail(&self.snapshot.mihomo, self.mihomo.last_exit_detail()),
            )
        };
        let zapret_running = self.zapret.is_running();
        self.snapshot.zapret = if zapret_running {
            RuntimeComponentSnapshot::new(
                RuntimeComponentState::Running,
                self.snapshot.zapret.detail.clone(),
            )
        } else {
            RuntimeComponentSnapshot::new(
                RuntimeComponentState::Stopped,
                stopped_component_detail(&self.snapshot.zapret, self.zapret.last_exit_detail()),
            )
        };
    }

    fn late_zapret_death_requires_fallback(&self) -> bool {
        self.snapshot.effective_mode == RuntimeMode::Smart
            && self.snapshot.mihomo.state == RuntimeComponentState::Running
            && self.snapshot.zapret.state != RuntimeComponentState::Running
    }

    async fn fallback_to_vpn_only_after_late_zapret_death(&mut self) -> Result<()> {
        let request = self
            .last_request
            .clone()
            .context("Connect request is required for late zapret fallback")?;
        let mihomo_bin = self.component_store.mihomo_bin()?;
        let secret = self.config_store.controller_secret().unwrap_or_default();
        self.snapshot.diagnostics.push(
            "Smart requires zapret, but winws is not running; reloading Mihomo in VPN-only fallback."
                .to_string(),
        );

        let mut fallback =
            self.build_runtime_config_with_secret(&request, RuntimeMode::VpnOnly, secret.clone())?;
        self.prepare_runtime_config_for_local_mihomo(&mut fallback)?;
        ensure_vpn_only_fallback_policy(&fallback.policy)
            .context("late zapret VPN-only fallback policy violated invariants")?;
        self.write_zapret_lists_best_effort(&fallback.policy, "late zapret VPN-only fallback");
        self.record_policy_diagnostics(&fallback.policy);
        let fallback_draft = self.config_store.write_draft(&fallback.yaml)?;
        self.mihomo
            .validate(&mihomo_bin, &fallback_draft, self.config_store.home_dir())
            .context("Mihomo rejected late zapret VPN-only fallback config")?;
        let fallback_run = self.config_store.promote_draft_to_run(&fallback_draft)?;
        if let Err(reload_error) = self
            .mihomo
            .reload(
                fallback_run.as_path(),
                request.settings.mihomo.controller_port,
                &secret,
            )
            .await
        {
            self.snapshot.diagnostics.push(format!(
                "Mihomo reload failed during late zapret fallback; restarting: {reload_error}"
            ));
            let _ = self.mihomo.stop();
            if let Err(start_error) = self.mihomo.start(
                &mihomo_bin,
                &fallback_run,
                self.config_store.home_dir(),
                request.settings.mihomo.controller_port,
            ) {
                let _ = self.config_store.rollback_run();
                let _ = self.zapret.stop();
                return Err(anyhow!(
                    "Mihomo restart failed during late zapret fallback: {start_error}"
                ));
            }
            if let Err(ready_error) = self
                .mihomo
                .wait_ready(
                    request.settings.mihomo.controller_port,
                    MIHOMO_READY_TIMEOUT,
                    &secret,
                )
                .await
            {
                let _ = self.mihomo.stop();
                let _ = self.config_store.rollback_run();
                let _ = self.zapret.stop();
                return Err(anyhow!(
                    "Mihomo controller did not recover during late zapret fallback: {ready_error}"
                ));
            }
        }

        if let Err(close_error) = self
            .mihomo
            .close_connections(request.settings.mihomo.controller_port, &secret)
            .await
        {
            self.snapshot.diagnostics.push(format!(
                "Mihomo connection cleanup warning after late zapret fallback: {close_error}"
            ));
        }
        let _ = self.zapret.stop();
        self.config_store.commit_last_working()?;
        self.snapshot.phase = RuntimePhase::DegradedVpnOnly;
        self.snapshot.effective_mode = RuntimeMode::VpnOnly;
        self.snapshot.mihomo = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Running,
            Some(format!(
                "Mihomo is running with VPN-only fallback on {}",
                fallback_run.display()
            )),
        );
        self.snapshot.zapret = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Unhealthy,
            Some("winws stopped after Smart start; VPN-only fallback is active".to_string()),
        );
        self.snapshot.windivert = RuntimeComponentSnapshot::default();
        self.snapshot.active_config_id = Some(fallback.config_id);
        self.snapshot.last_error = None;
        self.active_policy = Some(fallback.policy.clone());
        if let Err(error) = self.config_store.write_policy_summary(&fallback.policy) {
            tracing::warn!(%error, "failed to write late zapret fallback policy summary JSON");
        }
        Ok(())
    }

    fn record_late_zapret_death_if_needed(&mut self) {
        if self.snapshot.effective_mode != RuntimeMode::Smart
            || self.snapshot.mihomo.state != RuntimeComponentState::Running
            || self.snapshot.zapret.state == RuntimeComponentState::Running
        {
            return;
        }
        const MESSAGE: &str = "Smart requires zapret, but winws is not running.";
        if !self
            .snapshot
            .diagnostics
            .iter()
            .any(|message| message == MESSAGE)
        {
            self.snapshot.diagnostics.push(MESSAGE.to_string());
        }
        self.snapshot.zapret = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Stopped,
            Some(match self.zapret.last_exit_detail() {
                Some(detail) => format!("{MESSAGE} {detail}"),
                None => MESSAGE.to_string(),
            }),
        );
    }

    fn last_controller_port(&self) -> u16 {
        self.last_request
            .as_ref()
            .map(|request| request.settings.mihomo.controller_port)
            .unwrap_or(9090)
    }

    pub async fn select_proxy(&mut self, group: &str, proxy: &str) -> Result<AgentRuntimeSnapshot> {
        if group.is_empty() || proxy.is_empty() {
            return Err(anyhow!("proxy group and proxy name are required"));
        }
        self.refresh_process_state();
        self.handle_late_mihomo_death();
        if self.snapshot.mihomo.state != RuntimeComponentState::Running {
            return Err(anyhow!(
                "Mihomo is not running; reconnect before selecting a proxy"
            ));
        }

        let controller_port = self.last_controller_port();
        let secret = self.config_store.controller_secret().unwrap_or_default();
        let client = reqwest::Client::builder()
            .timeout(MIHOMO_CONTROLLER_REQUEST_TIMEOUT)
            .build()?;
        let base = format!("http://{LOCALHOST}:{controller_port}");
        let mut list_request = client.get(format!("{base}/proxies"));
        if !secret.is_empty() {
            list_request = list_request.bearer_auth(&secret);
        }
        let list_response = list_request
            .send()
            .await
            .context("failed to read active Mihomo proxy groups")?;
        let list_status = list_response.status();
        if !list_status.is_success() {
            return Err(anyhow!("Mihomo proxy catalog returned HTTP {list_status}"));
        }
        let catalog = list_response
            .json::<serde_json::Value>()
            .await
            .context("failed to decode active Mihomo proxy groups")?;
        validate_active_proxy_selection(&catalog, group, proxy)?;

        let mut url = reqwest::Url::parse(&format!("{base}/proxies/"))?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("Mihomo controller URL cannot contain path segments"))?
            .pop_if_empty()
            .push(group);
        let mut select_request = client.put(url).json(&serde_json::json!({ "name": proxy }));
        if !secret.is_empty() {
            select_request = select_request.bearer_auth(&secret);
        }
        let response = select_request
            .send()
            .await
            .context("failed to send Mihomo proxy selection")?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            let detail = detail.trim().chars().take(512).collect::<String>();
            return Err(if detail.is_empty() {
                anyhow!("Mihomo rejected proxy selection with HTTP {status}")
            } else {
                anyhow!("Mihomo rejected proxy selection with HTTP {status}: {detail}")
            });
        }
        self.remember_proxy_selection(group, proxy);
        self.snapshot
            .diagnostics
            .push(format!("Selected a new proxy in Mihomo group '{group}'."));
        Ok(self.snapshot.clone())
    }

    fn remember_proxy_selection(&mut self, group: &str, proxy: &str) {
        if let Some(request) = self.last_request.as_mut() {
            request
                .selected_proxies
                .insert(group.to_string(), proxy.to_string());
        }
    }
}

fn validate_active_proxy_selection(
    catalog: &serde_json::Value,
    group: &str,
    proxy: &str,
) -> Result<()> {
    let state = catalog
        .get("proxies")
        .and_then(serde_json::Value::as_object)
        .and_then(|proxies| proxies.get(group))
        .ok_or_else(|| {
            anyhow!(
                "Proxy group '{group}' is not present in the active Mihomo runtime; refresh the server list or reconnect"
            )
        })?;
    if state
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("selector"))
    {
        return Err(anyhow!(
            "Proxy group '{group}' is not selectable in the active Mihomo runtime"
        ));
    }
    if let Some(members) = state.get("all").and_then(serde_json::Value::as_array) {
        if !members
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|member| member == proxy)
        {
            return Err(anyhow!(
                "Proxy '{proxy}' is not a member of active Mihomo group '{group}'; refresh the server list"
            ));
        }
    }
    Ok(())
}

fn stopped_component_detail(
    current: &RuntimeComponentSnapshot,
    last_exit_detail: Option<&str>,
) -> Option<String> {
    last_exit_detail.map(ToOwned::to_owned).or_else(|| {
        matches!(
            current.state,
            RuntimeComponentState::Stopped
                | RuntimeComponentState::Unhealthy
                | RuntimeComponentState::Missing
        )
        .then(|| current.detail.clone())
        .flatten()
    })
}

fn diagnostic_rule_kind(rule: &str) -> String {
    rule.split(',')
        .next()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .map(|kind| kind.to_ascii_uppercase())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

impl Default for RuntimeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct RuntimeConfig {
    secret: String,
    yaml: String,
    config_id: String,
    policy: CompiledPolicy,
}

#[derive(Debug)]
struct StartupTimeline {
    started: Instant,
    last_mark: Instant,
    stages: Vec<(&'static str, u128)>,
}

impl StartupTimeline {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last_mark: now,
            stages: Vec::new(),
        }
    }

    fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        self.stages
            .push((name, now.duration_since(self.last_mark).as_millis()));
        self.last_mark = now;
    }

    fn summary(&self) -> String {
        let mut parts = self
            .stages
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        parts.push(format!(
            "total_connect_ms={}",
            self.started.elapsed().as_millis()
        ));
        format!("Startup timeline: {}", parts.join(" "))
    }
}

#[derive(Debug, Default)]
struct GameBypassPlan {
    diagnostics: Vec<String>,
}

#[derive(Debug)]
struct GameOverlayLists {
    hostlist: PathBuf,
    ipset: PathBuf,
    ipset_exclude: PathBuf,
    has_hosts: bool,
    has_cidrs: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct PreflightDecision {
    force_vpn_only: bool,
}

#[derive(Debug, Clone)]
struct RuntimeConfigStore {
    root: PathBuf,
}

impl RuntimeConfigStore {
    fn root_dir() -> PathBuf {
        runtime_root_dir().join("mihomo")
    }

    fn home_dir(&self) -> &Path {
        &self.root
    }

    fn draft_path(&self) -> PathBuf {
        self.root.join("draft.yaml")
    }

    fn run_path(&self) -> PathBuf {
        self.root.join("config.yaml")
    }

    fn last_working_path(&self) -> PathBuf {
        self.root.join("last-working.yaml")
    }

    fn policy_summary_path(&self) -> PathBuf {
        self.root.join("policy-summary.json")
    }

    fn write_policy_summary(&self, policy: &CompiledPolicy) -> Result<()> {
        let mut response: badvpn_common::ipc::PolicySummaryResponse = policy.into();
        response.source = "agent_runtime".to_string();
        let json = serde_json::to_string_pretty(&response)?;
        fs::create_dir_all(&self.root)?;
        write_file_atomically(&self.policy_summary_path(), &json)?;
        Ok(())
    }

    fn write_draft(&self, content: &str) -> Result<PathBuf> {
        fs::create_dir_all(&self.root)?;
        let path = self.draft_path();
        write_file_atomically(&path, content)?;
        Ok(path)
    }

    fn promote_draft_to_run(&self, draft_path: &Path) -> Result<PathBuf> {
        fs::create_dir_all(&self.root)?;
        let run_path = self.run_path();
        if run_path.exists() {
            fs::copy(&run_path, self.last_working_path())?;
        }
        fs::copy(draft_path, &run_path)?;
        Ok(run_path)
    }

    fn commit_last_working(&self) -> Result<()> {
        let run_path = self.run_path();
        if run_path.exists() {
            fs::copy(run_path, self.last_working_path())?;
        }
        Ok(())
    }

    fn rollback_run(&self) -> Result<()> {
        let last_working = self.last_working_path();
        if last_working.exists() {
            fs::copy(last_working, self.run_path())?;
        }
        Ok(())
    }

    fn controller_secret(&self) -> Option<String> {
        let content = fs::read_to_string(self.run_path()).ok()?;
        let yaml = serde_yaml::from_str::<YamlValue>(&content).ok()?;
        yaml.get("secret")
            .and_then(YamlValue::as_str)
            .map(ToOwned::to_owned)
    }
}

impl Default for RuntimeConfigStore {
    fn default() -> Self {
        Self {
            root: Self::root_dir(),
        }
    }
}

#[derive(Debug, Clone)]
struct ComponentStore {
    root: PathBuf,
    appdata_fallback: Option<PathBuf>,
}

impl ComponentStore {
    fn mihomo_bin(&self) -> Result<PathBuf> {
        if let Some(path) = env_existing_file("BADVPN_MIHOMO_BIN") {
            return Ok(path);
        }
        self.first_existing_file(&["mihomo", "mihomo.exe"])
            .ok_or_else(|| anyhow!("Mihomo binary was not found."))
    }

    fn winws_bin(&self) -> Result<PathBuf> {
        if let Some(path) = env_existing_file("BADVPN_WINWS_BIN") {
            return Ok(path);
        }
        self.first_existing_file(&["zapret", "bin", "winws.exe"])
            .ok_or_else(|| anyhow!("zapret/winws binary was not found."))
    }

    fn missing_zapret_runtime_assets(&self) -> Vec<String> {
        let bin = self.zapret_bin_dir();
        [
            "WinDivert.dll",
            "WinDivert64.sys",
            "cygwin1.dll",
            "quic_initial_www_google_com.bin",
            "tls_clienthello_www_google_com.bin",
        ]
        .into_iter()
        .filter_map(|name| {
            let path = bin.join(name);
            if path.exists() {
                None
            } else {
                Some(path.display().to_string())
            }
        })
        .collect()
    }

    fn zapret_root(&self) -> PathBuf {
        self.root.join("zapret")
    }

    fn zapret_bin_dir(&self) -> PathBuf {
        self.zapret_root().join("bin")
    }

    fn zapret_lists_dir(&self) -> PathBuf {
        self.zapret_root().join("lists")
    }

    fn zapret_profiles_dir(&self) -> PathBuf {
        self.zapret_root().join("profiles")
    }

    fn zapret_profile_path(&self, file_name: &str) -> PathBuf {
        let root_profile = self.zapret_root().join(file_name);
        if root_profile.exists() {
            root_profile
        } else {
            self.zapret_profiles_dir().join(file_name)
        }
    }

    fn first_existing_file(&self, parts: &[&str]) -> Option<PathBuf> {
        let candidate = parts
            .iter()
            .fold(self.root.clone(), |path, part| path.join(part));
        if candidate.exists() {
            return Some(candidate);
        }
        let fallback = self.appdata_fallback.as_ref()?;
        let candidate = parts
            .iter()
            .fold(fallback.clone(), |path, part| path.join(part));
        candidate.exists().then_some(candidate)
    }
}

impl Default for ComponentStore {
    fn default() -> Self {
        let root = runtime_root_dir().join("components");
        let appdata_fallback = appdata_root_dir().map(|path| path.join("components"));
        Self {
            root,
            appdata_fallback,
        }
    }
}

#[derive(Debug, Default)]
struct MihomoManager {
    child: Option<Child>,
    last_exit_detail: Option<String>,
}

impl MihomoManager {
    fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.last_exit_detail =
                        Some(format!("Mihomo exited unexpectedly with {status}"));
                    self.child = None;
                    false
                }
                Ok(None) => true,
                Err(error) => {
                    self.last_exit_detail = Some(format!("Mihomo state check failed: {error}"));
                    // Keep reporting running until stop/kill clears the child; a transient
                    // try_wait error must not orphan the handle while claiming stopped.
                    true
                }
            }
        } else {
            false
        }
    }

    fn last_exit_detail(&self) -> Option<&str> {
        self.last_exit_detail.as_deref()
    }

    fn validate(&self, mihomo_bin: &Path, config_path: &Path, home_dir: &Path) -> Result<()> {
        tracing::debug!(
            mihomo = %mihomo_bin.display(),
            config = %config_path.display(),
            home = %home_dir.display(),
            "validating Mihomo config"
        );
        let mut child = Command::new(mihomo_bin)
            .arg("-t")
            .arg("-d")
            .arg(home_dir)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to run {}", mihomo_bin.display()))?;
        let stdout_reader = child.stdout.take().map(read_output_pipe);
        let stderr_reader = child.stderr.take().map(read_output_pipe);
        let started = Instant::now();
        let timed_out;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                timed_out = false;
                break status;
            }
            if started.elapsed() >= MIHOMO_VALIDATE_TIMEOUT {
                let _ = child.kill();
                timed_out = true;
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stdout = join_output_reader(stdout_reader)?;
        let stderr = join_output_reader(stderr_reader)?;
        if timed_out {
            return Err(anyhow!(
                "Mihomo config validation timed out after {}s{}{}",
                MIHOMO_VALIDATE_TIMEOUT.as_secs(),
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ));
        }
        if status.success() {
            tracing::debug!("Mihomo config validation succeeded");
            Ok(())
        } else {
            tracing::warn!(
                status = %status,
                "Mihomo config validation failed"
            );
            Err(anyhow!(
                "{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ))
        }
    }

    fn start(
        &mut self,
        mihomo_bin: &Path,
        config_path: &Path,
        home_dir: &Path,
        controller_port: u16,
    ) -> Result<()> {
        if self.is_running() {
            tracing::debug!("Mihomo start skipped because owned child is already running");
            return Ok(());
        }
        tracing::info!(
            mihomo = %mihomo_bin.display(),
            config = %config_path.display(),
            home = %home_dir.display(),
            controller_port,
            "starting Mihomo child"
        );
        let mut child = Command::new(mihomo_bin)
            .arg("-d")
            .arg(home_dir)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(log_stdio("mihomo.log")?)
            .stderr(log_stdio("mihomo.log")?)
            .spawn()
            .with_context(|| format!("failed to start {}", mihomo_bin.display()))?;
        std::thread::sleep(Duration::from_millis(350));
        if let Some(status) = child.try_wait()? {
            self.last_exit_detail = Some(format!("Mihomo exited immediately with {status}"));
            tracing::error!(%status, controller_port, "Mihomo exited immediately");
            return Err(anyhow!(
                "Mihomo exited immediately with {status}; controller port {controller_port}"
            ));
        }
        tracing::info!(pid = child.id(), "Mihomo child started");
        self.last_exit_detail = None;
        self.child = Some(child);
        Ok(())
    }

    async fn wait_ready(
        &self,
        controller_port: u16,
        timeout: Duration,
        secret: &str,
    ) -> Result<()> {
        tracing::debug!(controller_port, ?timeout, "waiting for Mihomo controller");
        let client = reqwest::Client::builder()
            .timeout(MIHOMO_CONTROLLER_REQUEST_TIMEOUT)
            .build()?;
        let started = SystemTime::now();
        loop {
            let mut request = client.get(format!("http://{LOCALHOST}:{controller_port}/version"));
            if !secret.is_empty() {
                request = request.bearer_auth(secret);
            }
            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    tracing::info!(controller_port, "Mihomo controller is ready");
                    return Ok(());
                }
                Ok(response) => {
                    if started.elapsed().unwrap_or(timeout) >= timeout {
                        tracing::warn!(
                            controller_port,
                            status = %response.status(),
                            "Mihomo controller readiness timed out with HTTP response"
                        );
                        return Err(anyhow!(
                            "Mihomo controller returned HTTP {}",
                            response.status()
                        ));
                    }
                }
                Err(error) => {
                    if started.elapsed().unwrap_or(timeout) >= timeout {
                        tracing::warn!(
                            controller_port,
                            %error,
                            "Mihomo controller readiness timed out"
                        );
                        return Err(anyhow!(
                            "Mihomo local controller did not become ready: {error}"
                        ));
                    }
                }
            }
            sleep(Duration::from_millis(350)).await;
        }
    }

    async fn reload(&self, config_path: &Path, controller_port: u16, secret: &str) -> Result<()> {
        tracing::info!(
            config = %config_path.display(),
            controller_port,
            "reloading Mihomo config"
        );
        let client = reqwest::Client::builder()
            .timeout(MIHOMO_CONTROLLER_REQUEST_TIMEOUT)
            .build()?;
        let mut request = client
            .put(format!(
                "http://{LOCALHOST}:{controller_port}/configs?force=true"
            ))
            .json(&serde_json::json!({
                "path": config_path.to_string_lossy(),
                "payload": "",
            }));
        if !secret.is_empty() {
            request = request.bearer_auth(secret);
        }
        let response = request.send().await?;
        if response.status().is_success() {
            tracing::info!(controller_port, "Mihomo config reload succeeded");
            Ok(())
        } else {
            tracing::warn!(
                controller_port,
                status = %response.status(),
                "Mihomo config reload failed"
            );
            Err(anyhow!("Mihomo reload returned HTTP {}", response.status()))
        }
    }

    async fn verify_proxy_egress(
        &self,
        proxy_group: &str,
        controller_port: u16,
        secret: &str,
    ) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let mut failures = Vec::new();
        for attempt in 1..=2 {
            failures.clear();
            for test_url in [
                "https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
            ] {
                let url = mihomo_proxy_delay_url(controller_port, proxy_group, test_url, 3_500)?;
                let mut request = client.get(url);
                if !secret.is_empty() {
                    request = request.bearer_auth(secret);
                }
                match request.send().await {
                    Ok(response) if response.status().is_success() => {
                        tracing::info!(
                            proxy_group,
                            test_url,
                            attempt,
                            "Mihomo proxy egress verified"
                        );
                        return Ok(());
                    }
                    Ok(response) => {
                        let status = response.status();
                        let detail = response.text().await.unwrap_or_default();
                        let detail = detail.trim().chars().take(256).collect::<String>();
                        failures.push(if detail.is_empty() {
                            format!("{test_url} returned HTTP {status}")
                        } else {
                            format!("{test_url} returned HTTP {status}: {detail}")
                        });
                    }
                    Err(error) => failures.push(format!("{test_url} failed: {error}")),
                }
            }
            if attempt < 2 {
                sleep(Duration::from_millis(500)).await;
            }
        }
        Err(anyhow!(failures.join("; ")))
    }

    async fn close_connections(&self, controller_port: u16, secret: &str) -> Result<()> {
        tracing::debug!(controller_port, "closing Mihomo controller connections");
        let client = reqwest::Client::builder()
            .timeout(MIHOMO_CONTROLLER_REQUEST_TIMEOUT)
            .build()?;
        let mut request =
            client.delete(format!("http://{LOCALHOST}:{controller_port}/connections"));
        if !secret.is_empty() {
            request = request.bearer_auth(secret);
        }
        let _ = request.send().await?;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!(pid = child.id(), "stopping Mihomo child");
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!("Mihomo child stopped");
            self.last_exit_detail = None;
        } else {
            tracing::debug!("Mihomo stop skipped; no owned child");
        }
        Ok(())
    }
}

fn mihomo_proxy_delay_url(
    controller_port: u16,
    proxy_group: &str,
    test_url: &str,
    timeout_ms: u32,
) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(&format!("http://{LOCALHOST}:{controller_port}/proxies/"))?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("Mihomo controller URL cannot contain path segments"))?
        .pop_if_empty()
        .extend([proxy_group, "delay"]);
    url.query_pairs_mut()
        .append_pair("url", test_url)
        .append_pair("timeout", &timeout_ms.to_string())
        .append_pair("expected", "200-204");
    Ok(url)
}

fn read_output_pipe<R>(mut pipe: R) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut output = Vec::new();
        pipe.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn join_output_reader(
    reader: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| anyhow!("Mihomo validation output reader panicked"))?
            .context("failed to read Mihomo validation output"),
        None => Ok(Vec::new()),
    }
}

#[derive(Debug, Default)]
struct ZapretManager {
    child: Option<Child>,
    last_exit_detail: Option<String>,
}

impl ZapretManager {
    fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.last_exit_detail =
                        Some(format!("winws exited unexpectedly with {status}"));
                    self.child = None;
                    false
                }
                Ok(None) => true,
                Err(error) => {
                    self.last_exit_detail = Some(format!("winws state check failed: {error}"));
                    // Keep reporting running until stop/kill clears the child; a transient
                    // try_wait error must not orphan the handle while claiming stopped.
                    true
                }
            }
        } else {
            false
        }
    }

    fn last_exit_detail(&self) -> Option<&str> {
        self.last_exit_detail.as_deref()
    }

    fn start(
        &mut self,
        component_store: &ComponentStore,
        settings: &badvpn_common::RuntimeZapretSettings,
    ) -> Result<String> {
        self.stop()?;
        let winws = component_store.winws_bin()?;
        let attempts = zapret_strategy_attempt_order(settings);
        let mut errors = Vec::new();
        for strategy in attempts {
            let mut attempt_settings = settings.clone();
            attempt_settings.strategy = strategy.to_string();
            match self.spawn_with_strategy(component_store, &winws, &attempt_settings) {
                Ok(message) => {
                    if strategy != settings.strategy.as_str() {
                        return Ok(format!(
                            "{message}; auto-selected strategy={strategy} after selected profile failed"
                        ));
                    }
                    return Ok(message);
                }
                Err(error) => {
                    tracing::warn!(strategy, %error, "winws strategy attempt failed");
                    errors.push(format!("{strategy}: {error}"));
                }
            }
        }
        Err(anyhow!(
            "all zapret Flowseal profiles failed: {}",
            errors.join("; ")
        ))
    }

    fn spawn_with_strategy(
        &mut self,
        component_store: &ComponentStore,
        winws: &Path,
        settings: &badvpn_common::RuntimeZapretSettings,
    ) -> Result<String> {
        let args = build_winws_args(component_store, settings)?;
        tracing::info!(
            winws = %winws.display(),
            cwd = %component_store.zapret_bin_dir().display(),
            strategy = %settings.strategy,
            game_filter = %settings.game_filter,
            ipset_filter = %settings.ipset_filter,
            arg_count = args.len(),
            "starting winws child"
        );
        tracing::debug!(args = ?args, "winws arguments");
        let mut child = Command::new(winws)
            .current_dir(component_store.zapret_bin_dir())
            .args(&args)
            .stdin(Stdio::null())
            .stdout(log_stdio("winws.log")?)
            .stderr(log_stdio("winws.log")?)
            .spawn()
            .with_context(|| format!("failed to start {}", winws.display()))?;
        std::thread::sleep(Duration::from_millis(900));
        if let Some(status) = child.try_wait()? {
            self.last_exit_detail = Some(format!("winws exited immediately with {status}"));
            tracing::error!(%status, strategy = %settings.strategy, "winws exited immediately");
            return Err(anyhow!(
                "winws exited immediately with {status}; WinDivert may need service elevation or another DPI tool owns the driver"
            ));
        }
        tracing::info!(pid = child.id(), strategy = %settings.strategy, "winws child started");
        self.last_exit_detail = None;
        self.child = Some(child);
        Ok(format!(
            "winws started with profile={} ipset={} game={}",
            settings.strategy, settings.ipset_filter, settings.game_filter
        ))
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!(pid = child.id(), "stopping winws child");
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!("winws child stopped");
            self.last_exit_detail = None;
        } else {
            tracing::debug!("winws stop skipped; no owned child");
        }
        Ok(())
    }
}

fn build_winws_args(
    component_store: &ComponentStore,
    settings: &badvpn_common::RuntimeZapretSettings,
) -> Result<Vec<String>> {
    let lists = component_store.zapret_lists_dir();
    fs::create_dir_all(&lists)?;
    let list_general = ensure_list_file(
        &lists.join("list-general.txt"),
        badvpn_common::flowseal_general_hostlist(),
    )?;
    let list_google = ensure_list_file(
        &lists.join("list-google.txt"),
        badvpn_common::flowseal_google_hostlist(),
    )?;
    let list_exclude = ensure_list_file(
        &lists.join("list-exclude.txt"),
        badvpn_common::flowseal_exclude_hostlist(),
    )?;
    let ipset_exclude = ensure_list_file(
        &lists.join("ipset-exclude.txt"),
        badvpn_common::flowseal_ipset_exclude(),
    )?;
    let ipset_all = ensure_effective_ipset_all_file(&lists, settings)?;
    let game_overlay = write_game_overlay_lists(&lists, settings)?;
    ensure_empty_list_file(&lists.join("list-general-user.txt"))?;
    ensure_empty_list_file(&lists.join("list-exclude-user.txt"))?;
    ensure_empty_list_file(&lists.join("ipset-exclude-user.txt"))?;

    if let Ok(mut args) = parse_flowseal_profile_bat(component_store, settings) {
        rewrite_ipset_all_args(&mut args, &ipset_all);
        append_google_quic_hostlist_args(
            &mut args,
            &list_google,
            &list_exclude,
            &ipset_exclude,
            &component_store.zapret_bin_dir(),
        );
        append_game_overlay_winws_args(&mut args, &game_overlay, settings);
        return Ok(args);
    }

    let (game_tcp, game_udp) = game_filter_ports(&settings.game_filter);

    let bin = component_store.zapret_bin_dir();
    let fake_quic = bin.join("quic_initial_www_google_com.bin");
    let fake_tls = bin.join("tls_clienthello_www_google_com.bin");

    let mut args = vec![
        format!("--wf-tcp=80,443,2053,2083,2087,2096,8443,{game_tcp}"),
        format!("--wf-udp=443,19294-19344,50000-50100,{game_udp}"),
        "--filter-udp=443".to_string(),
        format!("--hostlist={}", list_general.display()),
        format!("--hostlist={}", list_google.display()),
        format!("--hostlist-exclude={}", list_exclude.display()),
        format!("--ipset-exclude={}", ipset_exclude.display()),
        "--dpi-desync=fake".to_string(),
        "--dpi-desync-repeats=6".to_string(),
    ];
    if fake_quic.exists() {
        args.push(format!("--dpi-desync-fake-quic={}", fake_quic.display()));
    }
    args.extend([
        "--new".to_string(),
        "--filter-tcp=80,443".to_string(),
        format!("--hostlist={}", list_general.display()),
        format!("--hostlist={}", list_google.display()),
        format!("--hostlist-exclude={}", list_exclude.display()),
        format!("--ipset-exclude={}", ipset_exclude.display()),
    ]);
    args.extend(desync_strategy_args(&settings.strategy));
    if fake_tls.exists() {
        args.push(format!(
            "--dpi-desync-split-seqovl-pattern={}",
            fake_tls.display()
        ));
        args.push(format!("--dpi-desync-fake-tls={}", fake_tls.display()));
    }
    if settings.ipset_filter == "loaded" {
        args.extend([
            "--new".to_string(),
            "--filter-udp=443".to_string(),
            format!("--ipset={}", ipset_all.display()),
            format!("--ipset-exclude={}", ipset_exclude.display()),
            "--dpi-desync=fake".to_string(),
            "--dpi-desync-repeats=6".to_string(),
        ]);
    }
    append_game_overlay_winws_args(&mut args, &game_overlay, settings);
    Ok(args)
}

fn parse_flowseal_profile_bat(
    component_store: &ComponentStore,
    settings: &badvpn_common::RuntimeZapretSettings,
) -> Result<Vec<String>> {
    let path =
        component_store.zapret_profile_path(flowseal_profile_bat_file_name(&settings.strategy));
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read Flowseal profile {}", path.display()))?;
    let mut command_line = extract_winws_command_from_bat(&content)
        .ok_or_else(|| anyhow!("{} does not contain a winws.exe command", path.display()))?;

    let (game_tcp, game_udp) = game_filter_ports(&settings.game_filter);
    command_line = replace_case_insensitive(&command_line, "%GameFilterTCP%", game_tcp);
    command_line = replace_case_insensitive(&command_line, "%GameFilterUDP%", game_udp);
    command_line = replace_case_insensitive(
        &command_line,
        "%GameFilter%",
        max_game_filter_port(game_tcp, game_udp),
    );
    command_line = replace_case_insensitive(
        &command_line,
        "%BIN%",
        &format!("{}\\", component_store.zapret_bin_dir().display()),
    );
    command_line = replace_case_insensitive(
        &command_line,
        "%LISTS%",
        &format!("{}\\", component_store.zapret_lists_dir().display()),
    );
    command_line = replace_case_insensitive(
        &command_line,
        "%~dp0bin\\",
        &format!("{}\\", component_store.zapret_bin_dir().display()),
    );
    command_line = replace_case_insensitive(
        &command_line,
        "%~dp0lists\\",
        &format!("{}\\", component_store.zapret_lists_dir().display()),
    );
    command_line = replace_case_insensitive(
        &command_line,
        "%~dp0",
        &format!("{}\\", component_store.zapret_root().display()),
    );

    let mut args = split_windows_command_line(&command_line)?;
    append_winws_filter_safety_args(&mut args);
    if args.is_empty() {
        return Err(anyhow!("{} generated no winws arguments", path.display()));
    }
    Ok(args)
}

fn flowseal_profile_bat_file_name(strategy: &str) -> &'static str {
    match strategy {
        "alt" => "general (ALT).bat",
        "alt2" => "general (ALT2).bat",
        "alt3" => "general (ALT3).bat",
        "alt4" => "general (ALT4).bat",
        "alt5" => "general (ALT5).bat",
        "alt6" => "general (ALT6).bat",
        "alt7" => "general (ALT7).bat",
        "alt8" => "general (ALT8).bat",
        "alt9" => "general (ALT9).bat",
        "alt10" => "general (ALT10).bat",
        "alt11" => "general (ALT11).bat",
        "fake_tls_auto" => "general (FAKE TLS AUTO).bat",
        "fake_tls_auto_alt" => "general (FAKE TLS AUTO ALT).bat",
        "fake_tls_auto_alt2" => "general (FAKE TLS AUTO ALT2).bat",
        "fake_tls_auto_alt3" => "general (FAKE TLS AUTO ALT3).bat",
        "simple_fake" => "general (SIMPLE FAKE).bat",
        "simple_fake_alt" => "general (SIMPLE FAKE ALT).bat",
        "simple_fake_alt2" => "general (SIMPLE FAKE ALT2).bat",
        _ => "general.bat",
    }
}

fn zapret_strategy_ids() -> &'static [&'static str] {
    &[
        "general",
        "alt",
        "alt2",
        "alt3",
        "alt4",
        "alt5",
        "alt6",
        "alt7",
        "alt8",
        "alt9",
        "alt10",
        "alt11",
        "fake_tls_auto",
        "fake_tls_auto_alt",
        "fake_tls_auto_alt2",
        "fake_tls_auto_alt3",
        "simple_fake",
        "simple_fake_alt",
        "simple_fake_alt2",
    ]
}

fn normalize_zapret_strategy(strategy: &str) -> &'static str {
    let trimmed = strategy.trim().to_ascii_lowercase();
    zapret_strategy_ids()
        .iter()
        .copied()
        .find(|id| *id == trimmed)
        .unwrap_or("general")
}

fn zapret_strategy_attempt_order(
    settings: &badvpn_common::RuntimeZapretSettings,
) -> Vec<&'static str> {
    let preferred = normalize_zapret_strategy(&settings.strategy);
    if !settings.auto_profile_fallback {
        return vec![preferred];
    }
    let mut order = vec![preferred];
    for strategy in zapret_strategy_ids() {
        if !order.contains(strategy) {
            order.push(*strategy);
        }
    }
    order
}

fn extract_winws_command_from_bat(content: &str) -> Option<String> {
    let mut captured = Vec::new();
    let mut active = false;
    for raw in content.lines() {
        let mut line = raw.trim().to_string();
        if line.is_empty()
            || line.starts_with("::")
            || line.to_ascii_lowercase().starts_with("rem ")
        {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("winws.exe") {
            active = true;
            if let Some(index) = lower.find("winws.exe") {
                line = line[index + "winws.exe".len()..].to_string();
            }
            line = line.trim_start_matches('"').trim().to_string();
        }
        if active {
            let continued = line.ends_with('^');
            if continued {
                line.pop();
            }
            captured.push(line.trim().to_string());
            if !continued {
                break;
            }
        }
    }
    let joined = captured
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.trim().is_empty()).then_some(joined)
}

fn replace_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut out = String::new();
    let mut cursor = 0;
    while let Some(relative) = lower_input[cursor..].find(&lower_needle) {
        let index = cursor + relative;
        out.push_str(&input[cursor..index]);
        out.push_str(replacement);
        cursor = index + needle.len();
    }
    out.push_str(&input[cursor..]);
    out
}

fn split_windows_command_line(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '^' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ch if ch.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if in_quotes {
        return Err(anyhow!("Flowseal BAT command has an unclosed quote"));
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn append_winws_filter_safety_args(args: &mut Vec<String>) {
    if !args.iter().any(|arg| arg.starts_with("--wf-filter-lan")) {
        args.push("--wf-filter-lan=1".to_string());
    }
    if !args.iter().any(|arg| arg.starts_with("--wf-l3")) {
        args.push("--wf-l3=ipv4,ipv6".to_string());
    }
}

fn max_game_filter_port(tcp: &str, udp: &str) -> &'static str {
    if tcp == "1024-65535" || udp == "1024-65535" {
        "1024-65535"
    } else {
        "12"
    }
}

fn desync_strategy_args(strategy: &str) -> Vec<String> {
    match strategy {
        "alt" => vec![
            "--dpi-desync=fake,fakedsplit".to_string(),
            "--dpi-desync-fooling=ts".to_string(),
            "--dpi-desync-fakedsplit-pattern=0x00".to_string(),
        ],
        "alt2" => vec![
            "--dpi-desync=multisplit".to_string(),
            "--dpi-desync-split-seqovl=652".to_string(),
            "--dpi-desync-split-pos=2".to_string(),
        ],
        _ => vec![
            "--dpi-desync=multisplit".to_string(),
            "--dpi-desync-split-seqovl=681".to_string(),
            "--dpi-desync-split-pos=1".to_string(),
        ],
    }
}

fn game_filter_ports(mode: &str) -> (&'static str, &'static str) {
    match mode {
        "tcp_udp" => ("1024-65535", "1024-65535"),
        "aggressive" => ("1024-65535", "1024-65535"),
        "tcp" => ("1024-65535", "12"),
        "udp" => ("12", "1024-65535"),
        "udp_first" => ("12", "1024-65535"),
        _ => ("12", "12"),
    }
}

fn write_game_overlay_lists(
    lists: &Path,
    settings: &badvpn_common::RuntimeZapretSettings,
) -> Result<GameOverlayLists> {
    let domains = settings
        .active_game_profiles
        .iter()
        .flat_map(|profile| profile.domains.iter())
        .filter_map(|domain| normalize_overlay_domain(domain))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let cidrs = settings
        .active_game_profiles
        .iter()
        .flat_map(|profile| profile.cidrs.iter())
        .filter_map(|cidr| normalize_overlay_cidr(cidr))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let hostlist = lists.join("game-hostlist.txt");
    let ipset = lists.join("game-ipset.txt");
    let ipset_exclude = lists.join("ipset-exclude.txt");
    write_file_atomically(&hostlist, &domains.join("\n"))?;
    write_file_atomically(&ipset, &cidrs.join("\n"))?;
    Ok(GameOverlayLists {
        hostlist,
        ipset,
        ipset_exclude,
        has_hosts: !domains.is_empty(),
        has_cidrs: !cidrs.is_empty(),
    })
}

fn append_game_overlay_winws_args(
    args: &mut Vec<String>,
    lists: &GameOverlayLists,
    settings: &badvpn_common::RuntimeZapretSettings,
) {
    let (game_tcp, game_udp) = game_filter_ports(&settings.game_filter);
    if game_tcp == "12" && game_udp == "12" {
        return;
    }
    if lists.has_hosts && game_tcp != "12" {
        args.extend([
            "--new".to_string(),
            "--filter-tcp=80,443".to_string(),
            format!("--hostlist={}", lists.hostlist.display()),
            "--dpi-desync=multisplit".to_string(),
            "--dpi-desync-split-pos=1".to_string(),
        ]);
    }
    if lists.has_cidrs && game_udp != "12" {
        args.extend([
            "--new".to_string(),
            format!("--filter-udp={game_udp}"),
            format!("--ipset={}", lists.ipset.display()),
            format!("--ipset-exclude={}", lists.ipset_exclude.display()),
            "--dpi-desync=fake".to_string(),
            "--dpi-desync-any-protocol=1".to_string(),
            "--dpi-desync-repeats=6".to_string(),
        ]);
    }
    if lists.has_cidrs && game_tcp != "12" {
        args.extend([
            "--new".to_string(),
            format!("--filter-tcp={game_tcp}"),
            format!("--ipset={}", lists.ipset.display()),
            format!("--ipset-exclude={}", lists.ipset_exclude.display()),
            "--dpi-desync=multisplit".to_string(),
            "--dpi-desync-any-protocol=1".to_string(),
        ]);
    }
}

fn apply_game_bypass_to_request(request: &mut ConnectRequest) -> GameBypassPlan {
    let mut plan = GameBypassPlan::default();
    let bypass_mode = request
        .settings
        .zapret
        .game_bypass_mode
        .trim()
        .to_ascii_lowercase();
    if request.route_mode != RuntimeMode::Smart || !request.settings.zapret.enabled {
        request.settings.zapret.game_filter = "off".to_string();
        request.settings.zapret.active_game_profiles.clear();
        plan.diagnostics
            .push("Game Bypass inactive because Smart/zapret is disabled.".to_string());
        return plan;
    }
    if !request
        .settings
        .mihomo
        .routing_policy
        .smart_presets
        .games_zapret
    {
        request.settings.zapret.game_filter = "off".to_string();
        request.settings.zapret.active_game_profiles.clear();
        plan.diagnostics.push(
            "Game Bypass inactive because the Smart games zapret preset is disabled.".to_string(),
        );
        return plan;
    }
    if bypass_mode == "off" {
        request.settings.zapret.game_filter = "off".to_string();
        request.settings.zapret.active_game_profiles.clear();
        plan.diagnostics
            .push("Game Bypass is disabled; game traffic keeps normal Mihomo routing.".to_string());
        return plan;
    }

    let mut active_profiles = if bypass_mode == "manual" {
        request.settings.zapret.active_game_profiles.clone()
    } else {
        auto_detect_game_profiles(&request.settings.zapret.learned_game_profiles)
    };
    if bypass_mode == "manual" && active_profiles.is_empty() {
        active_profiles = request.settings.zapret.learned_game_profiles.clone();
    }
    active_profiles = normalize_game_profiles(active_profiles);

    if active_profiles.is_empty() {
        request.settings.zapret.game_filter = "off".to_string();
        request.settings.zapret.active_game_profiles.clear();
        plan.diagnostics.push(
            "Auto Game Bypass found no known or learned game process; winws game filter stays off."
                .to_string(),
        );
        return plan;
    }

    let filter = effective_game_filter(&request.settings.zapret.game_filter_mode);
    request.settings.zapret.game_filter = filter.to_string();
    request.settings.zapret.active_game_profiles = active_profiles.clone();
    for profile in &active_profiles {
        if game_profile_processes_are_routing_targets(profile) {
            request
                .settings
                .mihomo
                .zapret_direct_processes
                .extend(profile.process_names.iter().cloned());
        }
        request
            .settings
            .mihomo
            .zapret_direct_domains
            .extend(profile.domains.iter().cloned());
        request
            .settings
            .mihomo
            .zapret_direct_cidrs
            .extend(profile.cidrs.iter().cloned());
        request
            .settings
            .mihomo
            .zapret_direct_tcp_ports
            .extend(profile.tcp_ports.iter().cloned());
        request
            .settings
            .mihomo
            .zapret_direct_udp_ports
            .extend(profile.udp_ports.iter().cloned());
    }
    let (tcp, udp) = game_filter_ports(filter);
    let titles = active_profiles
        .iter()
        .map(|profile| profile.title.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    plan.diagnostics.push(format!(
        "Game Bypass active: mode={} filter={} winws_tcp={} winws_udp={} profiles={}",
        bypass_mode, filter, tcp, udp, titles
    ));
    plan
}

fn game_profile_processes_are_routing_targets(profile: &RuntimeGameProfile) -> bool {
    profile.id != "discord_rtc"
}

fn effective_game_filter(mode: &str) -> &'static str {
    match mode.trim().to_ascii_lowercase().as_str() {
        "tcp_udp" | "aggressive" => "tcp_udp",
        _ => "udp",
    }
}

fn auto_detect_game_profiles(learned: &[RuntimeGameProfile]) -> Vec<RuntimeGameProfile> {
    let running = running_process_names_all();
    let running_lc = running
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let mut profiles = built_in_game_profiles()
        .into_iter()
        .chain(learned.iter().cloned())
        .filter_map(|mut profile| {
            let matched = profile
                .process_names
                .iter()
                .any(|process| running_lc.contains(&process.to_ascii_lowercase()));
            if matched {
                profile.detected = true;
                Some(profile)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let known = profiles
        .iter()
        .flat_map(|profile| profile.process_names.iter())
        .map(|process| process.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    for process in running {
        let process_lc = process.to_ascii_lowercase();
        if known.contains(&process_lc) {
            continue;
        }
        if process_lc.ends_with("-win64-shipping.exe") || process_lc == "repo.exe" {
            profiles.push(RuntimeGameProfile {
                id: format!("detected-{}", process_lc.replace(".exe", "")),
                title: format!("Detected game ({process})"),
                process_names: vec![process],
                filter_mode: "udp_first".to_string(),
                risk_level: "auto_detected".to_string(),
                detected: true,
                ..RuntimeGameProfile::default()
            });
        }
    }
    profiles
}

fn built_in_game_profiles() -> Vec<RuntimeGameProfile> {
    vec![
        RuntimeGameProfile {
            id: "fortnite_epic".to_string(),
            title: "Fortnite / Epic Games".to_string(),
            process_names: vec![
                "FortniteClient-Win64-Shipping.exe".to_string(),
                "FortniteLauncher.exe".to_string(),
                "EpicGamesLauncher.exe".to_string(),
            ],
            domains: vec![
                "epicgames.com".to_string(),
                "epicgames.dev".to_string(),
                "fortnite.com".to_string(),
                "unrealengine.com".to_string(),
            ],
            tcp_ports: vec!["5222".to_string()],
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            detected: false,
            ..RuntimeGameProfile::default()
        },
        RuntimeGameProfile {
            id: "roblox".to_string(),
            title: "Roblox".to_string(),
            process_names: vec!["RobloxPlayerBeta.exe".to_string()],
            domains: vec!["roblox.com".to_string(), "rbxcdn.com".to_string()],
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            detected: false,
            ..RuntimeGameProfile::default()
        },
        RuntimeGameProfile {
            id: "discord_rtc".to_string(),
            title: "Discord RTC".to_string(),
            process_names: vec![
                "Discord.exe".to_string(),
                "DiscordCanary.exe".to_string(),
                "DiscordPTB.exe".to_string(),
            ],
            domains: vec!["discord.com".to_string(), "discord.gg".to_string()],
            udp_ports: vec!["19294-19344".to_string(), "50000-50100".to_string()],
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            detected: false,
            ..RuntimeGameProfile::default()
        },
        RuntimeGameProfile {
            id: "repo".to_string(),
            title: "R.E.P.O.".to_string(),
            process_names: vec![
                "REPO.exe".to_string(),
                "REPO-Win64-Shipping.exe".to_string(),
            ],
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            detected: false,
            ..RuntimeGameProfile::default()
        },
    ]
}

fn normalize_game_profiles(profiles: Vec<RuntimeGameProfile>) -> Vec<RuntimeGameProfile> {
    let mut seen = std::collections::BTreeSet::new();
    let mut normalized = Vec::new();
    for mut profile in profiles {
        if !profile.enabled {
            continue;
        }
        profile.process_names = profile
            .process_names
            .into_iter()
            .filter_map(|process| normalize_process_name(&process))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        profile.domains = profile
            .domains
            .into_iter()
            .filter_map(|domain| normalize_overlay_domain(&domain))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        profile.cidrs = profile
            .cidrs
            .into_iter()
            .filter_map(|cidr| normalize_overlay_cidr(&cidr))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if profile.process_names.is_empty() {
            continue;
        }
        let key = if profile.id.trim().is_empty() {
            profile.process_names.join("|").to_ascii_lowercase()
        } else {
            profile.id.trim().to_ascii_lowercase()
        };
        if seen.insert(key) {
            normalized.push(profile);
        }
    }
    normalized
}

fn running_process_names_all() -> Vec<String> {
    #[cfg(windows)]
    {
        let Ok(output) = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
        else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let first = line.split("\",").next()?.trim().trim_matches('"');
                normalize_process_name(first)
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

fn normalize_process_name(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || value.contains('/') || value.contains('\\') || value.contains(',') {
        return None;
    }
    if value.to_ascii_lowercase().ends_with(".exe") {
        Some(value.to_string())
    } else {
        Some(format!("{value}.exe"))
    }
}

fn normalize_overlay_domain(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.is_empty() || value.starts_with('#') || value.contains('/') || value.contains('*') {
        None
    } else {
        Some(value)
    }
}

fn normalize_overlay_cidr(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value.starts_with('#') || !value.contains('/') {
        None
    } else {
        Some(value)
    }
}

fn ensure_list_file(path: &Path, values: Vec<&'static str>) -> Result<PathBuf> {
    let missing_or_empty =
        !path.exists() || fs::metadata(path).map_or(true, |metadata| metadata.len() == 0);
    if missing_or_empty {
        write_file_atomically(path, &values.join("\n"))?;
    }
    Ok(path.to_path_buf())
}

fn ensure_effective_ipset_all_file(
    lists: &Path,
    settings: &badvpn_common::RuntimeZapretSettings,
) -> Result<PathBuf> {
    let source = lists.join("ipset-all.txt");
    if !source.exists() || fs::metadata(&source).map_or(true, |metadata| metadata.len() == 0) {
        write_file_atomically(&source, &badvpn_common::zapret_default_ipset().join("\n"))?;
    }

    let effective = lists.join("ipset-all.effective.txt");
    let compiled_ipset = fs::read_to_string(lists.join("zapret_ipset.txt")).unwrap_or_default();
    match settings.ipset_filter.trim().to_ascii_lowercase().as_str() {
        "any" => write_file_atomically(&effective, "")?,
        "loaded" => {
            let body = fs::read_to_string(&source).unwrap_or_default();
            let body = if body.trim().is_empty() {
                badvpn_common::zapret_default_ipset().join("\n")
            } else {
                body
            };
            write_file_atomically(&effective, &merge_ipset_bodies(&body, &compiled_ipset))?;
        }
        _ => write_file_atomically(
            &effective,
            &merge_ipset_bodies(
                &badvpn_common::zapret_default_ipset().join("\n"),
                &compiled_ipset,
            ),
        )?,
    }
    Ok(effective)
}

fn merge_ipset_bodies(base_body: &str, compiled_body: &str) -> String {
    let mut body = base_body.to_string();
    let mut seen = base_body
        .lines()
        .filter_map(normalize_ipset_entry)
        .collect::<std::collections::BTreeSet<_>>();

    for entry in compiled_body.lines().filter_map(normalize_ipset_entry) {
        if !seen.insert(entry.clone()) {
            continue;
        }
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&entry);
        body.push('\n');
    }

    body
}

fn normalize_ipset_entry(line: &str) -> Option<String> {
    let value = line.trim().to_ascii_lowercase();
    if value.is_empty() || value.starts_with('#') {
        None
    } else {
        Some(value)
    }
}

fn rewrite_ipset_all_args(args: &mut [String], effective_ipset: &Path) {
    for arg in args {
        if !arg.starts_with("--ipset=") {
            continue;
        }
        let normalized = arg
            .trim_start_matches("--ipset=")
            .trim_matches('"')
            .replace('\\', "/")
            .to_ascii_lowercase();
        if normalized.ends_with("/ipset-all.txt") || normalized == "ipset-all.txt" {
            *arg = format!("--ipset={}", effective_ipset.display());
        }
    }
}

fn append_google_quic_hostlist_args(
    args: &mut Vec<String>,
    list_google: &Path,
    list_exclude: &Path,
    ipset_exclude: &Path,
    bin: &Path,
) {
    // Skip only when a UDP/443 Google branch with fake-quic is already present.
    let already_has_google_quic = args.iter().any(|arg| {
        let normalized = arg.replace('\\', "/").to_ascii_lowercase();
        normalized.contains("dpi-desync-fake-quic=")
            || normalized.contains("quic_initial_www_google_com.bin")
    });
    if already_has_google_quic {
        return;
    }
    args.extend([
        "--new".to_string(),
        "--filter-udp=443".to_string(),
        format!("--hostlist={}", list_google.display()),
        format!("--hostlist-exclude={}", list_exclude.display()),
        format!("--ipset-exclude={}", ipset_exclude.display()),
        "--dpi-desync=fake".to_string(),
        "--dpi-desync-repeats=6".to_string(),
    ]);
    let fake_quic = bin.join("quic_initial_www_google_com.bin");
    if fake_quic.exists() {
        args.push(format!("--dpi-desync-fake-quic={}", fake_quic.display()));
    }
}

fn write_compiled_zapret_lists(
    component_store: &ComponentStore,
    policy: &CompiledPolicy,
) -> Result<()> {
    let lists = component_store.zapret_lists_dir();
    fs::create_dir_all(&lists)?;
    let google_hostlist = flowseal_google_policy_hostlist(&policy.zapret_hostlist);
    let general_hostlist = flowseal_general_policy_hostlist(&policy.zapret_hostlist);
    write_policy_list_file(&lists.join("zapret_hostlist.txt"), &policy.zapret_hostlist)?;
    write_policy_list_file(
        &lists.join("zapret_hostlist_exclude.txt"),
        &policy.zapret_hostlist_exclude,
    )?;
    write_policy_list_file(&lists.join("zapret_ipset.txt"), &policy.zapret_ipset)?;
    write_policy_list_file(
        &lists.join("zapret_ipset_exclude.txt"),
        &policy.zapret_ipset_exclude,
    )?;

    // VPN Only clears policy hosts; keep Flowseal defaults so a later Smart
    // start (or ensure_list_file) never inherits empty ProgramData lists.
    let general_values = if general_hostlist.is_empty() {
        badvpn_common::flowseal_general_hostlist()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        general_hostlist
    };
    let google_values = if google_hostlist.is_empty() {
        badvpn_common::flowseal_google_hostlist()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        google_hostlist
    };
    let exclude_values = if policy.zapret_hostlist_exclude.is_empty() {
        badvpn_common::flowseal_exclude_hostlist()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        policy.zapret_hostlist_exclude.clone()
    };
    let ipset_exclude_values = if policy.zapret_ipset_exclude.is_empty() {
        badvpn_common::flowseal_ipset_exclude()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        policy.zapret_ipset_exclude.clone()
    };

    write_policy_list_file(&lists.join("list-general.txt"), &general_values)?;
    write_policy_list_file(&lists.join("list-google.txt"), &google_values)?;
    write_policy_list_file(&lists.join("list-exclude.txt"), &exclude_values)?;
    write_policy_list_file(&lists.join("ipset-exclude.txt"), &ipset_exclude_values)?;
    ensure_empty_list_file(&lists.join("list-general-user.txt"))?;
    ensure_empty_list_file(&lists.join("list-exclude-user.txt"))?;
    ensure_empty_list_file(&lists.join("ipset-exclude-user.txt"))?;
    Ok(())
}

fn flowseal_google_policy_hostlist(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .filter(|host| is_flowseal_google_host(host))
        .cloned()
        .collect()
}

fn flowseal_general_policy_hostlist(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .filter(|host| !is_flowseal_google_host(host))
        .cloned()
        .collect()
}

fn is_flowseal_google_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('.').to_ascii_lowercase();
    badvpn_common::flowseal_google_hostlist()
        .into_iter()
        .any(|candidate| host == candidate || host.ends_with(&format!(".{candidate}")))
}

fn ensure_vpn_only_fallback_policy(policy: &CompiledPolicy) -> Result<()> {
    if policy.mode != AppRouteMode::VpnOnly {
        return Err(anyhow!(
            "VPN-only fallback compile returned {:?} policy.",
            policy.mode
        ));
    }
    policy
        .validate_invariants()
        .map_err(|error| anyhow!("invalid VPN-only fallback policy: {error}"))?;

    for forbidden_rule in [
        "MATCH,DIRECT",
        "GEOSITE,youtube,DIRECT",
        "DOMAIN-SUFFIX,googlevideo.com,DIRECT",
        "DOMAIN-SUFFIX,youtu.be,DIRECT",
        "GEOSITE,discord,DIRECT",
    ] {
        if policy
            .mihomo_rules
            .iter()
            .any(|rule| rule == forbidden_rule)
        {
            return Err(anyhow!(
                "VPN-only fallback policy contains Smart direct rule {forbidden_rule}."
            ));
        }
    }

    debug_assert_vpn_only_policy(policy);
    Ok(())
}

fn debug_assert_vpn_only_policy(policy: &CompiledPolicy) {
    debug_assert_eq!(policy.mode, AppRouteMode::VpnOnly);
    debug_assert!(policy.zapret_hostlist.is_empty());
    debug_assert!(policy.zapret_hostlist_exclude.is_empty());
    debug_assert!(policy.zapret_ipset.is_empty());
    debug_assert!(policy.zapret_ipset_exclude.is_empty());
    let expected_final_rule = format!("MATCH,{}", policy.main_proxy_group);
    debug_assert_eq!(
        policy.mihomo_rules.last().map(String::as_str),
        Some(expected_final_rule.as_str())
    );
}

fn runtime_phase_after_connect(
    requested_mode: RuntimeMode,
    effective_mode: RuntimeMode,
) -> RuntimePhase {
    if requested_mode == RuntimeMode::Smart && effective_mode == RuntimeMode::VpnOnly {
        RuntimePhase::DegradedVpnOnly
    } else {
        RuntimePhase::Running
    }
}

fn write_policy_list_file(path: &Path, values: &[String]) -> Result<()> {
    write_file_atomically(path, &values.join("\n"))
}

fn ensure_empty_list_file(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        write_file_atomically(path, "")?;
    }
    Ok(path.to_path_buf())
}

async fn run_discord_youtube_probes() -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("BadVpn-Agent/0.1.0")
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()?;
    for url in [
        "https://discord.com/api/v9/experiments",
        "https://www.youtube.com/generate_204",
    ] {
        let mut last_error = None;
        for attempt in 1..=1 {
            match client.get(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() || matches!(status.as_u16(), 204 | 403 | 429) {
                        last_error = None;
                        break;
                    }
                    last_error = Some(anyhow!("{url} returned HTTP {status}"));
                }
                Err(error) => {
                    last_error = Some(anyhow!("{url} attempt {attempt} failed: {error}"));
                }
            }
            sleep(Duration::from_millis(250)).await;
        }
        if let Some(error) = last_error {
            return Err(error);
        }
    }
    Ok(())
}

fn write_file_atomically(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", now_unix()));
    fs::write(&tmp, content)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn preflight_failed(
    id: impl Into<String>,
    severity: PreflightSeverity,
    component: impl Into<String>,
    message: impl Into<String>,
    recommended_action: impl Into<String>,
) -> PreflightCheck {
    PreflightCheck::new(
        id,
        severity,
        component,
        PreflightStatus::Failed,
        message,
        Some(recommended_action.into()),
    )
}

fn prepare_cached_rule_providers(
    yaml: &mut String,
    _home: &Path,
    _geosite_available: bool,
    _geoip_available: bool,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut root = serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .context("failed to parse generated Mihomo YAML for provider preparation")?;
    let mut messages = Vec::new();
    let mut disabled = Vec::new();
    {
        let Some(providers) = root
            .as_mapping_mut()
            .and_then(|map| map.get_mut(serde_yaml::Value::String("rule-providers".to_string())))
            .and_then(serde_yaml::Value::as_mapping_mut)
        else {
            return Ok((Vec::new(), Vec::new()));
        };

        let provider_names = providers
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        for provider_name in provider_names {
            let key = serde_yaml::Value::String(provider_name.clone());
            let Some(provider) = providers
                .get_mut(&key)
                .and_then(serde_yaml::Value::as_mapping_mut)
            else {
                continue;
            };
            let is_http = provider
                .get(serde_yaml::Value::String("type".to_string()))
                .and_then(serde_yaml::Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("http"));
            if !is_http {
                continue;
            }
            disabled.push(provider_name);
        }

        for provider_name in &disabled {
            providers.remove(serde_yaml::Value::String(provider_name.clone()));
            messages.push(format!(
                "Disabled HTTP rule provider '{provider_name}' for offline-safe startup; managed provider updates require a separately verified resource update."
            ));
        }
    }

    if !disabled.is_empty() {
        remove_rule_set_entries_from_yaml(&mut root, &disabled);
    }
    if !disabled.is_empty() {
        *yaml = serde_yaml::to_string(&root)
            .context("failed to render Mihomo YAML after provider preparation")?;
    }
    Ok((messages, disabled))
}

fn remove_rule_set_entries_from_yaml(root: &mut serde_yaml::Value, disabled: &[String]) {
    let Some(rules) = root
        .as_mapping_mut()
        .and_then(|map| map.get_mut(serde_yaml::Value::String("rules".to_string())))
        .and_then(serde_yaml::Value::as_sequence_mut)
    else {
        return;
    };
    rules.retain(|rule| {
        rule.as_str().is_none_or(|rule| {
            !disabled
                .iter()
                .any(|name| rule_references_rule_set(rule, name))
        })
    });
}

fn rule_references_rule_set(rule: &str, provider_name: &str) -> bool {
    const PREFIX: &str = "rule-set,";
    let lowercase = rule.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(offset) = lowercase[search_from..].find(PREFIX) {
        let name_start = search_from + offset + PREFIX.len();
        let name = rule[name_start..]
            .split([',', ')', '('])
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if name == provider_name {
            return true;
        }
        search_from = name_start;
    }
    false
}

fn sync_policy_after_rule_provider_strip(
    policy: &mut CompiledPolicy,
    disabled: &[String],
) -> Result<()> {
    let references_disabled = |rule: &str| {
        disabled
            .iter()
            .any(|name| rule_references_rule_set(rule, name))
    };
    policy
        .mihomo_rules
        .retain(|rule| !references_disabled(rule));
    policy.policy_rules.retain(|rule| {
        rule.target.kind != PolicyTargetKind::RuleSet
            || !disabled.iter().any(|value| value == &rule.target.value)
    });
    policy
        .diagnostics_expectations
        .retain(|expectation| !references_disabled(&expectation.target));
    policy.suppressed_rules.retain(|rule| {
        !references_disabled(&rule.original_rule) && !references_disabled(&rule.chosen_rule)
    });
    policy
        .validate_invariants()
        .map_err(|error| anyhow!("policy became invalid after rule-provider stripping: {error}"))?;
    Ok(())
}

fn sync_policy_after_missing_geodata_strip(
    policy: &mut CompiledPolicy,
    geosite_available: bool,
    geoip_available: bool,
) -> Result<()> {
    policy
        .mihomo_rules
        .retain(|rule| !missing_geodata_rule_text(rule, geosite_available, geoip_available));
    policy.policy_rules.retain(|rule| {
        !missing_geodata_target_kind(rule.target.kind, geosite_available, geoip_available)
    });
    policy.diagnostics_expectations.retain(|expectation| {
        !missing_geodata_rule_text(&expectation.target, geosite_available, geoip_available)
    });
    policy.suppressed_rules.retain(|rule| {
        !missing_geodata_rule_text(&rule.original_rule, geosite_available, geoip_available)
            && !missing_geodata_rule_text(&rule.chosen_rule, geosite_available, geoip_available)
    });
    policy
        .validate_invariants()
        .map_err(|error| anyhow!("policy became invalid after geodata rule stripping: {error}"))?;
    Ok(())
}

fn missing_geodata_rule_text(rule: &str, geosite_available: bool, geoip_available: bool) -> bool {
    let normalized = rule.trim_start().to_ascii_uppercase();
    (!geosite_available && normalized.starts_with("GEOSITE,"))
        || (!geoip_available && normalized.starts_with("GEOIP,"))
}

fn missing_geodata_target_kind(
    kind: PolicyTargetKind,
    geosite_available: bool,
    geoip_available: bool,
) -> bool {
    (!geosite_available && kind == PolicyTargetKind::GeoSite)
        || (!geoip_available && kind == PolicyTargetKind::GeoIp)
}

fn tcp_port_is_busy(port: u16) -> bool {
    TcpListener::bind((LOCALHOST, port)).is_err()
}

fn udp_port_is_busy(port: u16) -> bool {
    UdpSocket::bind((LOCALHOST, port)).is_err()
}

#[derive(Debug, Clone)]
struct RunningProcess {
    name: String,
    pid: u32,
    executable_path: Option<PathBuf>,
}

fn classify_zapret_preflight_processes(
    processes: &[RunningProcess],
    managed_winws: Option<&Path>,
) -> (Vec<String>, Vec<String>) {
    let mut external = Vec::new();
    let mut cleanup_messages = Vec::new();

    for process in processes {
        if process_is_managed_winws(process, managed_winws) {
            match terminate_process(process.pid) {
                Ok(()) => cleanup_messages.push(format!(
                    "Stopped stale BadVpn-owned winws.exe process pid {} before Smart start.",
                    process.pid
                )),
                Err(error) => {
                    cleanup_messages.push(format!(
                        "Failed to stop stale BadVpn-owned winws.exe process pid {}: {error}",
                        process.pid
                    ));
                    external.push(process_label(process));
                }
            }
        } else {
            external.push(process_label(process));
        }
    }

    (external, cleanup_messages)
}

fn cleanup_stale_managed_mihomo_processes(
    processes: &[RunningProcess],
    managed_mihomo: Option<&Path>,
) -> Vec<String> {
    let mut cleanup_messages = Vec::new();

    for process in processes {
        if !process_is_managed_mihomo(process, managed_mihomo) {
            continue;
        }
        match terminate_process(process.pid) {
            Ok(()) => cleanup_messages.push(format!(
                "Stopped stale BadVpn-owned mihomo.exe process pid {} before VPN start.",
                process.pid
            )),
            Err(error) => cleanup_messages.push(format!(
                "Failed to stop stale BadVpn-owned mihomo.exe process pid {}: {error}",
                process.pid
            )),
        }
    }

    cleanup_messages
}

fn process_is_managed_mihomo(process: &RunningProcess, managed_mihomo: Option<&Path>) -> bool {
    if !process.name.eq_ignore_ascii_case("mihomo.exe") {
        return false;
    }
    let Some(managed_mihomo) = managed_mihomo else {
        return false;
    };
    let Some(process_path) = process.executable_path.as_deref() else {
        return false;
    };
    same_windows_path(process_path, managed_mihomo)
}

fn process_is_managed_winws(process: &RunningProcess, managed_winws: Option<&Path>) -> bool {
    if !process.name.eq_ignore_ascii_case("winws.exe") {
        return false;
    }
    let Some(managed_winws) = managed_winws else {
        return false;
    };
    let Some(process_path) = process.executable_path.as_deref() else {
        return false;
    };
    same_windows_path(process_path, managed_winws)
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    normalized_windows_path(left) == normalized_windows_path(right)
}

fn normalized_windows_path(path: &Path) -> String {
    let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    normalized
        .to_string_lossy()
        .replace('/', "\\")
        .trim_matches('"')
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn process_label(process: &RunningProcess) -> String {
    match &process.executable_path {
        Some(path) => format!("{}#{} ({})", process.name, process.pid, path.display()),
        None => format!("{}#{}", process.name, process.pid),
    }
}

fn terminate_process(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to terminate process pid {pid}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "taskkill /PID {pid} returned {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(())
    }
}

fn running_process_details(names: &[&str]) -> Vec<RunningProcess> {
    #[cfg(windows)]
    {
        let filter = names
            .iter()
            .map(|name| format!("Name = '{}'", name.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(" OR ");
        let script = format!(
            "Get-CimInstance Win32_Process -Filter \"{filter}\" | ForEach-Object {{ \"$($_.Name)`t$($_.ProcessId)`t$($_.ExecutablePath)\" }}"
        );
        let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdin(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.splitn(3, '\t');
                let name = parts.next()?.trim();
                let pid = parts.next()?.trim().parse::<u32>().ok()?;
                let executable_path = parts
                    .next()
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from);
                Some(RunningProcess {
                    name: name.to_string(),
                    pid,
                    executable_path,
                })
            })
            .collect()
    }

    #[cfg(not(windows))]
    {
        let _ = names;
        Vec::new()
    }
}

fn running_process_names(names: &[&str]) -> Vec<String> {
    #[cfg(windows)]
    {
        let Ok(output) = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .stdin(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        names
            .iter()
            .filter(|name| stdout.contains(&format!("\"{}\"", name.to_ascii_lowercase())))
            .map(|name| (*name).to_string())
            .collect()
    }

    #[cfg(not(windows))]
    {
        let _ = names;
        Vec::new()
    }
}

fn stale_badvpn_tun_adapter_present() -> bool {
    #[cfg(windows)]
    {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "if (Get-NetAdapter -Name 'BadVpn' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }",
            ])
            .stdin(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn stop_legacy_zapret_service() -> Result<()> {
    #[cfg(windows)]
    {
        let output = Command::new("sc")
            .args(["stop", "BadVpnZapret"])
            .stdin(Stdio::null())
            .output()
            .context("failed to request BadVpnZapret service stop")?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if output.status.success()
            || stdout.contains("does not exist")
            || stdout.contains("1060")
            || stderr.contains("does not exist")
            || stderr.contains("1060")
        {
            Ok(())
        } else {
            Err(anyhow!(
                "sc stop BadVpnZapret returned {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(not(windows))]
    {
        Ok(())
    }
}

fn env_existing_file(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var(name).ok()?);
    path.exists().then_some(path)
}

fn runtime_root_dir() -> PathBuf {
    if let Ok(path) = std::env::var("BADVPN_AGENT_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("PROGRAMDATA") {
        return PathBuf::from(path).join("BadVpn");
    }
    appdata_root_dir().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("runtime")
            .join("BadVpn")
    })
}

fn runtime_logs_dir() -> PathBuf {
    runtime_root_dir().join("logs")
}

fn open_runtime_log_file(name: &str) -> Result<File> {
    let dir = runtime_logs_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create runtime log dir {}", dir.display()))?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(name))
        .with_context(|| format!("failed to open runtime log file {name}"))
}

fn log_stdio(name: &str) -> Result<Stdio> {
    Ok(Stdio::from(open_runtime_log_file(name)?))
}

fn appdata_root_dir() -> Option<PathBuf> {
    std::env::var("APPDATA")
        .ok()
        .map(|path| PathBuf::from(path).join("BadVpn"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn snapshot_to_agent_state(
    snapshot: &AgentRuntimeSnapshot,
    subscription: SubscriptionState,
    selected_proxy: Option<String>,
) -> badvpn_common::AgentState {
    let running = matches!(
        snapshot.phase,
        RuntimePhase::Running | RuntimePhase::DegradedVpnOnly
    );
    badvpn_common::AgentState {
        installed: true,
        running,
        phase: match snapshot.phase {
            RuntimePhase::Idle => badvpn_common::AppPhase::Ready,
            RuntimePhase::Preparing
            | RuntimePhase::StartingZapret
            | RuntimePhase::StartingMihomo
            | RuntimePhase::Verifying => badvpn_common::AppPhase::Connecting,
            RuntimePhase::Running | RuntimePhase::DegradedVpnOnly => {
                badvpn_common::AppPhase::Connected
            }
            RuntimePhase::Stopping => badvpn_common::AppPhase::Disconnecting,
            RuntimePhase::Error => badvpn_common::AppPhase::Error,
        },
        subscription,
        connection: badvpn_common::ConnectionState {
            connected: running,
            status: match snapshot.phase {
                RuntimePhase::Idle => badvpn_common::ConnectionStatus::Idle,
                RuntimePhase::Preparing
                | RuntimePhase::StartingZapret
                | RuntimePhase::StartingMihomo
                | RuntimePhase::Verifying => badvpn_common::ConnectionStatus::Starting,
                RuntimePhase::Running | RuntimePhase::DegradedVpnOnly => {
                    badvpn_common::ConnectionStatus::Running
                }
                RuntimePhase::Stopping => badvpn_common::ConnectionStatus::Stopping,
                RuntimePhase::Error => badvpn_common::ConnectionStatus::Error,
            },
            selected_profile: snapshot.active_config_id.clone(),
            selected_proxy,
            route_mode: snapshot.effective_mode.as_route_mode(),
        },
        metrics: badvpn_common::TrafficMetrics::default(),
        diagnostics: badvpn_common::DiagnosticSummary {
            mihomo_healthy: snapshot.mihomo.state == RuntimeComponentState::Running,
            zapret_healthy: snapshot.zapret.state == RuntimeComponentState::Running,
            message: Some(snapshot.diagnostics.join(" ")),
        },
        last_error: snapshot.last_error.clone(),
    }
}

pub fn cleanup_legacy_zapret_service() -> Result<String> {
    stop_legacy_zapret_service()?;
    Ok("Legacy BadVpnZapret service stop was requested; badvpn-agent owns winws now.".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryCommandPlan {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    required: bool,
}

pub fn repair_windows_network_state() -> Result<String> {
    #[cfg(windows)]
    {
        let mut messages = Vec::new();
        let mut succeeded = 0_usize;
        for plan in windows_network_recovery_plan() {
            match run_recovery_command(plan) {
                Ok(message) => {
                    succeeded += 1;
                    messages.push(message);
                }
                Err(error) if plan.required => return Err(error),
                Err(error) => messages.push(format!("{} warning: {error}", plan.label)),
            }
        }
        if succeeded == 0 {
            return Err(anyhow!(
                "Windows network recovery failed; no recovery command succeeded: {}",
                messages.join("; ")
            ));
        }
        Ok(format!(
            "Windows network recovery completed via badvpn-agent: {}",
            messages.join("; ")
        ))
    }

    #[cfg(not(windows))]
    {
        Ok(
            "Windows network recovery is only required on Windows; no action was taken."
                .to_string(),
        )
    }
}

fn windows_network_recovery_plan() -> Vec<RecoveryCommandPlan> {
    vec![
        RecoveryCommandPlan {
            label: "DNS cache flush",
            program: "ipconfig",
            args: &["/flushdns"],
            required: false,
        },
        RecoveryCommandPlan {
            label: "IPv4 destination cache reset",
            program: "netsh",
            args: &["interface", "ip", "delete", "destinationcache"],
            required: false,
        },
        RecoveryCommandPlan {
            label: "IPv4 neighbor cache reset",
            program: "netsh",
            args: &["interface", "ip", "delete", "arpcache"],
            required: false,
        },
        RecoveryCommandPlan {
            label: "IPv6 destination cache reset",
            program: "netsh",
            args: &["interface", "ipv6", "delete", "destinationcache"],
            required: false,
        },
        RecoveryCommandPlan {
            label: "IPv6 neighbor cache reset",
            program: "netsh",
            args: &["interface", "ipv6", "delete", "neighbors"],
            required: false,
        },
        RecoveryCommandPlan {
            label: "BPN Mihomo firewall rule cleanup",
            program: "netsh",
            args: &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=BadVpn Mihomo",
            ],
            required: false,
        },
        RecoveryCommandPlan {
            label: "BPN winws firewall rule cleanup",
            program: "netsh",
            args: &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=BadVpn winws",
            ],
            required: false,
        },
    ]
}

fn run_recovery_command(plan: RecoveryCommandPlan) -> Result<String> {
    let output = Command::new(plan.program)
        .args(plan.args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {}", plan.program))?;
    if output.status.success() {
        return Ok(format!("{} ok", plan.label));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("command returned non-zero status");
    Err(anyhow!("{} failed: {detail}", plan.label))
}

#[cfg(test)]
mod architecture_fix_tests {
    use super::*;

    #[test]
    fn controller_secret_is_random_shape() {
        let first = badvpn_common::generate_controller_secret().unwrap();
        let second = badvpn_common::generate_controller_secret().unwrap();

        assert!(first.starts_with("badvpn-"));
        assert_eq!(first.len(), "badvpn-".len() + 64);
        assert_ne!(first, second);
        assert!(!first["badvpn-".len()..]
            .chars()
            .all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn zapret_strategy_fallback_order_prefers_selected_then_all() {
        let mut settings = badvpn_common::RuntimeZapretSettings::default();
        settings.strategy = "alt5".to_string();
        settings.auto_profile_fallback = true;
        let order = zapret_strategy_attempt_order(&settings);
        assert_eq!(order.first().copied(), Some("alt5"));
        assert_eq!(order.len(), zapret_strategy_ids().len());
        assert!(order.contains(&"general"));
        assert!(order.contains(&"simple_fake_alt2"));

        settings.auto_profile_fallback = false;
        assert_eq!(zapret_strategy_attempt_order(&settings), vec!["alt5"]);
    }

    #[test]
    fn append_google_quic_skips_when_fake_quic_already_present() {
        let mut args = vec![
            "--filter-udp=443".to_string(),
            "--dpi-desync-fake-quic=C:\\bin\\quic_initial_www_google_com.bin".to_string(),
        ];
        let google = PathBuf::from("C:\\lists\\list-google.txt");
        let exclude = PathBuf::from("C:\\lists\\list-exclude.txt");
        let ipset = PathBuf::from("C:\\lists\\ipset-exclude.txt");
        let bin = PathBuf::from("C:\\bin");
        append_google_quic_hostlist_args(&mut args, &google, &exclude, &ipset, &bin);
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn windows_network_recovery_plan_is_scoped_to_cache_and_bpn_rules() {
        let plan = windows_network_recovery_plan();
        assert!(plan
            .iter()
            .any(|command| command.args.contains(&"destinationcache")));
        assert!(plan
            .iter()
            .any(|command| command.args.contains(&"arpcache")));
        assert!(plan
            .iter()
            .any(|command| command.args.contains(&"name=BadVpn Mihomo")));
        assert!(plan
            .iter()
            .any(|command| command.args.contains(&"name=BadVpn winws")));

        for command in plan {
            let joined = std::iter::once(command.program)
                .chain(command.args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase();
            assert!(!joined.contains("advfirewall reset"));
            assert!(!joined.contains("winsock reset"));
            assert!(!joined.contains("route -f"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use badvpn_common::{
        compile_policy, AppRouteMode, MihomoConfigOptions, PolicyCompileInput, ProxyGroupInfo,
        RoutingPolicySettings, RuntimeDiagnosticsSettings, RuntimeFacts, RuntimeSettings,
        RuntimeZapretSettings,
    };

    #[tokio::test]
    async fn duplicate_connect_returns_busy_error() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.phase = RuntimePhase::StartingMihomo;
        let error = manager
            .connect(test_request())
            .await
            .expect_err("duplicate connect must fail while a transition is active");
        assert!(
            error.to_string().contains("already in progress"),
            "unexpected error: {error}"
        );
        assert_eq!(manager.snapshot.phase, RuntimePhase::StartingMihomo);
    }

    #[test]
    fn smart_running_without_zapret_requires_late_fallback() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.effective_mode = RuntimeMode::Smart;
        manager.snapshot.mihomo =
            RuntimeComponentSnapshot::new(RuntimeComponentState::Running, None);
        manager.snapshot.zapret =
            RuntimeComponentSnapshot::new(RuntimeComponentState::Stopped, None);

        assert!(manager.late_zapret_death_requires_fallback());

        manager.snapshot.effective_mode = RuntimeMode::VpnOnly;
        assert!(!manager.late_zapret_death_requires_fallback());
    }

    #[test]
    fn late_zapret_death_keeps_exit_detail_for_ui() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.effective_mode = RuntimeMode::Smart;
        manager.snapshot.mihomo =
            RuntimeComponentSnapshot::new(RuntimeComponentState::Running, None);
        manager.zapret.last_exit_detail =
            Some("winws exited unexpectedly with exit code: 1".to_string());

        manager.record_late_zapret_death_if_needed();

        assert_eq!(
            manager.snapshot.zapret.state,
            RuntimeComponentState::Stopped
        );
        assert!(manager
            .snapshot
            .zapret
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("exit code: 1"));
    }

    #[test]
    fn refresh_process_state_preserves_stopped_zapret_detail() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.zapret = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Stopped,
            Some("zapret is disabled for VPN Only.".to_string()),
        );

        manager.refresh_process_state();

        assert_eq!(
            manager.snapshot.zapret.state,
            RuntimeComponentState::Stopped
        );
        assert_eq!(
            manager.snapshot.zapret.detail.as_deref(),
            Some("zapret is disabled for VPN Only.")
        );
    }

    #[test]
    fn late_mihomo_death_transitions_connected_runtime_to_error() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.phase = RuntimePhase::Running;
        manager.snapshot.mihomo = RuntimeComponentSnapshot::new(
            RuntimeComponentState::Stopped,
            Some("Mihomo exited unexpectedly with exit code: 1".to_string()),
        );
        manager.snapshot.zapret =
            RuntimeComponentSnapshot::new(RuntimeComponentState::Running, None);

        manager.handle_late_mihomo_death();

        assert_eq!(manager.snapshot.phase, RuntimePhase::Error);
        assert_eq!(
            manager.snapshot.zapret.state,
            RuntimeComponentState::Stopped
        );
        assert!(manager
            .snapshot
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("VPN routing is no longer active"));
        let state = snapshot_to_agent_state(&manager.snapshot, SubscriptionState::default(), None);
        assert!(!state.running);
        assert!(!state.connection.connected);
        assert_eq!(state.phase, badvpn_common::AppPhase::Error);
    }

    #[test]
    fn active_proxy_selection_rejects_stale_group_and_unknown_member() {
        let catalog = serde_json::json!({
            "proxies": {
                "__BADVPN_VPN_ONLY__": {
                    "type": "Selector",
                    "all": ["Germany", "Switzerland"]
                }
            }
        });

        let stale = validate_active_proxy_selection(&catalog, "Выбор сервера", "Germany")
            .unwrap_err()
            .to_string();
        assert!(stale.contains("not present in the active Mihomo runtime"));

        let unknown = validate_active_proxy_selection(&catalog, "__BADVPN_VPN_ONLY__", "Poland")
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("not a member"));

        validate_active_proxy_selection(&catalog, "__BADVPN_VPN_ONLY__", "Germany").unwrap();
    }

    #[test]
    fn proxy_delay_url_encodes_unicode_group_as_one_path_segment() {
        let url = mihomo_proxy_delay_url(
            9090,
            "Выбор сервера/основной",
            "https://www.gstatic.com/generate_204",
            4_500,
        )
        .unwrap();

        assert!(url
            .as_str()
            .contains("/proxies/%D0%92%D1%8B%D0%B1%D0%BE%D1%80%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D0%B0%2F%D0%BE%D1%81%D0%BD%D0%BE%D0%B2%D0%BD%D0%BE%D0%B9/delay"), "unexpected URL: {url}");
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "timeout")
                .map(|(_, value)| value.into_owned())
                .as_deref(),
            Some("4500")
        );
    }

    #[test]
    fn corrupt_draft_does_not_replace_last_working() {
        let root = std::env::temp_dir().join(format!("badvpn-config-test-{}", now_unix()));
        let store = RuntimeConfigStore { root: root.clone() };
        let draft = store.write_draft("bad: [").unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(store.run_path(), "good: true\n").unwrap();
        fs::write(store.last_working_path(), "good: true\n").unwrap();
        assert!(store.promote_draft_to_run(&draft).is_ok());
        store.rollback_run().unwrap();
        assert_eq!(
            fs::read_to_string(store.run_path()).unwrap(),
            "good: true\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn flowseal_bat_profile_is_used_for_winws_args() {
        let root = std::env::temp_dir().join(format!("badvpn-zapret-test-{}", now_unix()));
        let components = root.join("components");
        let zapret = components.join("zapret");
        fs::create_dir_all(zapret.join("profiles")).unwrap();
        fs::create_dir_all(zapret.join("bin")).unwrap();
        fs::create_dir_all(zapret.join("lists")).unwrap();
        fs::write(
            zapret.join("profiles").join("general (ALT9).bat"),
            r#"
start "zapret: general (ALT9)" /min "%BIN%winws.exe" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=multisplit --new ^
--filter-udp=%GameFilterUDP% --ipset="%LISTS%ipset-all.txt" --dpi-desync=fake
"#,
        )
        .unwrap();
        let store = ComponentStore {
            root: components,
            appdata_fallback: None,
        };
        let settings = RuntimeZapretSettings {
            strategy: "alt9".to_string(),
            game_filter: "tcp_udp".to_string(),
            ipset_filter: "none".to_string(),
            ..RuntimeZapretSettings::default()
        };

        let args = build_winws_args(&store, &settings).unwrap();

        assert!(args.iter().any(|arg| arg == "--filter-l7=discord,stun"));
        assert!(args.iter().any(|arg| arg == "--ip-id=zero"));
        assert!(args
            .iter()
            .any(|arg| arg.contains("ipset-all.effective.txt")));
        assert!(!args.iter().any(|arg| arg.contains("ipset-all.txt")));
        assert!(
            args.windows(2).any(|window| {
                window[0] == "--filter-udp=443" && window[1].contains("list-google.txt")
            }),
            "Flowseal BAT args should include a curated Google/YouTube QUIC hostlist branch"
        );
        assert!(args.iter().any(|arg| arg == "--wf-filter-lan=1"));
        assert!(args.iter().any(|arg| arg == "--wf-l3=ipv4,ipv6"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manual_game_bypass_enables_udp_first_process_direct() {
        let mut request = test_request();
        request.settings.zapret.game_bypass_mode = "manual".to_string();
        request.settings.zapret.game_filter_mode = "udp_first".to_string();
        request.settings.zapret.active_game_profiles = vec![RuntimeGameProfile {
            id: "repo".to_string(),
            title: "R.E.P.O.".to_string(),
            process_names: vec!["REPO.exe".to_string()],
            filter_mode: "udp_first".to_string(),
            ..RuntimeGameProfile::default()
        }];

        let plan = apply_game_bypass_to_request(&mut request);

        assert_eq!(request.settings.zapret.game_filter, "udp");
        assert!(request
            .settings
            .mihomo
            .zapret_direct_processes
            .contains(&"REPO.exe".to_string()));
        assert!(plan
            .diagnostics
            .iter()
            .any(|message| message.contains("Game Bypass active")));
    }

    #[test]
    fn discord_rtc_game_bypass_does_not_add_process_only_direct_rules() {
        let mut request = test_request();
        request.settings.zapret.game_bypass_mode = "manual".to_string();
        request.settings.zapret.game_filter_mode = "udp_first".to_string();
        request.settings.zapret.active_game_profiles = vec![RuntimeGameProfile {
            id: "discord_rtc".to_string(),
            title: "Discord RTC".to_string(),
            process_names: vec!["Discord.exe".to_string()],
            domains: vec!["discord.com".to_string(), "discord.gg".to_string()],
            udp_ports: vec!["19294-19344".to_string(), "50000-50100".to_string()],
            filter_mode: "udp_first".to_string(),
            ..RuntimeGameProfile::default()
        }];

        let plan = apply_game_bypass_to_request(&mut request);

        assert_eq!(request.settings.zapret.game_filter, "udp");
        assert!(request.settings.mihomo.zapret_direct_processes.is_empty());
        assert!(request
            .settings
            .mihomo
            .zapret_direct_domains
            .contains(&"discord.com".to_string()));
        assert!(request
            .settings
            .mihomo
            .zapret_direct_udp_ports
            .contains(&"19294-19344".to_string()));
        assert!(plan
            .diagnostics
            .iter()
            .any(|message| message.contains("Game Bypass active")));
    }

    #[test]
    fn game_bypass_respects_disabled_games_zapret_preset() {
        let mut request = test_request();
        request
            .settings
            .mihomo
            .routing_policy
            .smart_presets
            .games_zapret = false;
        request.settings.zapret.game_bypass_mode = "manual".to_string();
        request.settings.zapret.game_filter_mode = "tcp_udp".to_string();
        request.settings.zapret.active_game_profiles = vec![RuntimeGameProfile {
            id: "repo".to_string(),
            title: "R.E.P.O.".to_string(),
            process_names: vec!["REPO.exe".to_string()],
            domains: vec!["game.example.com".to_string()],
            cidrs: vec!["203.0.113.0/24".to_string()],
            tcp_ports: vec!["27015".to_string()],
            udp_ports: vec!["50000-50100".to_string()],
            filter_mode: "tcp_udp".to_string(),
            ..RuntimeGameProfile::default()
        }];

        let plan = apply_game_bypass_to_request(&mut request);

        assert_eq!(request.settings.zapret.game_filter, "off");
        assert!(request.settings.zapret.active_game_profiles.is_empty());
        assert!(request.settings.mihomo.zapret_direct_processes.is_empty());
        assert!(request.settings.mihomo.zapret_direct_domains.is_empty());
        assert!(request.settings.mihomo.zapret_direct_cidrs.is_empty());
        assert!(request.settings.mihomo.zapret_direct_tcp_ports.is_empty());
        assert!(request.settings.mihomo.zapret_direct_udp_ports.is_empty());
        assert!(plan
            .diagnostics
            .iter()
            .any(|message| message.contains("games zapret preset is disabled")));
    }

    #[test]
    fn disabled_manual_game_profile_is_preserved_but_not_activated() {
        let mut request = test_request();
        request.settings.zapret.game_bypass_mode = "manual".to_string();
        request.settings.zapret.game_filter_mode = "udp_first".to_string();
        request.settings.zapret.active_game_profiles = vec![RuntimeGameProfile {
            id: "disabled-repo".to_string(),
            title: "Disabled R.E.P.O.".to_string(),
            process_names: vec!["REPO.exe".to_string()],
            filter_mode: "udp_first".to_string(),
            enabled: false,
            ..RuntimeGameProfile::default()
        }];

        let plan = apply_game_bypass_to_request(&mut request);

        assert_eq!(request.settings.zapret.game_filter, "off");
        assert!(request.settings.zapret.active_game_profiles.is_empty());
        assert!(request.settings.mihomo.zapret_direct_processes.is_empty());
        assert!(plan
            .diagnostics
            .iter()
            .any(|message| message.contains("found no known or learned game process")));
    }

    #[test]
    fn smart_writes_zapret_lists_from_compiled_policy() {
        let root = std::env::temp_dir().join(format!("badvpn-policy-lists-test-{}", now_unix()));
        let components = root.join("components");
        let store = ComponentStore {
            root: components.clone(),
            appdata_fallback: None,
        };
        let mut routing = RoutingPolicySettings::default();
        routing.force_zapret_cidrs = vec!["203.0.113.0/24".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: vec![
                "DOMAIN-SUFFIX,googlevideo.com,YouTube".to_string(),
                "DOMAIN-SUFFIX,perplexity.ai,AI".to_string(),
                "MATCH,PROXY".to_string(),
            ],
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        let lists = components.join("zapret").join("lists");
        fs::create_dir_all(&lists).unwrap();
        fs::write(lists.join("ipset-all.txt"), "198.51.100.0/24\n").unwrap();
        fs::write(lists.join("list-general-user.txt"), "custom.example\n").unwrap();
        fs::write(lists.join("list-exclude-user.txt"), "exclude.example\n").unwrap();
        fs::write(lists.join("ipset-exclude-user.txt"), "203.0.113.99\n").unwrap();

        write_compiled_zapret_lists(&store, &policy).unwrap();

        assert!(fs::read_to_string(lists.join("zapret_hostlist.txt"))
            .unwrap()
            .contains("googlevideo.com"));
        assert!(
            fs::read_to_string(lists.join("zapret_hostlist_exclude.txt"))
                .unwrap()
                .contains("perplexity.ai")
        );
        let general = fs::read_to_string(lists.join("list-general.txt")).unwrap();
        let google = fs::read_to_string(lists.join("list-google.txt")).unwrap();
        assert!(general.contains("discord.com"));
        assert!(!general.contains("googlevideo.com"));
        assert!(google.contains("googlevideo.com"));
        assert!(!google.contains("discord.com"));
        assert_eq!(
            fs::read_to_string(lists.join("ipset-all.txt")).unwrap(),
            "198.51.100.0/24\n"
        );
        let settings = RuntimeZapretSettings {
            ipset_filter: "loaded".to_string(),
            ..RuntimeZapretSettings::default()
        };
        ensure_effective_ipset_all_file(&lists, &settings).unwrap();
        assert_eq!(
            fs::read_to_string(lists.join("ipset-all.effective.txt")).unwrap(),
            "198.51.100.0/24\n203.0.113.0/24\n"
        );
        assert_eq!(
            fs::read_to_string(lists.join("list-general-user.txt")).unwrap(),
            "custom.example\n"
        );
        assert_eq!(
            fs::read_to_string(lists.join("list-exclude-user.txt")).unwrap(),
            "exclude.example\n"
        );
        assert_eq!(
            fs::read_to_string(lists.join("ipset-exclude-user.txt")).unwrap(),
            "203.0.113.99\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn remembered_proxy_selection_is_kept_for_late_fallback_request() {
        let mut manager = RuntimeManager::new();
        manager.last_request = Some(test_request());

        manager.remember_proxy_selection("PROXY", "Backup node");

        let fallback_request = manager
            .last_request
            .clone()
            .expect("late fallback request should remain available");
        assert_eq!(
            fallback_request.selected_proxies.get("PROXY"),
            Some(&"Backup node".to_string())
        );
    }

    #[test]
    fn vpn_only_list_write_keeps_flowseal_defaults() {
        let root = std::env::temp_dir().join(format!("badvpn-vpn-only-lists-{}", now_unix()));
        let components = root.join("components");
        let store = ComponentStore {
            root: components.clone(),
            appdata_fallback: None,
        };
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec!["MATCH,PROXY".to_string()],
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        let lists = components.join("zapret").join("lists");
        fs::create_dir_all(&lists).unwrap();
        fs::write(lists.join("list-general.txt"), "").unwrap();
        fs::write(lists.join("list-google.txt"), "").unwrap();

        write_compiled_zapret_lists(&store, &policy).unwrap();

        assert!(policy.zapret_hostlist.is_empty());
        assert!(fs::read_to_string(lists.join("zapret_hostlist.txt"))
            .unwrap()
            .trim()
            .is_empty());
        let general = fs::read_to_string(lists.join("list-general.txt")).unwrap();
        let google = fs::read_to_string(lists.join("list-google.txt")).unwrap();
        assert!(general.contains("discord.com"));
        assert!(google.contains("googlevideo.com"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ensure_list_file_refills_empty_hostlists() {
        let root = std::env::temp_dir().join(format!("badvpn-ensure-list-{}", now_unix()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("list-general.txt");
        fs::write(&path, "").unwrap();

        ensure_list_file(&path, badvpn_common::flowseal_general_hostlist()).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("discord.com"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn policy_diagnostics_are_summarized_without_raw_provider_rules() {
        let mut provider_rules = (0..20)
            .map(|index| format!("DOMAIN-SUFFIX,sensitive{index}.example.com,DIRECT"))
            .collect::<Vec<_>>();
        provider_rules.push("MATCH,PROXY".to_string());
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules,
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        let mut manager = RuntimeManager::new();

        manager.record_policy_diagnostics(&policy);

        let diagnostics = manager.snapshot.diagnostics.join("\n");
        assert!(diagnostics.contains("Policy overrides: total=20 samples=5"));
        assert!(diagnostics.contains("original_kind=DOMAIN-SUFFIX"));
        assert!(!diagnostics.contains("sensitive0.example.com"));
        assert!(!diagnostics.contains("sensitive19.example.com"));
        assert!(manager.snapshot.diagnostics.len() <= 8);
    }

    #[test]
    fn smart_fallback_recompiles_fresh_vpn_only_policy() {
        let manager = RuntimeManager::new();
        let mut request = test_request();
        request.profile_body = r#"
proxies:
  - name: Node-DE
    type: http
    server: 198.51.100.80
    port: 443
proxy-groups:
  - name: MainProxy
    type: select
    proxies:
      - Node-DE
  - name: Streaming
    type: select
    proxies:
      - MainProxy
rules:
  - GEOSITE,youtube,Streaming
  - DOMAIN-SUFFIX,googlevideo.com,Streaming
  - GEOSITE,discord,Streaming
  - MATCH,MainProxy
"#
        .to_string();

        let smart = manager
            .build_runtime_config_with_secret(&request, RuntimeMode::Smart, "shared-secret".into())
            .unwrap();
        assert_eq!(smart.policy.mode, AppRouteMode::Smart);
        assert!(smart
            .policy
            .mihomo_rules
            .contains(&"MATCH,MainProxy".to_string()));
        assert!(!smart
            .policy
            .mihomo_rules
            .contains(&"MATCH,DIRECT".to_string()));
        assert!(smart
            .policy
            .mihomo_rules
            .contains(&"GEOSITE,youtube,DIRECT".to_string()));
        assert!(!smart.policy.zapret_hostlist.is_empty());

        let fallback = manager
            .build_runtime_config_with_secret(&request, RuntimeMode::VpnOnly, smart.secret.clone())
            .unwrap();

        ensure_vpn_only_fallback_policy(&fallback.policy).unwrap();
        assert_eq!(fallback.secret, smart.secret);
        assert_eq!(fallback.policy.mode, AppRouteMode::VpnOnly);
        assert!(!fallback
            .policy
            .mihomo_rules
            .contains(&"MATCH,DIRECT".to_string()));
        assert!(!fallback
            .policy
            .mihomo_rules
            .contains(&"GEOSITE,youtube,DIRECT".to_string()));
        assert!(!fallback
            .policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,googlevideo.com,DIRECT".to_string()));
        assert!(!fallback
            .policy
            .mihomo_rules
            .contains(&"GEOSITE,discord,DIRECT".to_string()));
        assert!(fallback.policy.zapret_hostlist.is_empty());
        assert!(fallback.policy.zapret_hostlist_exclude.is_empty());
        assert!(fallback.policy.zapret_ipset.is_empty());
        assert!(fallback.policy.zapret_ipset_exclude.is_empty());
    }

    #[test]
    fn probe_fallback_config_is_prepared_before_validation() {
        let root = std::env::temp_dir().join(format!("badvpn-probe-fallback-test-{}", now_unix()));
        let mut manager = RuntimeManager::new();
        manager.config_store = RuntimeConfigStore { root: root.clone() };
        let mut request = test_request();
        request.profile_body = r#"
proxies:
  - name: Node-DE
    type: http
    server: 198.51.100.80
    port: 443
proxy-groups:
  - name: MainProxy
    type: select
    proxies:
      - Node-DE
rules:
  - GEOSITE,youtube,MainProxy
  - GEOIP,telegram,MainProxy,no-resolve
  - MATCH,MainProxy
"#
        .to_string();

        let mut fallback = manager
            .build_runtime_config_with_secret(
                &request,
                RuntimeMode::VpnOnly,
                "shared-secret".into(),
            )
            .unwrap();
        assert!(fallback.yaml.contains("GEOSITE,youtube,MainProxy"));
        assert!(fallback
            .yaml
            .contains("GEOIP,telegram,MainProxy,no-resolve"));

        manager
            .prepare_runtime_config_for_local_mihomo(&mut fallback)
            .unwrap();

        assert!(!fallback.yaml.contains("GEOSITE,youtube,MainProxy"));
        assert!(!fallback
            .yaml
            .contains("GEOIP,telegram,MainProxy,no-resolve"));
        assert!(!fallback
            .policy
            .mihomo_rules
            .iter()
            .any(|rule| rule.starts_with("GEOSITE,") || rule.starts_with("GEOIP,")));
        assert!(!fallback.policy.policy_rules.iter().any(|rule| {
            matches!(
                rule.target.kind,
                PolicyTargetKind::GeoSite | PolicyTargetKind::GeoIp
            )
        }));
        assert!(!fallback
            .policy
            .diagnostics_expectations
            .iter()
            .any(|expectation| expectation.target.starts_with("GEOSITE,")
                || expectation.target.starts_with("GEOIP,")));
        assert!(manager
            .snapshot
            .diagnostics
            .iter()
            .any(|message| { message.contains("GEOSITE provider rules") }));
        assert!(manager
            .snapshot
            .diagnostics
            .iter()
            .any(|message| { message.contains("GEOIP provider rules") }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cached_classical_provider_with_missing_geodata_is_disabled() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-sanitize-{}", now_unix()));
        let ruleset = root.join("ruleset");
        fs::create_dir_all(&ruleset).unwrap();
        fs::write(
            ruleset.join("ai.yaml"),
            "payload:\n  - GEOSITE,openai\n  - GEOIP,private\n  - DOMAIN-SUFFIX,openai.com\n",
        )
        .unwrap();
        let mut yaml = r#"
rule-providers:
  AI:
    type: http
    behavior: classical
    format: yaml
    url: https://example.invalid/ai.yaml
    path: ./ruleset/ai.yaml
    proxy: PROXY
    interval: 86400
rules:
  - RULE-SET,AI,PROXY
  - MATCH,PROXY
"#
        .to_string();

        let (messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, false, false).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(disabled, vec!["AI".to_string()]);
        assert!(!yaml.contains("example.invalid"));
        assert!(!yaml.contains("RULE-SET,AI"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn http_provider_is_disabled_even_when_an_unverified_cache_exists() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-local-{}", now_unix()));
        let ruleset = root.join("ruleset");
        fs::create_dir_all(&ruleset).unwrap();
        fs::write(
            ruleset.join("domains.yaml"),
            "payload:\n  - DOMAIN-SUFFIX,example.com\n",
        )
        .unwrap();
        let mut yaml = r#"
rule-providers:
  Domains:
    type: http
    behavior: classical
    format: yaml
    url: https://example.invalid/domains.yaml
    path: ./ruleset/domains.yaml
    interval: 86400
rules:
  - RULE-SET,Domains,PROXY
  - MATCH,PROXY
"#
        .to_string();

        let (_messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, false, false).unwrap();

        assert_eq!(disabled, vec!["Domains".to_string()]);
        assert!(!yaml.contains("example.invalid"));
        assert!(!yaml.contains("RULE-SET,Domains"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_yaml_provider_cache_is_disabled() {
        for body in [
            "payload: broken\n",
            "foo: bar\n",
            "payload:\n  - ok\n  - 7\n",
            "payload:\n  - NOT-A-MIHOMO-RULE\n",
        ] {
            let root = std::env::temp_dir().join(format!("badvpn-provider-invalid-{}", now_unix()));
            let ruleset = root.join("ruleset");
            fs::create_dir_all(&ruleset).unwrap();
            fs::write(ruleset.join("invalid.yaml"), body).unwrap();
            let mut yaml = "rule-providers:\n  Invalid:\n    type: http\n    behavior: classical\n    format: yaml\n    url: https://example.invalid/provider.yaml\n    path: ./ruleset/invalid.yaml\nrules:\n  - RULE-SET,Invalid,PROXY\n  - MATCH,PROXY\n".to_string();

            let (_messages, disabled) =
                prepare_cached_rule_providers(&mut yaml, &root, true, true).unwrap();

            assert_eq!(disabled, vec!["Invalid".to_string()]);
            assert!(!yaml.contains("example.invalid"));
            assert!(!yaml.contains("RULE-SET,Invalid"));
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn unvalidated_mrs_provider_cache_is_disabled() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-mrs-{}", now_unix()));
        let ruleset = root.join("ruleset");
        fs::create_dir_all(&ruleset).unwrap();
        fs::write(
            ruleset.join("invalid.mrs"),
            [0x28, 0xB5, 0x2F, 0xFD, 0, 1, 2, 3],
        )
        .unwrap();
        let mut yaml = "rule-providers:\n  InvalidMrs:\n    type: http\n    behavior: domain\n    format: mrs\n    url: https://example.invalid/provider.mrs\n    path: ./ruleset/invalid.mrs\nrules:\n  - RULE-SET,InvalidMrs,PROXY\n  - MATCH,PROXY\n".to_string();

        let (_messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, true, true).unwrap();

        assert_eq!(disabled, vec!["InvalidMrs".to_string()]);
        assert!(!yaml.contains("example.invalid"));
        assert!(!yaml.contains("RULE-SET,InvalidMrs"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_http_provider_cache_disables_provider_and_rule() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-missing-{}", now_unix()));
        fs::create_dir_all(&root).unwrap();
        let mut yaml = r#"
rule-providers:
  TikTok:
    type: http
    behavior: classical
    format: yaml
    url: https://example.invalid/missing.yaml
    path: ./ruleset/missing.yaml
    interval: 86400
rules:
  - RULE-SET,TikTok,PROXY
  - MATCH,PROXY
"#
        .to_string();

        let (messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, false, false).unwrap();

        assert_eq!(disabled, vec!["TikTok".to_string()]);
        assert!(messages
            .iter()
            .any(|message| message.contains("offline-safe startup")));
        assert!(!yaml.contains("example.invalid"));
        assert!(!yaml.contains("RULE-SET,TikTok"));
        assert!(yaml.contains("MATCH,PROXY"));
        let mut policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec![
                "RULE-SET,TikTok,PROXY".to_string(),
                "MATCH,PROXY".to_string(),
            ],
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        sync_policy_after_rule_provider_strip(&mut policy, &disabled).unwrap();
        assert!(!policy
            .mihomo_rules
            .iter()
            .any(|rule| rule.contains("RULE-SET,TikTok")));
        assert!(policy.mihomo_rules.iter().any(|rule| rule == "MATCH,PROXY"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disabling_http_provider_preserves_case_distinct_local_provider() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-case-{}", now_unix()));
        fs::create_dir_all(&root).unwrap();
        let mut yaml = r#"
rule-providers:
  Foo:
    type: http
    behavior: classical
    format: yaml
    url: https://example.invalid/Foo.yaml
    path: ./ruleset/Foo.yaml
  foo:
    type: file
    behavior: classical
    format: yaml
    path: ./ruleset/foo.yaml
rules:
  - RULE-SET,Foo,PROXY
  - RULE-SET,foo,DIRECT
  - MATCH,PROXY
"#
        .to_string();

        let (_messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, false, false).unwrap();

        assert_eq!(disabled, vec!["Foo".to_string()]);
        assert!(!yaml.contains("RULE-SET,Foo,PROXY"));
        assert!(yaml.contains("RULE-SET,foo,DIRECT"));
        assert!(yaml.contains("foo:"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disabling_http_provider_removes_nested_rule_set_reference() {
        let root = std::env::temp_dir().join(format!("badvpn-provider-nested-{}", now_unix()));
        fs::create_dir_all(&root).unwrap();
        let mut yaml = r#"
rule-providers:
  Remote:
    type: http
    behavior: classical
    format: yaml
    url: https://example.invalid/remote.yaml
    path: ./ruleset/remote.yaml
rules:
  - AND,((RULE-SET,Remote),(NETWORK,TCP)),PROXY
  - MATCH,PROXY
"#
        .to_string();

        let (_messages, disabled) =
            prepare_cached_rule_providers(&mut yaml, &root, false, false).unwrap();

        assert_eq!(disabled, vec!["Remote".to_string()]);
        assert!(!yaml.contains("RULE-SET,Remote"));
        assert!(yaml.contains("MATCH,PROXY"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallback_phase_is_degraded_only_for_requested_smart() {
        assert_eq!(
            runtime_phase_after_connect(RuntimeMode::Smart, RuntimeMode::VpnOnly),
            RuntimePhase::DegradedVpnOnly
        );
        assert_eq!(
            runtime_phase_after_connect(RuntimeMode::VpnOnly, RuntimeMode::VpnOnly),
            RuntimePhase::Running
        );
        assert_eq!(
            runtime_phase_after_connect(RuntimeMode::Smart, RuntimeMode::Smart),
            RuntimePhase::Running
        );
    }

    #[test]
    fn startup_timeline_summary_is_redacted_and_stage_keyed() {
        let mut timeline = StartupTimeline::new();
        timeline.mark("preflight_ms");
        timeline.mark("policy_render_ms");

        let summary = timeline.summary();

        assert!(summary.starts_with("Startup timeline: "));
        assert!(summary.contains("preflight_ms="));
        assert!(summary.contains("policy_render_ms="));
        assert!(summary.contains("total_connect_ms="));
        assert!(!summary.contains("http"));
        assert!(!summary.contains("token"));
        assert!(!summary.contains("secret"));
    }

    #[test]
    fn managed_mihomo_classifier_only_matches_badvpn_binary_path() {
        let managed = PathBuf::from(r"C:\ProgramData\BadVpn\components\mihomo.exe");
        let managed_process = RunningProcess {
            name: "mihomo.exe".to_string(),
            pid: 42,
            executable_path: Some(PathBuf::from(
                r"C:\ProgramData\BadVpn\components\mihomo.exe",
            )),
        };
        let external_process = RunningProcess {
            name: "mihomo.exe".to_string(),
            pid: 43,
            executable_path: Some(PathBuf::from(r"C:\Tools\mihomo\mihomo.exe")),
        };
        let missing_path_process = RunningProcess {
            name: "mihomo.exe".to_string(),
            pid: 44,
            executable_path: None,
        };
        let different_binary_process = RunningProcess {
            name: "winws.exe".to_string(),
            pid: 45,
            executable_path: Some(managed.clone()),
        };

        assert!(process_is_managed_mihomo(&managed_process, Some(&managed)));
        assert!(!process_is_managed_mihomo(
            &external_process,
            Some(&managed)
        ));
        assert!(!process_is_managed_mihomo(
            &missing_path_process,
            Some(&managed)
        ));
        assert!(!process_is_managed_mihomo(
            &different_binary_process,
            Some(&managed)
        ));
    }

    fn test_request() -> ConnectRequest {
        ConnectRequest {
            profile_body: "proxies:\n  - name: Test\n    type: direct\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - Test\nrules:\n  - MATCH,PROXY\n".to_string(),
            subscription: SubscriptionState::default(),
            selected_proxies: BTreeMap::new(),
            route_mode: RuntimeMode::Smart,
            settings: RuntimeSettings {
                mihomo: MihomoConfigOptions::default(),
                zapret: RuntimeZapretSettings::default(),
                diagnostics: RuntimeDiagnosticsSettings::default(),
            },
        }
    }
}
