use std::{
    fs::{self, File, OpenOptions},
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use badvpn_common::{
    generate_mihomo_config_from_subscription_with_options, AgentRuntimeSnapshot, AppRouteMode,
    CompiledPolicy, ConnectRequest, PreflightCheck, PreflightSeverity, PreflightStatus,
    RuntimeComponentSnapshot, RuntimeComponentState, RuntimeGameProfile, RuntimeMode, RuntimePhase,
    SubscriptionState,
};
use serde_yaml::Value as YamlValue;
use tokio::time::sleep;

const MIHOMO_READY_TIMEOUT: Duration = Duration::from_secs(12);
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
        }
    }

    pub fn snapshot(&mut self) -> AgentRuntimeSnapshot {
        self.refresh_process_state();
        self.record_late_zapret_death_if_needed();
        self.snapshot.clone()
    }

    pub async fn connect(&mut self, mut request: ConnectRequest) -> Result<AgentRuntimeSnapshot> {
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
            self.snapshot
                .diagnostics
                .push("Runtime operation is already in progress.".to_string());
            return Ok(self.snapshot.clone());
        }

        if self.mihomo.is_running() {
            self.snapshot.phase = RuntimePhase::Running;
            self.snapshot
                .diagnostics
                .push("BadVpn-owned Mihomo is already running.".to_string());
            return Ok(self.snapshot.clone());
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
        self.last_request = Some(request.clone());

        let preflight = match self.preflight(&request) {
            Ok(preflight) => preflight,
            Err(error) => {
                tracing::warn!(%error, "runtime preflight failed");
                self.set_error(error.to_string());
                return Ok(self.snapshot.clone());
            }
        };

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
            self.snapshot.zapret = RuntimeComponentSnapshot::new(
                RuntimeComponentState::Stopped,
                Some("zapret is disabled for VPN Only.".to_string()),
            );
        }

        self.snapshot.phase = RuntimePhase::Preparing;
        let mut runtime_config = self
            .build_runtime_config(&request, effective_mode)
            .context("failed to build Mihomo runtime config")?;
        self.prepare_runtime_config_for_local_mihomo(&mut runtime_config)?;
        self.record_policy_diagnostics(&runtime_config.policy);
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

        if should_start_zapret {
            write_compiled_zapret_lists(&self.component_store, &runtime_config.policy)
                .context("failed to write compiled zapret policy lists")?;
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
                    tracing::info!(message, "zapret started");
                    self.snapshot.zapret = RuntimeComponentSnapshot::new(
                        RuntimeComponentState::Running,
                        Some(message),
                    );
                }
                Err(error) => {
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
                    debug_assert_vpn_only_policy(&runtime_config.policy);
                    write_compiled_zapret_lists(&self.component_store, &runtime_config.policy)
                        .context("failed to write empty VPN-only zapret policy lists")?;
                    self.record_policy_diagnostics(&runtime_config.policy);
                    let fallback_draft = self
                        .config_store
                        .write_draft(&runtime_config.yaml)
                        .context("failed to write Mihomo VPN-only fallback draft config")?;
                    self.mihomo
                        .validate(&mihomo_bin, &fallback_draft, self.config_store.home_dir())
                        .context("Mihomo rejected VPN-only fallback config")?;
                }
            }
        }

        let run_path = self
            .config_store
            .promote_draft_to_run(&self.config_store.draft_path())
            .context("failed to promote Mihomo runtime config")?;

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

        self.snapshot.phase = RuntimePhase::Verifying;
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
                        "Falling back to VPN-only because winws stopped after probes failed."
                            .to_string(),
                    );
                    effective_mode = RuntimeMode::VpnOnly;
                    let fallback = self.build_runtime_config_with_secret(
                        &request,
                        effective_mode,
                        runtime_config.secret.clone(),
                    )?;
                    debug_assert_vpn_only_policy(&fallback.policy);
                    write_compiled_zapret_lists(&self.component_store, &fallback.policy)
                        .context("failed to write empty VPN-only zapret policy lists")?;
                    self.record_policy_diagnostics(&fallback.policy);
                    let fallback_draft = self.config_store.write_draft(&fallback.yaml)?;
                    self.mihomo.validate(
                        &mihomo_bin,
                        &fallback_draft,
                        self.config_store.home_dir(),
                    )?;
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
                        self.mihomo.start(
                            &mihomo_bin,
                            &fallback_run,
                            self.config_store.home_dir(),
                            request.settings.mihomo.controller_port,
                        )?;
                        self.mihomo
                            .wait_ready(
                                request.settings.mihomo.controller_port,
                                MIHOMO_READY_TIMEOUT,
                                &fallback.secret,
                            )
                            .await?;
                    }
                    let _ = self.zapret.stop();
                    self.snapshot.zapret = RuntimeComponentSnapshot::new(
                        RuntimeComponentState::Unhealthy,
                        Some(
                            "winws stopped after probe failure; disabled for VPN-only fallback"
                                .to_string(),
                        ),
                    );
                } else {
                    self.snapshot.diagnostics.push(
                        "Keeping Smart because winws is still running; service-level HTTPS probes are advisory."
                            .to_string(),
                    );
                }
            }
        }

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
        self.snapshot.phase =
            if request.route_mode == RuntimeMode::Smart && effective_mode == RuntimeMode::VpnOnly {
                RuntimePhase::DegradedVpnOnly
            } else {
                RuntimePhase::Running
            };
        self.snapshot.active_config_id = Some(runtime_config.config_id);
        self.snapshot.last_error = None;
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
        self.snapshot.phase = RuntimePhase::Idle;
        self.snapshot.effective_mode = self.snapshot.desired_mode;
        self.snapshot.mihomo = RuntimeComponentSnapshot::default();
        self.snapshot.zapret = RuntimeComponentSnapshot::default();
        self.snapshot.windivert = RuntimeComponentSnapshot::default();
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

        let external_vpn = running_process_names(&[
            "mihomo.exe",
            "clash.exe",
            "clash-meta.exe",
            "sing-box.exe",
            "v2rayn.exe",
        ]);
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
        self.build_runtime_config_with_secret(request, mode, generate_controller_secret()?)
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
        let messages = strip_missing_geodata_rules(&mut config.yaml, self.config_store.home_dir())?;
        for message in messages {
            tracing::warn!(message, "mihomo geodata rule disabled");
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

    fn set_error(&mut self, message: String) {
        tracing::error!(message, "runtime entered error state");
        self.snapshot.phase = RuntimePhase::Error;
        self.snapshot.last_error = Some(message.clone());
        self.snapshot
            .diagnostics
            .push(format!("Runtime error: {message}"));
        self.refresh_process_state();
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
        self.snapshot.mihomo.state = if self.mihomo.is_running() {
            RuntimeComponentState::Running
        } else {
            RuntimeComponentState::Stopped
        };
        self.snapshot.zapret.state = if self.zapret.is_running() {
            RuntimeComponentState::Running
        } else {
            RuntimeComponentState::Stopped
        };
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
            Some(MESSAGE.to_string()),
        );
    }

    fn last_controller_port(&self) -> u16 {
        self.last_request
            .as_ref()
            .map(|request| request.settings.mihomo.controller_port)
            .unwrap_or(9090)
    }
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
}

impl MihomoManager {
    fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn validate(&self, mihomo_bin: &Path, config_path: &Path, home_dir: &Path) -> Result<()> {
        tracing::debug!(
            mihomo = %mihomo_bin.display(),
            config = %config_path.display(),
            home = %home_dir.display(),
            "validating Mihomo config"
        );
        let output = Command::new(mihomo_bin)
            .arg("-t")
            .arg("-d")
            .arg(home_dir)
            .arg("-f")
            .arg(config_path)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to run {}", mihomo_bin.display()))?;
        if output.status.success() {
            tracing::debug!("Mihomo config validation succeeded");
            Ok(())
        } else {
            tracing::warn!(
                status = %output.status,
                "Mihomo config validation failed"
            );
            Err(anyhow!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
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
            tracing::error!(%status, controller_port, "Mihomo exited immediately");
            return Err(anyhow!(
                "Mihomo exited immediately with {status}; controller port {controller_port}"
            ));
        }
        tracing::info!(pid = child.id(), "Mihomo child started");
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
        let client = reqwest::Client::new();
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
        let client = reqwest::Client::new();
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

    async fn close_connections(&self, controller_port: u16, secret: &str) -> Result<()> {
        tracing::debug!(controller_port, "closing Mihomo controller connections");
        let client = reqwest::Client::new();
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
        } else {
            tracing::debug!("Mihomo stop skipped; no owned child");
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ZapretManager {
    child: Option<Child>,
}

impl ZapretManager {
    fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn start(
        &mut self,
        component_store: &ComponentStore,
        settings: &badvpn_common::RuntimeZapretSettings,
    ) -> Result<String> {
        self.stop()?;
        let winws = component_store.winws_bin()?;
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
        let mut child = Command::new(&winws)
            .current_dir(component_store.zapret_bin_dir())
            .args(&args)
            .stdin(Stdio::null())
            .stdout(log_stdio("winws.log")?)
            .stderr(log_stdio("winws.log")?)
            .spawn()
            .with_context(|| format!("failed to start {}", winws.display()))?;
        std::thread::sleep(Duration::from_millis(900));
        if let Some(status) = child.try_wait()? {
            tracing::error!(%status, "winws exited immediately");
            return Err(anyhow!(
                "winws exited immediately with {status}; WinDivert may need service elevation or another DPI tool owns the driver"
            ));
        }
        tracing::info!(pid = child.id(), "winws child started");
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
    let ipset_all = ensure_list_file(
        &lists.join("ipset-all.txt"),
        badvpn_common::zapret_default_ipset(),
    )?;
    let game_overlay = write_game_overlay_lists(&lists, settings)?;
    ensure_empty_list_file(&lists.join("list-general-user.txt"))?;
    ensure_empty_list_file(&lists.join("list-exclude-user.txt"))?;
    ensure_empty_list_file(&lists.join("ipset-exclude-user.txt"))?;

    if let Ok(mut args) = parse_flowseal_profile_bat(component_store, settings) {
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
        request
            .settings
            .mihomo
            .zapret_direct_processes
            .extend(profile.process_names.iter().cloned());
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
    if !path.exists() {
        write_file_atomically(path, &values.join("\n"))?;
    }
    Ok(path.to_path_buf())
}

fn write_compiled_zapret_lists(
    component_store: &ComponentStore,
    policy: &CompiledPolicy,
) -> Result<()> {
    let lists = component_store.zapret_lists_dir();
    fs::create_dir_all(&lists)?;
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

    write_policy_list_file(&lists.join("list-general.txt"), &policy.zapret_hostlist)?;
    write_policy_list_file(&lists.join("list-google.txt"), &policy.zapret_hostlist)?;
    write_policy_list_file(
        &lists.join("list-exclude.txt"),
        &policy.zapret_hostlist_exclude,
    )?;
    write_policy_list_file(&lists.join("ipset-all.txt"), &policy.zapret_ipset)?;
    write_policy_list_file(
        &lists.join("ipset-exclude.txt"),
        &policy.zapret_ipset_exclude,
    )?;
    write_policy_list_file(&lists.join("list-general-user.txt"), &[])?;
    write_policy_list_file(&lists.join("list-exclude-user.txt"), &[])?;
    write_policy_list_file(&lists.join("ipset-exclude-user.txt"), &[])?;
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
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()?;
    for url in [
        "https://discord.com/api/v9/experiments",
        "https://www.youtube.com/generate_204",
    ] {
        let mut last_error = None;
        for attempt in 1..=2 {
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

fn strip_missing_geodata_rules(yaml: &mut String, home: &Path) -> Result<Vec<String>> {
    let mut value: YamlValue =
        serde_yaml::from_str(yaml).context("failed to parse generated Mihomo YAML")?;
    let geosite_available = geodata_asset_exists(home, &["GeoSite.dat", "geosite.dat"]);
    let geoip_available = geodata_asset_exists(home, &["GeoIP.dat", "geoip.dat"]);
    let mut removed_geosite = 0usize;
    let mut removed_geoip = 0usize;

    if let Some(map) = value.as_mapping_mut() {
        if let Some(rules) = map
            .get_mut(YamlValue::String("rules".to_string()))
            .and_then(YamlValue::as_sequence_mut)
        {
            rules.retain(|rule| {
                let Some(text) = rule.as_str() else {
                    return true;
                };
                let normalized = text.trim_start().to_ascii_uppercase();
                if !geosite_available && normalized.starts_with("GEOSITE,") {
                    removed_geosite += 1;
                    return false;
                }
                if !geoip_available && normalized.starts_with("GEOIP,") {
                    removed_geoip += 1;
                    return false;
                }
                true
            });
        }
    }

    let mut messages = Vec::new();
    if removed_geosite > 0 {
        messages.push(format!(
            "Disabled {removed_geosite} GEOSITE provider rules because no local GeoSite.dat asset is installed; this prevents Mihomo startup-time downloads."
        ));
    }
    if removed_geoip > 0 {
        messages.push(format!(
            "Disabled {removed_geoip} GEOIP provider rules because no local GeoIP.dat asset is installed; this prevents Mihomo startup-time downloads."
        ));
    }
    if !messages.is_empty() {
        *yaml = serde_yaml::to_string(&value).context("failed to render Mihomo YAML")?;
    }
    Ok(messages)
}

fn geodata_asset_exists(home: &Path, names: &[&str]) -> bool {
    names.iter().any(|name| home.join(name).is_file())
        || fs::read_dir(home)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                let file_name = entry.file_name();
                let file_name = file_name.to_string_lossy();
                names
                    .iter()
                    .any(|name| file_name.eq_ignore_ascii_case(name))
            })
}

fn tcp_port_is_busy(port: u16) -> bool {
    TcpListener::bind((LOCALHOST, port)).is_err()
}

fn udp_port_is_busy(port: u16) -> bool {
    UdpSocket::bind((LOCALHOST, port)).is_err()
}

fn generate_controller_secret() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("failed to read OS random bytes for Mihomo secret: {error}"))?;
    Ok(format!("badvpn-{}", to_hex(&bytes)))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let byte = *byte;
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
            selected_proxy: None,
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

#[cfg(test)]
mod architecture_fix_tests {
    use super::*;

    #[test]
    fn controller_secret_is_random_shape() {
        let first = generate_controller_secret().unwrap();
        let second = generate_controller_secret().unwrap();

        assert!(first.starts_with("badvpn-"));
        assert_eq!(first.len(), "badvpn-".len() + 64);
        assert_ne!(first, second);
        assert!(!first["badvpn-".len()..]
            .chars()
            .all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn hex_encoding_is_lowercase_and_stable() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
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
    async fn duplicate_connect_returns_transition_snapshot() {
        let mut manager = RuntimeManager::new();
        manager.snapshot.phase = RuntimePhase::StartingMihomo;
        let snapshot = manager.connect(test_request()).await.unwrap();
        assert_eq!(snapshot.phase, RuntimePhase::StartingMihomo);
        assert!(snapshot
            .diagnostics
            .iter()
            .any(|message| message.contains("already in progress")));
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
        assert!(args.iter().any(|arg| arg.contains("ipset-all.txt")));
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
    fn smart_writes_zapret_lists_from_compiled_policy() {
        let root = std::env::temp_dir().join(format!("badvpn-policy-lists-test-{}", now_unix()));
        let components = root.join("components");
        let store = ComponentStore {
            root: components.clone(),
            appdata_fallback: None,
        };
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
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        write_compiled_zapret_lists(&store, &policy).unwrap();

        let lists = components.join("zapret").join("lists");
        assert!(fs::read_to_string(lists.join("zapret_hostlist.txt"))
            .unwrap()
            .contains("googlevideo.com"));
        assert!(
            fs::read_to_string(lists.join("zapret_hostlist_exclude.txt"))
                .unwrap()
                .contains("perplexity.ai")
        );
        assert!(fs::read_to_string(lists.join("list-general.txt"))
            .unwrap()
            .contains("googlevideo.com"));
        assert!(fs::read_to_string(lists.join("list-google.txt"))
            .unwrap()
            .contains("googlevideo.com"));
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
