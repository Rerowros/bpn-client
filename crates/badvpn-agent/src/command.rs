use badvpn_common::{
    AgentCommand, AgentState, AppPhase, BadVpnError, BadVpnResult, ConnectRequest,
    DiagnosticSummary,
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;

use crate::{
    runtime::{cleanup_legacy_zapret_service, repair_windows_network_state, RuntimeManager},
    security::redact_url,
    service,
    state::AgentRuntimeState,
};

struct AgentInner {
    runtime: AgentRuntimeState,
    manager: RuntimeManager,
}

pub struct AgentController {
    inner: Arc<Mutex<AgentInner>>,
    connecting: Arc<AtomicBool>,
    cancel_connect: Arc<AtomicBool>,
    connect_task: Option<tokio::task::JoinHandle<()>>,
    /// Progress visible to Status while connect holds the runtime lock.
    progress: Arc<std::sync::RwLock<AgentState>>,
}

impl Default for AgentController {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AgentInner {
                runtime: AgentRuntimeState::default(),
                manager: RuntimeManager::new(),
            })),
            connecting: Arc::new(AtomicBool::new(false)),
            cancel_connect: Arc::new(AtomicBool::new(false)),
            connect_task: None,
            progress: Arc::new(std::sync::RwLock::new(AgentState::default())),
        }
    }
}

impl AgentController {
    pub fn start_background_watchdog(&self) {
        let inner = Arc::clone(&self.inner);
        let connecting = Arc::clone(&self.connecting);
        let progress = Arc::clone(&self.progress);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if connecting.load(Ordering::SeqCst) {
                    continue;
                }
                let mut guard = inner.lock().await;
                guard.manager.refresh_process_state_for_watchdog();
                guard.manager.handle_late_mihomo_death_for_watchdog();
                if guard.manager.late_zapret_death_requires_fallback() {
                    match guard
                        .manager
                        .fallback_to_vpn_only_after_late_zapret_death()
                        .await
                    {
                        Ok(()) => {
                            tracing::warn!(
                                "watchdog applied VPN-only fallback after late zapret death"
                            );
                        }
                        Err(error) => {
                            tracing::error!(
                                %error,
                                "watchdog failed to apply VPN-only fallback after late zapret death"
                            );
                            guard.manager.set_error_for_watchdog(format!(
                                "Late zapret death fallback failed; Smart DIRECT rules may still be active: {error}"
                            ));
                        }
                    }
                }
                let snapshot = guard.manager.snapshot();
                let _ = snapshot;
                guard.runtime = AgentRuntimeState::from_agent_state(
                    guard
                        .manager
                        .to_agent_state(guard.runtime.subscription.clone()),
                );
                if let Ok(mut slot) = progress.write() {
                    *slot = guard.runtime.snapshot();
                }
            }
        });
    }

    pub async fn handle(&mut self, command: AgentCommand) -> BadVpnResult<AgentState> {
        tracing::debug!(command = ?command_kind(&command), "agent command received");
        match command {
            AgentCommand::Status => self.runtime_status().await,
            AgentCommand::RuntimeStatus => self.runtime_status().await,
            AgentCommand::Connect { request } => self.connect(*request).await,
            AgentCommand::Start => {
                let mut guard = self.inner.lock().await;
                guard
                    .runtime
                    .set_error("ConnectRequest is required for service-first runtime start");
                Ok(guard.runtime.snapshot())
            }
            AgentCommand::Stop => self.stop().await,
            AgentCommand::Restart => self.restart().await,
            AgentCommand::SetSubscription { url } => self.set_subscription(url).await,
            AgentCommand::RefreshSubscription => self.refresh_subscription().await,
            AgentCommand::RunDiagnostics => self.run_diagnostics().await,
            AgentCommand::CleanupLegacyZapret => self.cleanup_legacy_zapret().await,
            AgentCommand::RepairWindowsNetwork => self.repair_windows_network().await,
            AgentCommand::VerifyInstalledAgent => self.verify_installed_agent().await,
            AgentCommand::SelectProxy { group, proxy } => self.select_proxy(group, proxy).await,
            AgentCommand::SetRouteMode { .. }
            | AgentCommand::SetDpiProfile { .. }
            | AgentCommand::UpdateComponents
            | AgentCommand::RollbackComponent { .. }
            | AgentCommand::PolicySummary => {
                let mut guard = self.inner.lock().await;
                guard
                    .runtime
                    .set_error("command is planned but not implemented in M1 scaffold");
                Ok(guard.runtime.snapshot())
            }
        }
    }

    async fn runtime_status(&mut self) -> BadVpnResult<AgentState> {
        // Prefer a non-blocking view while connect is running so status polling
        // cannot wait behind a long Connect on the serial named-pipe loop.
        if self.connecting.load(Ordering::SeqCst) {
            if let Ok(progress) = self.progress.read() {
                return Ok(progress.clone());
            }
        }

        let mut guard = self.inner.lock().await;
        let _snapshot = guard.manager.status_snapshot().await;
        guard.runtime = AgentRuntimeState::from_agent_state(
            guard
                .manager
                .to_agent_state(guard.runtime.subscription.clone()),
        );
        if let Some(message) = crate::runtime::safe_mode_message() {
            let existing = guard
                .runtime
                .diagnostics
                .message
                .clone()
                .unwrap_or_default();
            if !existing.contains(message.as_str()) {
                guard.runtime.diagnostics.message = Some(if existing.is_empty() {
                    message
                } else {
                    format!("{message} {existing}")
                });
            }
        }
        let state = guard.runtime.snapshot();
        if let Ok(mut progress) = self.progress.write() {
            *progress = state.clone();
        }
        Ok(state)
    }

    pub fn policy_summary(&self) -> anyhow::Result<badvpn_common::ipc::PolicySummaryResponse> {
        // Blocking path for sync IPC PolicySummary; try_lock avoids waiting on connect.
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| anyhow::anyhow!("runtime is busy"))?;
        if let Some(policy) = guard.manager.active_policy() {
            let mut response: badvpn_common::ipc::PolicySummaryResponse = policy.into();
            response.source = "agent_runtime".to_string();
            Ok(response)
        } else {
            anyhow::bail!("no active policy");
        }
    }

    async fn connect(&mut self, request: ConnectRequest) -> BadVpnResult<AgentState> {
        if self.connecting.load(Ordering::SeqCst) {
            return Err(BadVpnError::OperationFailed(
                "Connect is already in progress".to_string(),
            ));
        }

        // Ensure any previous task is finished before starting another.
        if let Some(task) = self.connect_task.take() {
            let _ = task.await;
        }

        self.cancel_connect.store(false, Ordering::SeqCst);
        self.connecting.store(true, Ordering::SeqCst);

        {
            let mut guard = self.inner.lock().await;
            guard.runtime.subscription = request.subscription.clone();
            guard.runtime.set_phase(AppPhase::Connecting);
            guard.runtime.connection.status = badvpn_common::ConnectionStatus::Starting;
            guard.runtime.connection.connected = false;
            guard.runtime.clear_error();
            guard.runtime.diagnostics.message =
                Some("Connect started in background; poll status for progress.".to_string());
            if let Ok(mut progress) = self.progress.write() {
                *progress = guard.runtime.snapshot();
            }
        }

        let inner = Arc::clone(&self.inner);
        let connecting = Arc::clone(&self.connecting);
        let cancel = Arc::clone(&self.cancel_connect);
        let progress = Arc::clone(&self.progress);
        self.connect_task = Some(tokio::spawn(async move {
            let result = {
                let mut guard = inner.lock().await;
                guard
                    .manager
                    .connect_with_cancel(request, Some(cancel.as_ref()))
                    .await
            };
            let mut guard = inner.lock().await;
            match result {
                Ok(_snapshot) => {
                    guard.runtime = AgentRuntimeState::from_agent_state(
                        guard
                            .manager
                            .to_agent_state(guard.runtime.subscription.clone()),
                    );
                }
                Err(error) => {
                    if cancel.load(Ordering::SeqCst) {
                        guard.runtime.clear_error();
                        guard.runtime.set_phase(AppPhase::Ready);
                        guard.runtime.connection.status = badvpn_common::ConnectionStatus::Idle;
                        guard.runtime.connection.connected = false;
                        guard.runtime.diagnostics.message =
                            Some(format!("Connect cancelled: {error}"));
                    } else {
                        guard.runtime.set_error(error.to_string());
                    }
                }
            }
            if let Ok(mut slot) = progress.write() {
                *slot = guard.runtime.snapshot();
            }
            connecting.store(false, Ordering::SeqCst);
        }));

        let guard = self.inner.lock().await;
        Ok(guard.runtime.snapshot())
    }

    async fn stop(&mut self) -> BadVpnResult<AgentState> {
        self.cancel_connect.store(true, Ordering::SeqCst);
        if let Some(task) = self.connect_task.take() {
            // Give the connect loop a moment to observe cancel, then detach if stuck.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
            self.connecting.store(false, Ordering::SeqCst);
        }

        let mut guard = self.inner.lock().await;
        let _snapshot = guard
            .manager
            .stop()
            .await
            .map_err(|error| BadVpnError::OperationFailed(error.to_string()))?;
        guard.runtime = AgentRuntimeState::from_agent_state(
            guard
                .manager
                .to_agent_state(guard.runtime.subscription.clone()),
        );
        guard.runtime.clear_error();
        Ok(guard.runtime.snapshot())
    }

    pub async fn shutdown_cleanup(&mut self) -> anyhow::Result<()> {
        self.cancel_connect.store(true, Ordering::SeqCst);
        if let Some(task) = self.connect_task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
            self.connecting.store(false, Ordering::SeqCst);
        }
        let mut guard = self.inner.lock().await;
        let _snapshot = guard.manager.stop().await?;
        guard.runtime = AgentRuntimeState::from_agent_state(
            guard
                .manager
                .to_agent_state(guard.runtime.subscription.clone()),
        );
        guard.runtime.clear_error();
        Ok(())
    }

    async fn restart(&mut self) -> BadVpnResult<AgentState> {
        let request = {
            let guard = self.inner.lock().await;
            guard.manager.last_connect_request()
        };
        let Some(request) = request else {
            let mut guard = self.inner.lock().await;
            guard
                .runtime
                .set_error("Connect request is required before restart.".to_string());
            return Ok(guard.runtime.snapshot());
        };
        let _ = self.stop().await?;
        self.connect(request).await
    }

    async fn select_proxy(&mut self, group: String, proxy: String) -> BadVpnResult<AgentState> {
        if self.connecting.load(Ordering::SeqCst) {
            return Err(BadVpnError::OperationFailed(
                "Cannot select proxy while connect is in progress".to_string(),
            ));
        }
        let mut guard = self.inner.lock().await;
        let snapshot = guard
            .manager
            .select_proxy(group.trim(), proxy.trim())
            .await
            .map_err(|error| BadVpnError::OperationFailed(error.to_string()))?;
        guard.runtime = AgentRuntimeState::from_agent_state(
            guard
                .manager
                .to_agent_state(guard.runtime.subscription.clone()),
        );
        Ok(guard.runtime.snapshot())
    }

    async fn set_subscription(&mut self, url: String) -> BadVpnResult<AgentState> {
        let mut guard = self.inner.lock().await;
        let trimmed = url.trim();
        if trimmed.is_empty() {
            guard
                .runtime
                .set_subscription_error(BadVpnError::EmptySubscriptionUrl.to_string());
            return Ok(guard.runtime.snapshot());
        }

        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            guard
                .runtime
                .set_subscription_error(BadVpnError::InvalidSubscriptionUrl.to_string());
            return Ok(guard.runtime.snapshot());
        }

        guard.runtime.subscription.url = Some(trimmed.to_string());
        guard.runtime.subscription.is_valid = Some(true);
        guard.runtime.subscription.validation_error = None;
        guard.runtime.set_phase(AppPhase::Ready);
        guard.runtime.clear_error();
        tracing::info!(subscription = %redact_url(trimmed), "subscription accepted");
        Ok(guard.runtime.snapshot())
    }

    async fn refresh_subscription(&mut self) -> BadVpnResult<AgentState> {
        let mut guard = self.inner.lock().await;
        if guard.runtime.subscription.url.is_none() {
            guard
                .runtime
                .set_subscription_error("subscription URL is required before refresh");
            return Ok(guard.runtime.snapshot());
        }

        // Agent does not fetch subscription bodies; the GUI owns refresh and reconnect.
        guard.runtime.set_error(
            "RefreshSubscription is not implemented in badvpn-agent; refresh from the UI and reconnect."
                .to_string(),
        );
        Ok(guard.runtime.snapshot())
    }

    async fn run_diagnostics(&mut self) -> BadVpnResult<AgentState> {
        let mut guard = self.inner.lock().await;
        let _ = guard.manager.status_snapshot().await;
        let snapshot = guard.manager.snapshot();
        let mut messages = Vec::new();
        messages.push(format!(
            "phase={:?} desired={:?} effective={:?}",
            snapshot.phase, snapshot.desired_mode, snapshot.effective_mode
        ));
        messages.push(format!(
            "mihomo={:?} zapret={:?} windivert={:?}",
            snapshot.mihomo.state, snapshot.zapret.state, snapshot.windivert.state
        ));
        if let Some(detail) = snapshot.mihomo.detail.as_deref() {
            messages.push(format!("mihomo_detail={detail}"));
        }
        if let Some(detail) = snapshot.zapret.detail.as_deref() {
            messages.push(format!("zapret_detail={detail}"));
        }
        for check in snapshot.preflight.iter().take(8) {
            messages.push(format!(
                "preflight:{}:{}:{}",
                check.component, check.id, check.message
            ));
        }
        if let Some(safe) = crate::runtime::safe_mode_message() {
            messages.push(safe);
        }
        let service = service::status();
        messages.push(format!(
            "agent_service installed={} running={} state={:?}",
            service.installed, service.running, service.state
        ));
        for note in snapshot.diagnostics.iter().rev().take(5).rev() {
            messages.push(note.clone());
        }
        guard.runtime = AgentRuntimeState::from_agent_state(
            guard
                .manager
                .to_agent_state(guard.runtime.subscription.clone()),
        );
        guard.runtime.diagnostics = DiagnosticSummary {
            mihomo_healthy: snapshot.mihomo.state == badvpn_common::RuntimeComponentState::Running,
            zapret_healthy: snapshot.zapret.state == badvpn_common::RuntimeComponentState::Running,
            message: Some(messages.join(" | ")),
        };
        Ok(guard.runtime.snapshot())
    }

    async fn cleanup_legacy_zapret(&mut self) -> BadVpnResult<AgentState> {
        let mut guard = self.inner.lock().await;
        match cleanup_legacy_zapret_service() {
            Ok(message) => {
                let snapshot = guard.manager.snapshot();
                guard.runtime.diagnostics = DiagnosticSummary {
                    mihomo_healthy: snapshot.mihomo.state
                        == badvpn_common::RuntimeComponentState::Running,
                    zapret_healthy: snapshot.zapret.state
                        == badvpn_common::RuntimeComponentState::Running,
                    message: Some(message),
                };
                Ok(guard.runtime.snapshot())
            }
            Err(error) => {
                guard.runtime.set_error(format!(
                    "failed to clean legacy BadVpnZapret service: {error}"
                ));
                Ok(guard.runtime.snapshot())
            }
        }
    }

    async fn repair_windows_network(&mut self) -> BadVpnResult<AgentState> {
        let _ = self.stop().await?;
        let mut guard = self.inner.lock().await;
        match repair_windows_network_state() {
            Ok(message) => {
                guard.runtime.diagnostics = DiagnosticSummary {
                    mihomo_healthy: false,
                    zapret_healthy: false,
                    message: Some(message),
                };
                guard.runtime.clear_error();
                Ok(guard.runtime.snapshot())
            }
            Err(error) => {
                let message = format!("failed to repair Windows network state: {error}");
                guard.runtime.set_error(message.clone());
                Err(BadVpnError::OperationFailed(message))
            }
        }
    }

    async fn verify_installed_agent(&mut self) -> BadVpnResult<AgentState> {
        let status = service::status();
        let mut guard = self.inner.lock().await;
        guard.runtime.installed = status.installed;
        guard.runtime.running = status.running;
        let snapshot = guard.manager.snapshot();
        guard.runtime.diagnostics = DiagnosticSummary {
            mihomo_healthy: snapshot.mihomo.state == badvpn_common::RuntimeComponentState::Running,
            zapret_healthy: snapshot.zapret.state == badvpn_common::RuntimeComponentState::Running,
            message: Some(format!(
                "Installed agent verification: {}{}",
                status.message,
                installed_agent_attestation_message()
                    .map(|message| format!(" {message}"))
                    .unwrap_or_default()
            )),
        };
        Ok(guard.runtime.snapshot())
    }
}

fn installed_agent_attestation_message() -> Option<String> {
    let program_data = std::env::var("PROGRAMDATA").ok()?;
    let path = PathBuf::from(program_data)
        .join("BadVpn")
        .join("agent")
        .join("badvpn-agent.exe");
    let metadata = std::fs::metadata(&path).ok()?;
    let sha256 = file_sha256(&path).unwrap_or_else(|| "sha256-unavailable".to_string());
    Some(format!(
        "path={} bytes={} sha256={sha256}",
        path.display(),
        metadata.len()
    ))
}

fn file_sha256(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let path_arg = path.to_string_lossy().to_string();
        let output = Command::new("certutil")
            .args(["-hashfile", path_arg.as_str(), "SHA256"])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .find(|line| line.len() == 64 && line.chars().all(|ch| ch.is_ascii_hexdigit()))
            .map(|line| line.to_ascii_uppercase())
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

fn command_kind(command: &AgentCommand) -> &'static str {
    match command {
        AgentCommand::Status => "status",
        AgentCommand::RuntimeStatus => "runtime_status",
        AgentCommand::Connect { .. } => "connect",
        AgentCommand::Start => "start",
        AgentCommand::Stop => "stop",
        AgentCommand::Restart => "restart",
        AgentCommand::SetSubscription { .. } => "set_subscription",
        AgentCommand::RefreshSubscription => "refresh_subscription",
        AgentCommand::SelectProxy { .. } => "select_proxy",
        AgentCommand::SetRouteMode { .. } => "set_route_mode",
        AgentCommand::SetDpiProfile { .. } => "set_dpi_profile",
        AgentCommand::RunDiagnostics => "run_diagnostics",
        AgentCommand::CleanupLegacyZapret => "cleanup_legacy_zapret",
        AgentCommand::RepairWindowsNetwork => "repair_windows_network",
        AgentCommand::VerifyInstalledAgent => "verify_installed_agent",
        AgentCommand::UpdateComponents => "update_components",
        AgentCommand::RollbackComponent { .. } => "rollback_component",
        AgentCommand::PolicySummary => "policy_summary",
    }
}
