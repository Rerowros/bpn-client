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
    watchdog_transition: Arc<AtomicBool>,
    cancel_watchdog_transition: Arc<AtomicBool>,
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
            watchdog_transition: Arc::new(AtomicBool::new(false)),
            cancel_watchdog_transition: Arc::new(AtomicBool::new(false)),
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
        let watchdog_transition = Arc::clone(&self.watchdog_transition);
        let cancel_watchdog_transition = Arc::clone(&self.cancel_watchdog_transition);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if connecting.load(Ordering::SeqCst) {
                    continue;
                }
                // Publish the non-blocking snapshot path before taking `inner` so
                // Status cannot lose a race and wait behind fallback validation.
                watchdog_transition.store(true, Ordering::SeqCst);
                let mut guard = inner.lock().await;
                if cancel_watchdog_transition.load(Ordering::SeqCst) {
                    drop(guard);
                    watchdog_transition.store(false, Ordering::SeqCst);
                    continue;
                }
                guard.manager.refresh_process_state_for_watchdog();
                guard.manager.handle_late_mihomo_death_for_watchdog();
                if guard.manager.late_zapret_death_requires_fallback() {
                    guard.runtime = AgentRuntimeState::from_agent_state(
                        guard
                            .manager
                            .to_agent_state(guard.runtime.subscription.clone()),
                    );
                    if let Ok(mut slot) = progress.write() {
                        *slot = guard.runtime.snapshot();
                    }
                    match guard
                        .manager
                        .fallback_to_vpn_only_after_late_zapret_death(Some(
                            cancel_watchdog_transition.as_ref(),
                        ))
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
                            if !cancel_watchdog_transition.load(Ordering::SeqCst) {
                                guard.manager.fail_closed_after_late_zapret_fallback(&error);
                            }
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
                drop(guard);
                watchdog_transition.store(false, Ordering::SeqCst);
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
        if self.connecting.load(Ordering::SeqCst) || self.watchdog_transition.load(Ordering::SeqCst)
        {
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

        let connecting_snapshot = {
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
            guard.runtime.snapshot()
        };

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
                    let message = if cancel.load(Ordering::SeqCst) {
                        format!("Connect cancelled: {error}")
                    } else {
                        error.to_string()
                    };
                    guard.manager.persist_background_connect_failure(message);
                    guard.runtime = AgentRuntimeState::from_agent_state(
                        guard
                            .manager
                            .to_agent_state(guard.runtime.subscription.clone()),
                    );
                }
            }
            if let Ok(mut slot) = progress.write() {
                *slot = guard.runtime.snapshot();
            }
            connecting.store(false, Ordering::SeqCst);
        }));

        Ok(connecting_snapshot)
    }

    async fn stop(&mut self) -> BadVpnResult<AgentState> {
        self.cancel_connect.store(true, Ordering::SeqCst);
        // This is intentionally set before taking `inner`: a watchdog fallback may
        // hold that mutex while waiting on Mihomo, but will observe cancellation.
        self.cancel_watchdog_transition
            .store(true, Ordering::SeqCst);
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
        let state = guard.runtime.snapshot();
        drop(guard);
        // A completed Stop establishes the idle baseline for future watchdog ticks.
        // Never clear this while Stop is pending behind the runtime mutex.
        self.cancel_watchdog_transition
            .store(false, Ordering::SeqCst);
        Ok(state)
    }

    pub async fn shutdown_cleanup(&mut self) -> anyhow::Result<()> {
        self.cancel_connect.store(true, Ordering::SeqCst);
        self.cancel_watchdog_transition
            .store(true, Ordering::SeqCst);
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
        for note in crate::runtime::windivert_and_bfe_diagnostic_notes() {
            messages.push(note);
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
        redact_local_path(&path),
        metadata.len()
    ))
}

fn redact_local_path(path: &Path) -> String {
    let display = path.to_string_lossy();
    if let Ok(program_data) = std::env::var("PROGRAMDATA") {
        if !program_data.trim().is_empty() {
            return display.replace(&program_data, "%PROGRAMDATA%");
        }
    }
    display.into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn background_connect_returns_captured_connecting_snapshot_without_waiting_for_worker() {
        let mut controller = AgentController::default();
        let request = ConnectRequest {
            profile_body: String::new(),
            subscription: Default::default(),
            selected_proxies: BTreeMap::new(),
            route_mode: badvpn_common::RuntimeMode::Smart,
            settings: badvpn_common::RuntimeSettings::default(),
        };

        let state = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            controller.connect(request),
        )
        .await
        .expect("background Connect response must not wait for the runtime mutex")
        .unwrap();

        assert_eq!(state.phase, AppPhase::Connecting);
        assert_eq!(
            state.connection.status,
            badvpn_common::ConnectionStatus::Starting
        );
        if let Some(task) = controller.connect_task.take() {
            task.abort();
        }
    }

    #[tokio::test]
    async fn failed_background_connect_persists_manager_error_across_status_refresh() {
        let mut controller = AgentController::default();
        {
            let mut guard = controller.inner.lock().await;
            guard.manager.persist_background_connect_failure(
                "forced background connect failure".to_string(),
            );
            guard.runtime = AgentRuntimeState::from_agent_state(
                guard
                    .manager
                    .to_agent_state(guard.runtime.subscription.clone()),
            );
        }

        let state = controller.runtime_status().await.unwrap();
        assert_eq!(state.phase, AppPhase::Error);
        assert_eq!(
            state.connection.status,
            badvpn_common::ConnectionStatus::Error
        );
        assert!(!state.connection.connected);
        assert_eq!(
            state.last_error.as_deref(),
            Some("forced background connect failure")
        );
    }

    #[tokio::test]
    async fn status_remains_responsive_while_watchdog_transition_holds_runtime_mutex() {
        let mut controller = AgentController::default();
        controller.watchdog_transition.store(true, Ordering::SeqCst);
        let held_inner = Arc::clone(&controller.inner);
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let _guard = held_inner.lock().await;
            let _ = locked_tx.send(());
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });
        locked_rx.await.unwrap();

        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            controller.runtime_status(),
        )
        .await
        .expect("Status must use the progress snapshot during watchdog fallback")
        .unwrap();
        holder.abort();
    }

    #[tokio::test]
    async fn stop_requests_watchdog_cancellation_before_waiting_for_runtime_mutex() {
        let mut controller = AgentController::default();
        let cancel = Arc::clone(&controller.cancel_watchdog_transition);
        let cancel_for_holder = Arc::clone(&cancel);
        let held_inner = Arc::clone(&controller.inner);
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let _guard = held_inner.lock().await;
            let _ = locked_tx.send(());
            while !cancel_for_holder.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        });
        locked_rx.await.unwrap();
        let stopper = tokio::spawn(async move { controller.stop().await });

        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            while !cancel.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Stop must signal watchdog cancellation without waiting for the mutex");
        tokio::time::timeout(std::time::Duration::from_millis(250), stopper)
            .await
            .expect("Stop must complete after watchdog releases the runtime mutex")
            .unwrap()
            .unwrap();
        holder.await.unwrap();
        assert!(!cancel.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn pending_stop_cancellation_is_not_cleared_by_watchdog_transition_start() {
        let controller = AgentController::default();
        let held_inner = Arc::clone(&controller.inner);
        let guard = held_inner.lock().await;
        controller
            .cancel_watchdog_transition
            .store(true, Ordering::SeqCst);
        controller.start_background_watchdog();

        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            while !controller.watchdog_transition.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watchdog must publish transition before waiting for the mutex");

        assert!(controller.cancel_watchdog_transition.load(Ordering::SeqCst));
        drop(guard);
    }

    #[tokio::test]
    async fn shutdown_requests_watchdog_cancellation_before_waiting_for_runtime_mutex() {
        let mut controller = AgentController::default();
        let cancel = Arc::clone(&controller.cancel_watchdog_transition);
        let cancel_for_holder = Arc::clone(&cancel);
        let held_inner = Arc::clone(&controller.inner);
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let _guard = held_inner.lock().await;
            let _ = locked_tx.send(());
            while !cancel_for_holder.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        });
        locked_rx.await.unwrap();
        let cleanup = tokio::spawn(async move { controller.shutdown_cleanup().await });

        tokio::time::timeout(std::time::Duration::from_millis(250), async {
            while !cancel.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown must signal watchdog cancellation before waiting for the mutex");
        tokio::time::timeout(std::time::Duration::from_millis(250), cleanup)
            .await
            .expect("shutdown cleanup must complete after watchdog releases the mutex")
            .unwrap()
            .unwrap();
        holder.await.unwrap();
    }
}
