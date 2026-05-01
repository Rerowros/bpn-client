use badvpn_common::{
    AgentCommand, AgentState, AppPhase, BadVpnError, BadVpnResult, ConnectRequest,
    DiagnosticSummary,
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    runtime::{cleanup_legacy_zapret_service, snapshot_to_agent_state, RuntimeManager},
    security::redact_url,
    service,
    state::AgentRuntimeState,
};

#[derive(Debug, Default)]
pub struct AgentController {
    runtime: AgentRuntimeState,
    manager: RuntimeManager,
}

impl AgentController {
    pub async fn handle(&mut self, command: AgentCommand) -> BadVpnResult<AgentState> {
        tracing::debug!(command = ?command_kind(&command), "agent command received");
        match command {
            AgentCommand::Status => Ok(self.runtime_status()),
            AgentCommand::RuntimeStatus => Ok(self.runtime_status()),
            AgentCommand::Connect { request } => self.connect(*request).await,
            AgentCommand::Start => {
                self.runtime
                    .set_error("ConnectRequest is required for service-first runtime start");
                Ok(self.runtime.snapshot())
            }
            AgentCommand::Stop => self.stop().await,
            AgentCommand::Restart => self.restart().await,
            AgentCommand::SetSubscription { url } => self.set_subscription(url).await,
            AgentCommand::RefreshSubscription => self.refresh_subscription().await,
            AgentCommand::RunDiagnostics => self.run_diagnostics().await,
            AgentCommand::CleanupLegacyZapret => self.cleanup_legacy_zapret().await,
            AgentCommand::VerifyInstalledAgent => self.verify_installed_agent().await,
            AgentCommand::SelectProxy { .. }
            | AgentCommand::SetRouteMode { .. }
            | AgentCommand::SetDpiProfile { .. }
            | AgentCommand::UpdateComponents
            | AgentCommand::RollbackComponent { .. } => {
                self.runtime
                    .set_error("command is planned but not implemented in M1 scaffold");
                Ok(self.runtime.snapshot())
            }
        }
    }

    fn runtime_status(&mut self) -> AgentState {
        let snapshot = self.manager.snapshot();
        self.runtime = AgentRuntimeState::from_agent_state(snapshot_to_agent_state(
            &snapshot,
            self.runtime.subscription.clone(),
        ));
        self.runtime.snapshot()
    }

    async fn connect(&mut self, request: ConnectRequest) -> BadVpnResult<AgentState> {
        self.runtime.subscription = request.subscription.clone();
        let snapshot = self
            .manager
            .connect(request)
            .await
            .map_err(|error| BadVpnError::OperationFailed(error.to_string()))?;
        self.runtime = AgentRuntimeState::from_agent_state(snapshot_to_agent_state(
            &snapshot,
            self.runtime.subscription.clone(),
        ));
        Ok(self.runtime.snapshot())
    }

    async fn stop(&mut self) -> BadVpnResult<AgentState> {
        let snapshot = self
            .manager
            .stop()
            .await
            .map_err(|error| BadVpnError::OperationFailed(error.to_string()))?;
        self.runtime = AgentRuntimeState::from_agent_state(snapshot_to_agent_state(
            &snapshot,
            self.runtime.subscription.clone(),
        ));
        self.runtime.clear_error();
        Ok(self.runtime.snapshot())
    }

    async fn restart(&mut self) -> BadVpnResult<AgentState> {
        let snapshot = self
            .manager
            .restart()
            .await
            .map_err(|error| BadVpnError::OperationFailed(error.to_string()))?;
        self.runtime = AgentRuntimeState::from_agent_state(snapshot_to_agent_state(
            &snapshot,
            self.runtime.subscription.clone(),
        ));
        Ok(self.runtime.snapshot())
    }

    async fn set_subscription(&mut self, url: String) -> BadVpnResult<AgentState> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            self.runtime
                .set_subscription_error(BadVpnError::EmptySubscriptionUrl.to_string());
            return Ok(self.runtime.snapshot());
        }

        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            self.runtime
                .set_subscription_error(BadVpnError::InvalidSubscriptionUrl.to_string());
            return Ok(self.runtime.snapshot());
        }

        self.runtime.subscription.url = Some(trimmed.to_string());
        self.runtime.subscription.is_valid = Some(true);
        self.runtime.subscription.validation_error = None;
        self.runtime.set_phase(AppPhase::Ready);
        self.runtime.clear_error();
        tracing::info!(subscription = %redact_url(trimmed), "subscription accepted");
        Ok(self.runtime.snapshot())
    }

    async fn refresh_subscription(&mut self) -> BadVpnResult<AgentState> {
        if self.runtime.subscription.url.is_none() {
            self.runtime
                .set_subscription_error("subscription URL is required before refresh");
            return Ok(self.runtime.snapshot());
        }

        self.runtime.subscription.is_valid = Some(true);
        self.runtime.subscription.validation_error = None;
        Ok(self.runtime.snapshot())
    }

    async fn run_diagnostics(&mut self) -> BadVpnResult<AgentState> {
        self.runtime.diagnostics = DiagnosticSummary {
            mihomo_healthy: self.manager.snapshot().mihomo.state
                == badvpn_common::RuntimeComponentState::Running,
            zapret_healthy: self.manager.snapshot().zapret.state
                == badvpn_common::RuntimeComponentState::Running,
            message: Some("Service-first runtime manager diagnostics are available.".to_string()),
        };
        Ok(self.runtime.snapshot())
    }

    async fn cleanup_legacy_zapret(&mut self) -> BadVpnResult<AgentState> {
        match cleanup_legacy_zapret_service() {
            Ok(message) => {
                self.runtime.diagnostics = DiagnosticSummary {
                    mihomo_healthy: self.manager.snapshot().mihomo.state
                        == badvpn_common::RuntimeComponentState::Running,
                    zapret_healthy: self.manager.snapshot().zapret.state
                        == badvpn_common::RuntimeComponentState::Running,
                    message: Some(message),
                };
                Ok(self.runtime.snapshot())
            }
            Err(error) => {
                self.runtime.set_error(format!(
                    "failed to clean legacy BadVpnZapret service: {error}"
                ));
                Ok(self.runtime.snapshot())
            }
        }
    }

    async fn verify_installed_agent(&mut self) -> BadVpnResult<AgentState> {
        let status = service::status();
        self.runtime.installed = status.installed;
        self.runtime.running = status.running;
        self.runtime.diagnostics = DiagnosticSummary {
            mihomo_healthy: self.manager.snapshot().mihomo.state
                == badvpn_common::RuntimeComponentState::Running,
            zapret_healthy: self.manager.snapshot().zapret.state
                == badvpn_common::RuntimeComponentState::Running,
            message: Some(format!(
                "Installed agent verification: {}{}",
                status.message,
                installed_agent_attestation_message()
                    .map(|message| format!(" {message}"))
                    .unwrap_or_default()
            )),
        };
        Ok(self.runtime.snapshot())
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
        AgentCommand::VerifyInstalledAgent => "verify_installed_agent",
        AgentCommand::UpdateComponents => "update_components",
        AgentCommand::RollbackComponent { .. } => "rollback_component",
    }
}
