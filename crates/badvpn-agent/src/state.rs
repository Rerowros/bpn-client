use badvpn_common::{
    AgentState, AppPhase, ConnectionState, DiagnosticSummary, SubscriptionState, TrafficMetrics,
};

#[derive(Debug, Clone)]
pub struct AgentRuntimeState {
    pub installed: bool,
    pub running: bool,
    pub phase: AppPhase,
    pub subscription: SubscriptionState,
    pub connection: ConnectionState,
    pub metrics: TrafficMetrics,
    pub diagnostics: DiagnosticSummary,
    pub last_error: Option<String>,
}

impl Default for AgentRuntimeState {
    fn default() -> Self {
        Self {
            installed: false,
            running: false,
            phase: AppPhase::Onboarding,
            subscription: SubscriptionState::default(),
            connection: ConnectionState::default(),
            metrics: TrafficMetrics::default(),
            diagnostics: DiagnosticSummary::default(),
            last_error: None,
        }
    }
}

impl AgentRuntimeState {
    pub fn from_agent_state(state: AgentState) -> Self {
        Self {
            installed: state.installed,
            running: state.running,
            phase: state.phase,
            subscription: state.subscription,
            connection: state.connection,
            metrics: state.metrics,
            diagnostics: state.diagnostics,
            last_error: state.last_error,
        }
    }

    pub fn snapshot(&self) -> AgentState {
        AgentState {
            installed: self.installed,
            running: self.running,
            phase: self.phase,
            subscription: self.subscription.clone(),
            connection: self.connection.clone(),
            metrics: self.metrics,
            diagnostics: self.diagnostics.clone(),
            last_error: self.last_error.clone(),
        }
    }

    pub fn set_phase(&mut self, phase: AppPhase) {
        self.phase = phase;
    }

    pub fn set_error(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.last_error = Some(message.clone());
        self.phase = AppPhase::Error;
        self.connection.status = badvpn_common::ConnectionStatus::Error;
    }

    pub fn set_subscription_error(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.subscription = SubscriptionState {
            url: self.subscription.url.clone(),
            is_valid: Some(false),
            validation_error: Some(message.clone()),
            ..SubscriptionState::default()
        };
        self.last_error = Some(message);
        self.phase = AppPhase::Onboarding;
    }

    pub fn clear_error(&mut self) {
        self.last_error = None;
    }
}
