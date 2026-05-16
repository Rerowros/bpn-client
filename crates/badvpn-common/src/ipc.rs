use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    mihomo_config::MihomoConfigOptions,
    policy::{CompiledPolicy, PolicyPath},
    subscription::{SubscriptionFormat, SubscriptionUserInfo},
};

pub const AGENT_LOCAL_ADDR: &str = "127.0.0.1:38790";
pub const AGENT_PIPE_NAME: &str = r"\\.\pipe\badvpn-agent";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPhase {
    Init,
    Onboarding,
    Ready,
    Error,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Idle,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    #[serde(alias = "smart_hybrid", alias = "zapret_first")]
    Smart,
    #[serde(
        alias = "vpn_all",
        alias = "dpi_only",
        alias = "manual",
        alias = "unknown"
    )]
    VpnOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Idle,
    Preparing,
    StartingZapret,
    StartingMihomo,
    Verifying,
    Running,
    DegradedVpnOnly,
    Stopping,
    Error,
}

impl Default for RuntimePhase {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    #[serde(alias = "smart_hybrid", alias = "zapret_first")]
    Smart,
    #[serde(
        alias = "vpn_all",
        alias = "dpi_only",
        alias = "manual",
        alias = "unknown"
    )]
    VpnOnly,
}

impl RuntimeMode {
    pub fn as_route_mode(self) -> RouteMode {
        match self {
            Self::Smart => RouteMode::Smart,
            Self::VpnOnly => RouteMode::VpnOnly,
        }
    }
}

impl From<RouteMode> for RuntimeMode {
    fn from(value: RouteMode) -> Self {
        match value {
            RouteMode::Smart => Self::Smart,
            RouteMode::VpnOnly => Self::VpnOnly,
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Smart
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeComponentState {
    Stopped,
    Starting,
    Running,
    Unhealthy,
    Missing,
    Conflict,
}

impl Default for RuntimeComponentState {
    fn default() -> Self {
        Self::Stopped
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComponentSnapshot {
    pub state: RuntimeComponentState,
    pub detail: Option<String>,
}

impl RuntimeComponentSnapshot {
    pub fn new(state: RuntimeComponentState, detail: Option<String>) -> Self {
        Self { state, detail }
    }
}

impl Default for RuntimeComponentSnapshot {
    fn default() -> Self {
        Self {
            state: RuntimeComponentState::Stopped,
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightSeverity {
    BlockVpn,
    DegradeToVpnOnly,
    DiagnosticWarning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Passed,
    Failed,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub id: String,
    pub severity: PreflightSeverity,
    pub component: String,
    pub status: PreflightStatus,
    pub message: String,
    pub recommended_action: Option<String>,
}

impl PreflightCheck {
    pub fn new(
        id: impl Into<String>,
        severity: PreflightSeverity,
        component: impl Into<String>,
        status: PreflightStatus,
        message: impl Into<String>,
        recommended_action: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            component: component.into(),
            status,
            message: message.into(),
            recommended_action,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeGameProfile {
    pub id: String,
    pub title: String,
    pub process_names: Vec<String>,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub tcp_ports: Vec<String>,
    pub udp_ports: Vec<String>,
    pub filter_mode: String,
    pub risk_level: String,
    pub detected: bool,
}

impl Default for RuntimeGameProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            process_names: Vec::new(),
            domains: Vec::new(),
            cidrs: Vec::new(),
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            detected: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeZapretSettings {
    pub enabled: bool,
    pub strategy: String,
    pub game_filter: String,
    pub game_bypass_mode: String,
    pub game_filter_mode: String,
    pub active_game_profiles: Vec<RuntimeGameProfile>,
    pub learned_game_profiles: Vec<RuntimeGameProfile>,
    pub ipset_filter: String,
    pub auto_profile_fallback: bool,
    pub fallback_to_vpn_on_failed_probe: bool,
}

impl Default for RuntimeZapretSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: "auto".to_string(),
            game_filter: "off".to_string(),
            game_bypass_mode: "auto".to_string(),
            game_filter_mode: "udp_first".to_string(),
            active_game_profiles: Vec::new(),
            learned_game_profiles: Vec::new(),
            ipset_filter: "none".to_string(),
            auto_profile_fallback: true,
            fallback_to_vpn_on_failed_probe: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeDiagnosticsSettings {
    pub runtime_checks_after_connect: bool,
    pub discord_youtube_probes: bool,
}

impl Default for RuntimeDiagnosticsSettings {
    fn default() -> Self {
        Self {
            runtime_checks_after_connect: true,
            discord_youtube_probes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeSettings {
    pub mihomo: MihomoConfigOptions,
    pub zapret: RuntimeZapretSettings,
    pub diagnostics: RuntimeDiagnosticsSettings,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            mihomo: MihomoConfigOptions::default(),
            zapret: RuntimeZapretSettings::default(),
            diagnostics: RuntimeDiagnosticsSettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub profile_body: String,
    pub subscription: SubscriptionState,
    pub selected_proxies: BTreeMap<String, String>,
    pub route_mode: RuntimeMode,
    pub settings: RuntimeSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRuntimeSnapshot {
    pub phase: RuntimePhase,
    pub desired_mode: RuntimeMode,
    pub effective_mode: RuntimeMode,
    pub mihomo: RuntimeComponentSnapshot,
    pub zapret: RuntimeComponentSnapshot,
    pub windivert: RuntimeComponentSnapshot,
    pub preflight: Vec<PreflightCheck>,
    pub diagnostics: Vec<String>,
    pub last_error: Option<String>,
    pub active_config_id: Option<String>,
}

impl Default for AgentRuntimeSnapshot {
    fn default() -> Self {
        Self {
            phase: RuntimePhase::Idle,
            desired_mode: RuntimeMode::Smart,
            effective_mode: RuntimeMode::Smart,
            mihomo: RuntimeComponentSnapshot::default(),
            zapret: RuntimeComponentSnapshot::default(),
            windivert: RuntimeComponentSnapshot::default(),
            preflight: Vec::new(),
            diagnostics: Vec::new(),
            last_error: None,
            active_config_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "payload")]
pub enum AgentCommand {
    Status,
    RuntimeStatus,
    Connect { request: Box<ConnectRequest> },
    Start,
    Stop,
    Restart,
    SetSubscription { url: String },
    RefreshSubscription,
    SelectProxy { group: String, proxy: String },
    SetRouteMode { mode: RouteMode },
    SetDpiProfile { profile: String },
    RunDiagnostics,
    CleanupLegacyZapret,
    VerifyInstalledAgent,
    UpdateComponents,
    RollbackComponent { component: String },
    PolicySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionState {
    pub url: Option<String>,
    pub is_valid: Option<bool>,
    pub validation_error: Option<String>,
    pub last_refreshed_at: Option<String>,
    pub profile_title: Option<String>,
    pub announce: Option<String>,
    pub announce_url: Option<String>,
    pub support_url: Option<String>,
    pub profile_web_page_url: Option<String>,
    pub update_interval_hours: Option<u64>,
    pub user_info: SubscriptionUserInfo,
    pub node_count: usize,
    pub format: SubscriptionFormat,
}

impl Default for SubscriptionState {
    fn default() -> Self {
        Self {
            url: None,
            is_valid: None,
            validation_error: None,
            last_refreshed_at: None,
            profile_title: None,
            announce: None,
            announce_url: None,
            support_url: None,
            profile_web_page_url: None,
            update_interval_hours: None,
            user_info: SubscriptionUserInfo::default(),
            node_count: 0,
            format: SubscriptionFormat::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionState {
    pub connected: bool,
    pub status: ConnectionStatus,
    pub selected_profile: Option<String>,
    pub selected_proxy: Option<String>,
    pub route_mode: RouteMode,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            connected: false,
            status: ConnectionStatus::Idle,
            selected_profile: None,
            selected_proxy: None,
            route_mode: RouteMode::Smart,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficMetrics {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl Default for TrafficMetrics {
    fn default() -> Self {
        Self {
            upload_bytes: 0,
            download_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticSummary {
    pub mihomo_healthy: bool,
    pub zapret_healthy: bool,
    pub message: Option<String>,
}

impl Default for DiagnosticSummary {
    fn default() -> Self {
        Self {
            mihomo_healthy: false,
            zapret_healthy: false,
            message: Some("Diagnostics are not implemented yet.".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentState {
    pub installed: bool,
    pub running: bool,
    pub phase: AppPhase,
    pub subscription: SubscriptionState,
    pub connection: ConnectionState,
    pub metrics: TrafficMetrics,
    pub diagnostics: DiagnosticSummary,
    pub last_error: Option<String>,
}

impl Default for AgentState {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummaryResponse {
    pub available: bool,
    pub state: String,
    pub source: String,
    pub stale: bool,
    pub compiled_at: Option<u64>,
    pub policy_id: Option<String>,
    pub active_config_id: Option<String>,
    pub desired_mode: Option<RouteMode>,
    pub effective_mode: Option<RouteMode>,

    pub mode: String,
    pub main_proxy_group: String,
    pub final_rule: String,
    pub mihomo_rules: Vec<String>,
    pub zapret_hostlist: Vec<String>,
    pub zapret_hostlist_exclude: Vec<String>,
    pub zapret_ipset: Vec<String>,
    pub zapret_ipset_exclude: Vec<String>,
    pub dns_nameserver_policy: Vec<PolicyDnsRuleView>,
    pub policy_rules: Vec<PolicyRuleView>,
    pub suppressed_rules: Vec<SuppressedRuleView>,
    pub diagnostics_expectations: Vec<RouteExpectationView>,
    pub diagnostics_messages: Vec<String>,
    pub managed_proxy_groups: Vec<ManagedGroupView>,
    pub rule_count: usize,
    pub suppressed_count: usize,
    pub warnings_count: usize,
    pub zapret_domain_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleView {
    pub target_kind: String,
    pub target_value: String,
    pub path: String,
    pub path_group: Option<String>,
    pub source: String,
    pub priority: u16,
    pub original_rule: Option<String>,
    pub tags: Vec<String>,
    pub mihomo_rule: String,
    pub zapret_effect: String,
    pub dns_effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedRuleView {
    pub original_rule: String,
    pub chosen_rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteExpectationView {
    pub target: String,
    pub expected_path: String,
    pub expected_mihomo_action: String,
    pub expected_zapret: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDnsRuleView {
    pub pattern: String,
    pub nameservers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedGroupView {
    pub name: String,
    pub proxies: Vec<String>,
}

impl PolicySummaryResponse {
    pub fn empty() -> Self {
        Self {
            available: false,
            state: "none".to_string(),
            source: "none".to_string(),
            stale: false,
            compiled_at: None,
            policy_id: None,
            active_config_id: None,
            desired_mode: None,
            effective_mode: None,
            mode: String::new(),
            main_proxy_group: String::new(),
            final_rule: String::new(),
            mihomo_rules: Vec::new(),
            zapret_hostlist: Vec::new(),
            zapret_hostlist_exclude: Vec::new(),
            zapret_ipset: Vec::new(),
            zapret_ipset_exclude: Vec::new(),
            dns_nameserver_policy: Vec::new(),
            policy_rules: Vec::new(),
            suppressed_rules: Vec::new(),
            diagnostics_expectations: Vec::new(),
            diagnostics_messages: Vec::new(),
            managed_proxy_groups: Vec::new(),
            rule_count: 0,
            suppressed_count: 0,
            warnings_count: 0,
            zapret_domain_count: 0,
        }
    }
}

impl From<&CompiledPolicy> for PolicySummaryResponse {
    fn from(policy: &CompiledPolicy) -> Self {
        let mode = format!("{:?}", policy.mode);
        let final_rule = policy.mihomo_rules.last().cloned().unwrap_or_default();

        let policy_rules = policy
            .policy_rules
            .iter()
            .map(|rule| {
                let path_str = match &rule.path {
                    PolicyPath::DirectSafe => "DirectSafe".to_string(),
                    PolicyPath::ZapretDirect => "ZapretDirect".to_string(),
                    PolicyPath::VpnProxy { group } => format!("VpnProxy({})", group),
                    PolicyPath::Reject => "Reject".to_string(),
                };
                let path_group = match &rule.path {
                    PolicyPath::VpnProxy { group } => Some(group.clone()),
                    _ => None,
                };
                let mihomo_action = match &rule.path {
                    PolicyPath::DirectSafe => "DIRECT",
                    PolicyPath::ZapretDirect => "DIRECT",
                    PolicyPath::VpnProxy { .. } => "proxy group",
                    PolicyPath::Reject => "REJECT",
                };
                let target_kind_str = format!("{:?}", rule.target.kind);
                let mihomo_rule = rule.original_rule.clone().unwrap_or_else(|| {
                    format!(
                        "{},{},{}",
                        target_kind_str, rule.target.value, mihomo_action
                    )
                });
                let zapret_effect = match &rule.path {
                    PolicyPath::ZapretDirect => "hostlist/ipset".to_string(),
                    PolicyPath::VpnProxy { .. } => "exclude".to_string(),
                    _ => "none".to_string(),
                };
                let dns_effect = if matches!(rule.path, PolicyPath::VpnProxy { .. }) {
                    "trusted DoH".to_string()
                } else {
                    "default".to_string()
                };

                PolicyRuleView {
                    target_kind: target_kind_str,
                    target_value: rule.target.value.clone(),
                    path: path_str,
                    path_group,
                    source: format!("{:?}", rule.source),
                    priority: rule.priority,
                    original_rule: rule.original_rule.clone(),
                    tags: rule.tags.clone(),
                    mihomo_rule,
                    zapret_effect,
                    dns_effect,
                }
            })
            .collect();

        let suppressed_rules = policy
            .suppressed_rules
            .iter()
            .map(|rule| SuppressedRuleView {
                original_rule: rule.original_rule.clone(),
                chosen_rule: rule.chosen_rule.clone(),
                reason: rule.reason.clone(),
            })
            .collect();

        let diagnostics_expectations = policy
            .diagnostics_expectations
            .iter()
            .map(|exp| RouteExpectationView {
                target: exp.target.clone(),
                expected_path: format!("{:?}", exp.expected_path),
                expected_mihomo_action: exp.expected_mihomo_action.clone(),
                expected_zapret: exp.expected_zapret,
                source: format!("{:?}", exp.source),
            })
            .collect();

        let dns_nameserver_policy = policy
            .dns_nameserver_policy
            .iter()
            .map(|rule| PolicyDnsRuleView {
                pattern: rule.pattern.clone(),
                nameservers: rule.nameservers.clone(),
            })
            .collect();

        let managed_proxy_groups = policy
            .managed_proxy_groups
            .iter()
            .map(|group| ManagedGroupView {
                name: group.name.clone(),
                proxies: group.proxies.clone(),
            })
            .collect();

        let rule_count = policy.mihomo_rules.len();
        let suppressed_count = policy.suppressed_rules.len();
        let warnings_count = policy.diagnostics_messages.len();
        let zapret_domain_count = policy.zapret_hostlist.len();

        Self {
            available: true,
            state: "active".to_string(),
            source: "cache".to_string(),
            stale: false,
            compiled_at: None,
            policy_id: None,
            active_config_id: None,
            desired_mode: None,
            effective_mode: None,
            mode,
            main_proxy_group: policy.main_proxy_group.clone(),
            final_rule,
            mihomo_rules: policy.mihomo_rules.clone(),
            zapret_hostlist: policy.zapret_hostlist.clone(),
            zapret_hostlist_exclude: policy.zapret_hostlist_exclude.clone(),
            zapret_ipset: policy.zapret_ipset.clone(),
            zapret_ipset_exclude: policy.zapret_ipset_exclude.clone(),
            dns_nameserver_policy,
            policy_rules,
            suppressed_rules,
            diagnostics_expectations,
            diagnostics_messages: policy.diagnostics_messages.clone(),
            managed_proxy_groups,
            rule_count,
            suppressed_count,
            warnings_count,
            zapret_domain_count,
        }
    }
}
