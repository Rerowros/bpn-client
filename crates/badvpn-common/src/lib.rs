pub mod errors;
pub mod ipc;
pub mod mihomo_config;
pub mod policy;
pub mod subscription;

pub use errors::{BadVpnError, BadVpnResult};
pub use ipc::{
    AgentCommand, AgentRuntimeSnapshot, AgentState, AppPhase, ConnectRequest, ConnectionState,
    ConnectionStatus, DiagnosticSummary, PreflightCheck, PreflightSeverity, PreflightStatus,
    RouteMode, RuntimeComponentSnapshot, RuntimeComponentState, RuntimeDiagnosticsSettings,
    RuntimeGameProfile, RuntimeMode, RuntimePhase, RuntimeSettings, RuntimeZapretSettings,
    SubscriptionState, TrafficMetrics, AGENT_LOCAL_ADDR, AGENT_PIPE_NAME,
};
pub use mihomo_config::{
    flowseal_exclude_hostlist, flowseal_general_hostlist, flowseal_google_hostlist,
    flowseal_ipset_exclude, flowseal_target_hostlist, generate_mihomo_config_from_subscription,
    generate_mihomo_config_from_subscription_with_options, overlay_mihomo_config_yaml,
    smart_hybrid_direct_rules, zapret_default_hostlist, zapret_default_ipset,
    zapret_user_placeholder_hostlist, GeneratedMihomoConfig, MihomoConfigOptions,
};
pub use policy::{
    compile_policy, AppRouteMode, CompiledPolicy, DnsPolicyRule, ManagedProxyGroup,
    PolicyCompileInput, PolicyPath, PolicyRule, PolicySource, PolicyTarget, PolicyTargetKind,
    ProxyGroupInfo, ProxyGroupResolution, ProxyNode, RouteExpectation, RoutingPolicySettings,
    RuntimeFacts, SmartPresetSettings, SuppressedRule, ZapretCoverage,
};
pub use subscription::{
    decode_header_value, parse_subscription_userinfo, subscription_body_to_text,
    summarize_subscription_body, SubscriptionBodySummary, SubscriptionFormat, SubscriptionUserInfo,
};
