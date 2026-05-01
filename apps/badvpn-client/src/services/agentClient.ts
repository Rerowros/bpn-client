import { invoke } from "@tauri-apps/api/core";

export type AppPhase =
  | "init"
  | "onboarding"
  | "ready"
  | "error"
  | "connecting"
  | "connected"
  | "disconnecting";

export type ConnectionStatus = "idle" | "starting" | "running" | "stopping" | "error";

export type RouteMode = "smart" | "vpn_only";
export type SubscriptionFormat = "base64_uri_list" | "uri_list" | "clash_yaml" | "unknown";
export type LogLevel = "error" | "warning" | "info" | "debug";
export type TunStack = "mixed" | "gvisor" | "system";
export type DnsMode = "fake-ip" | "redir-host";
export type DnsPreset = "cloudflare_google" | "cloudflare" | "google" | "quad9";
export type ZapretRunMode = "service" | "process";
export type ZapretGameFilter = "off" | "tcp_udp" | "tcp" | "udp";
export type GameBypassMode = "off" | "auto" | "manual";
export type GameFilterMode = "udp_first" | "tcp_udp" | "aggressive";
export type ZapretIpSetFilter = "none" | "any" | "loaded";
export type RuntimePhase =
  | "idle"
  | "preparing"
  | "starting_zapret"
  | "starting_mihomo"
  | "verifying"
  | "running"
  | "degraded_vpn_only"
  | "stopping"
  | "error";
export type RuntimeMode = "smart" | "vpn_only";
export type RuntimeComponentState =
  | "stopped"
  | "starting"
  | "running"
  | "unhealthy"
  | "missing"
  | "conflict";
export type ZapretStrategy =
  | "auto"
  | "general"
  | "alt"
  | "alt2"
  | "alt3"
  | "alt4"
  | "alt5"
  | "alt6"
  | "alt7"
  | "alt8"
  | "alt9"
  | "alt10"
  | "alt11"
  | "fake_tls_auto"
  | "fake_tls_auto_alt"
  | "fake_tls_auto_alt2"
  | "fake_tls_auto_alt3"
  | "simple_fake"
  | "simple_fake_alt"
  | "simple_fake_alt2";

export interface SubscriptionState {
  url: string | null;
  is_valid: boolean | null;
  validation_error: string | null;
  last_refreshed_at: string | null;
  profile_title: string | null;
  announce: string | null;
  announce_url: string | null;
  support_url: string | null;
  profile_web_page_url: string | null;
  update_interval_hours: number | null;
  user_info: {
    upload_bytes: number | null;
    download_bytes: number | null;
    total_bytes: number | null;
    expire_at: number | null;
  };
  node_count: number;
  format: SubscriptionFormat;
}

export interface AgentState {
  installed: boolean;
  running: boolean;
  phase: AppPhase;
  subscription: SubscriptionState;
  connection: {
    connected: boolean;
    status: ConnectionStatus;
    selected_profile: string | null;
    selected_proxy: string | null;
    route_mode: RouteMode;
  };
  metrics: {
    upload_bytes: number;
    download_bytes: number;
  };
  diagnostics: {
    mihomo_healthy: boolean;
    zapret_healthy: boolean;
    message: string | null;
  };
  last_error: string | null;
}

export interface ComponentUpdate {
  name: string;
  current_version: string;
  latest_version: string | null;
  release_url: string | null;
  update_available: boolean;
  error: string | null;
}

export interface ComponentUpdateReport {
  components: ComponentUpdate[];
}

export interface AppSettings {
  core: {
    route_mode: RouteMode;
    log_level: LogLevel;
    mixed_port: number;
    controller_port: number;
    allow_lan: boolean;
    ipv6: boolean;
  };
  tun: {
    enabled: boolean;
    stack: TunStack;
    strict_route: boolean;
    auto_route: boolean;
    auto_detect_interface: boolean;
  };
  dns: {
    mode: DnsMode;
    preset: DnsPreset;
  };
  zapret: {
    enabled: boolean;
    run_mode: ZapretRunMode;
    strategy: ZapretStrategy;
    game_filter: ZapretGameFilter;
    game_bypass_mode: GameBypassMode;
    game_filter_mode: GameFilterMode;
    learned_game_profiles: RuntimeGameProfile[];
    ipset_filter: ZapretIpSetFilter;
    auto_profile_fallback: boolean;
    fallback_to_vpn_on_failed_probe: boolean;
  };
  routing_policy: {
    force_vpn_domains: string[];
    force_vpn_cidrs: string[];
    force_zapret_domains: string[];
    force_zapret_cidrs: string[];
    force_zapret_processes: string[];
    force_zapret_tcp_ports: string[];
    force_zapret_udp_ports: string[];
    force_direct_domains: string[];
    force_direct_cidrs: string[];
    force_direct_processes: string[];
    smart_presets: {
      youtube_discord_zapret: boolean;
      games_zapret: boolean;
      ai_vpn: boolean;
      social_vpn: boolean;
      telegram_vpn_from_provider: boolean;
    };
    coverage: "curated" | "broad";
  };
  updates: {
    auto_flowseal_list_refresh: boolean;
  };
  diagnostics: {
    runtime_checks_after_connect: boolean;
    discord_youtube_probes: boolean;
  };
}

export interface RuntimeSettings {
  mihomo: {
    route_mode: RouteMode;
    log_level: string;
    mixed_port: number;
    controller_port: number;
    allow_lan: boolean;
    ipv6: boolean;
    tun_enabled: boolean;
    tun_stack: string;
    tun_strict_route: boolean;
    tun_auto_route: boolean;
    tun_auto_detect_interface: boolean;
    dns_mode: string;
    dns_nameservers: string[];
    zapret_direct_domains: string[];
    zapret_direct_cidrs: string[];
    zapret_direct_processes: string[];
    zapret_direct_tcp_ports: string[];
    zapret_direct_udp_ports: string[];
    selected_proxies: Record<string, string>;
    routing_policy: AppSettings["routing_policy"];
  };
  zapret: {
    enabled: boolean;
    strategy: string;
    game_filter: string;
    game_bypass_mode: string;
    game_filter_mode: string;
    active_game_profiles: RuntimeGameProfile[];
    learned_game_profiles: RuntimeGameProfile[];
    ipset_filter: string;
    auto_profile_fallback: boolean;
    fallback_to_vpn_on_failed_probe: boolean;
  };
  diagnostics: {
    runtime_checks_after_connect: boolean;
    discord_youtube_probes: boolean;
  };
}

export interface RuntimeGameProfile {
  id: string;
  title: string;
  process_names: string[];
  domains: string[];
  cidrs: string[];
  tcp_ports: string[];
  udp_ports: string[];
  filter_mode: GameFilterMode | string;
  risk_level: string;
  detected: boolean;
}

export interface ConnectRequest {
  profile_body: string;
  subscription: SubscriptionState;
  selected_proxies: Record<string, string>;
  route_mode: RuntimeMode;
  settings: RuntimeSettings;
}

export interface RuntimeComponentSnapshot {
  state: RuntimeComponentState;
  detail: string | null;
}

export interface AgentRuntimeSnapshot {
  phase: RuntimePhase;
  desired_mode: RuntimeMode;
  effective_mode: RuntimeMode;
  mihomo: RuntimeComponentSnapshot;
  zapret: RuntimeComponentSnapshot;
  windivert: RuntimeComponentSnapshot;
  preflight: unknown[];
  diagnostics: string[];
  last_error: string | null;
  active_config_id: string | null;
}

export type SettingsPatch = AppSettings;

export interface SettingsApplyResult {
  settings: AppSettings;
  restart_required: boolean;
  state: AgentState;
  message: string;
}

export interface SubscriptionProfilesState {
  active_id: string | null;
  profiles: SubscriptionProfileView[];
}

export interface SubscriptionProfileView {
  id: string;
  name: string;
  active: boolean;
  redacted_url: string | null;
  subscription: SubscriptionState;
  created_at: number;
  updated_at: number;
}

export interface SubscriptionProfilesApplyResult {
  profiles: SubscriptionProfilesState;
  state: AgentState;
  message: string;
}

export interface ZapretProfileState {
  selected: string;
  options: ZapretProfileOption[];
}

export interface ZapretProfileOption {
  id: string;
  label: string;
  description: string;
  selected: boolean;
}

export interface ZapretServiceStatus {
  service_name: string;
  installed: boolean;
  running: boolean;
  state: string | null;
  config_hash: string | null;
  expected_hash: string | null;
  repair_required: boolean;
  message: string;
}

export interface AgentServiceStatus {
  service_name: string;
  installed: boolean;
  running: boolean;
  state: string | null;
  ipc_ready: boolean;
  message: string;
}

export type RuntimeCheckStatus = "ok" | "warning" | "error";

export interface RuntimeDiagnosticCheck {
  id: string;
  label: string;
  status: RuntimeCheckStatus;
  message: string;
}

export interface RuntimeDiagnosticsReport {
  checked_at: number;
  mihomo_healthy: boolean;
  zapret_healthy: boolean;
  summary: string;
  checks: RuntimeDiagnosticCheck[];
}

export interface RuntimeUpdateResult {
  changed: boolean;
  messages: string[];
  state: AgentState;
}

export type ConnectionPath = "vpn" | "zapret" | "direct" | "blocked" | "unknown";

export interface TrackedConnection {
  id: string;
  state: "active" | "closed" | string;
  host: string;
  destination: string;
  network: string;
  connection_type: string;
  process: string | null;
  rule: string | null;
  rule_payload: string | null;
  chains: string[];
  upload_bytes: number;
  download_bytes: number;
  started_at: string | null;
  closed_at: number | null;
  path: ConnectionPath;
  path_label: string;
  path_note: string;
}

export interface ConnectionsSnapshot {
  active: TrackedConnection[];
  closed: TrackedConnection[];
  upload_total: number;
  download_total: number;
  refreshed_at: number;
  error: string | null;
}

export interface ProxyCatalog {
  groups: ProxyGroupView[];
  running: boolean;
  refreshed_at: number;
  error: string | null;
}

export interface ProxyGroupView {
  name: string;
  group_type: string;
  selected: string | null;
  nodes: ProxyNodeView[];
}

export interface ProxyNodeView {
  name: string;
  proxy_type: string | null;
  server: string | null;
  delay_ms: number | null;
  alive: boolean | null;
  is_group: boolean;
  selected: boolean;
}

export function getStatus(): Promise<AgentState> {
  return invoke<AgentState>("status");
}

export function startConnection(): Promise<AgentState> {
  return invoke<AgentState>("start");
}

export function stopConnection(): Promise<AgentState> {
  return invoke<AgentState>("stop");
}

export function restartConnection(): Promise<AgentState> {
  return invoke<AgentState>("restart");
}

export function setSubscription(url: string): Promise<AgentState> {
  return invoke<AgentState>("set_subscription", { url });
}

export function refreshSubscription(): Promise<AgentState> {
  return invoke<AgentState>("refresh_subscription");
}

export function getSubscriptionProfiles(): Promise<SubscriptionProfilesState> {
  return invoke<SubscriptionProfilesState>("subscription_profiles");
}

export function addSubscriptionProfile(url: string, name?: string): Promise<SubscriptionProfilesApplyResult> {
  return invoke<SubscriptionProfilesApplyResult>("add_subscription_profile", { url, name: name ?? null });
}

export function selectSubscriptionProfile(id: string): Promise<SubscriptionProfilesApplyResult> {
  return invoke<SubscriptionProfilesApplyResult>("select_subscription_profile", { id });
}

export function removeSubscriptionProfile(id: string): Promise<SubscriptionProfilesApplyResult> {
  return invoke<SubscriptionProfilesApplyResult>("remove_subscription_profile", { id });
}

export function checkComponentUpdates(): Promise<ComponentUpdateReport> {
  return invoke<ComponentUpdateReport>("check_component_updates");
}

export function getSettings(): Promise<AppSettings> {
  return invoke<AppSettings>("get_settings");
}

export function saveSettings(settings: SettingsPatch): Promise<SettingsApplyResult> {
  return invoke<SettingsApplyResult>("save_settings", { settings });
}

export function resetSettings(): Promise<SettingsApplyResult> {
  return invoke<SettingsApplyResult>("reset_settings");
}

export function getAgentServiceStatus(): Promise<AgentServiceStatus> {
  return invoke<AgentServiceStatus>("agent_service_status");
}

export function installAgentService(): Promise<AgentServiceStatus> {
  return invoke<AgentServiceStatus>("install_agent_service");
}

export function removeAgentService(): Promise<AgentServiceStatus> {
  return invoke<AgentServiceStatus>("remove_agent_service");
}

export function getZapretProfileState(): Promise<ZapretProfileState> {
  return invoke<ZapretProfileState>("zapret_profile_state");
}

export function getZapretServiceStatus(): Promise<ZapretServiceStatus> {
  return invoke<ZapretServiceStatus>("zapret_service_status");
}

export function setZapretProfile(profile: string): Promise<ZapretProfileState> {
  return invoke<ZapretProfileState>("set_zapret_profile", { profile });
}

export function runDiagnostics(): Promise<RuntimeDiagnosticsReport> {
  return invoke<RuntimeDiagnosticsReport>("run_diagnostics");
}

export function updateRuntimeComponents(): Promise<RuntimeUpdateResult> {
  return invoke<RuntimeUpdateResult>("update_runtime_components");
}

export function getConnectionsSnapshot(): Promise<ConnectionsSnapshot> {
  return invoke<ConnectionsSnapshot>("connections_snapshot");
}

export function closeConnection(id: string): Promise<ConnectionsSnapshot> {
  return invoke<ConnectionsSnapshot>("close_connection", { id });
}

export function closeAllConnections(): Promise<ConnectionsSnapshot> {
  return invoke<ConnectionsSnapshot>("close_all_connections");
}

export function clearClosedConnections(): Promise<ConnectionsSnapshot> {
  return invoke<ConnectionsSnapshot>("clear_closed_connections");
}

export function getProxyCatalog(): Promise<ProxyCatalog> {
  return invoke<ProxyCatalog>("proxy_catalog");
}

export function selectProxy(group: string, proxy: string): Promise<ProxyCatalog> {
  return invoke<ProxyCatalog>("select_proxy", { group, proxy });
}

export interface PolicyRuleView {
  target_kind: string;
  target_value: string;
  path: string;
  path_group: string | null;
  source: string;
  priority: number;
  original_rule: string | null;
  tags: string[];
  mihomo_rule: string;
  zapret_effect: string;
  dns_effect: string;
}

export interface SuppressedRuleView {
  original_rule: string;
  chosen_rule: string;
  reason: string;
}

export interface RouteExpectationView {
  target: string;
  expected_path: string;
  expected_mihomo_action: string;
  expected_zapret: boolean;
  source: string;
}

export interface PolicyDnsRuleView {
  pattern: string;
  nameservers: string[];
}

export interface ManagedGroupView {
  name: string;
  proxies: string[];
}

export interface PolicySummaryResponse {
  available: boolean;
  mode: string;
  main_proxy_group: string;
  final_rule: string;
  mihomo_rules: string[];
  zapret_hostlist: string[];
  zapret_hostlist_exclude: string[];
  zapret_ipset: string[];
  zapret_ipset_exclude: string[];
  dns_nameserver_policy: PolicyDnsRuleView[];
  policy_rules: PolicyRuleView[];
  suppressed_rules: SuppressedRuleView[];
  diagnostics_expectations: RouteExpectationView[];
  diagnostics_messages: string[];
  managed_proxy_groups: ManagedGroupView[];
  rule_count: number;
  suppressed_count: number;
  warnings_count: number;
  zapret_domain_count: number;
}

export function getPolicySummary(): Promise<PolicySummaryResponse> {
  return invoke<PolicySummaryResponse>("policy_summary");
}
