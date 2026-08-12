import { invoke } from "@tauri-apps/api/core";

type InvokeArgs = Record<string, unknown>;

function invokeCommand<T>(command: string, args?: InvokeArgs): Promise<T> {
  if (hasTauriRuntime()) {
    return invoke<T>(command, args);
  }
  if (import.meta.env.DEV) {
    return import("./agentMock").then(({ mockInvoke }) => mockInvoke(command, args) as T);
  }
  return invoke<T>(command, args);
}

function hasTauriRuntime() {
  return typeof window !== "undefined" && Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}

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
    mtu: number;
    dns_hijack: string[];
    excluded_routes: string[];
  };
  dns: {
    mode: DnsMode;
    preset: DnsPreset;
    fake_ip_range: string;
    fake_ip_filter: string[];
    nameserver_policy: NameServerPolicySetting[];
  };
  sniffer: {
    enabled: boolean;
    http: boolean;
    tls: boolean;
    quic: boolean;
    force_domains: string[];
    skip_domains: string[];
    skip_src_cidrs: string[];
    skip_dst_cidrs: string[];
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
    local_overrides_enabled: boolean;
    local_overrides: LocalOverridesSettings;
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
    safe_resource_auto_update_interval_hours: number;
  };
  diagnostics: {
    runtime_checks_after_connect: boolean;
    discord_youtube_probes: boolean;
  };
}

export interface NameServerPolicySetting {
  pattern: string;
  nameservers: string[];
}

export interface LocalOverridesSettings {
  version: number;
  rules: LocalOverrideRule[];
}

export type LocalOverridePath = "direct" | "vpn" | "zapret";
export type LocalOverrideRuleTargetKind = "domain" | "cidr" | "process" | "app" | "tcp_port" | "udp_port";
export type LocalOverrideSource = "user" | "migrated_force_list" | "learned_game" | "preset";

export interface LocalOverrideRule {
  id: string;
  enabled: boolean;
  title: string;
  path: LocalOverridePath;
  target_kind: LocalOverrideRuleTargetKind;
  value: string;
  executable_path: string | null;
  process_name: string | null;
  source: LocalOverrideSource;
  created_at: number;
  updated_at: number;
  last_applied_at: number | null;
  last_policy_trace_id: string | null;
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
  enabled: boolean;
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

export type SubscriptionFetchProxyMode = "direct" | "system" | "custom";

export interface SubscriptionFetchOptionsView {
  timeout_seconds: number;
  proxy_mode: SubscriptionFetchProxyMode;
  custom_proxy_redacted: string | null;
  user_agent: string | null;
}

export interface SubscriptionProfileView {
  id: string;
  name: string;
  description: string | null;
  active: boolean;
  redacted_url: string | null;
  subscription: SubscriptionState;
  last_successful_refresh_at: number | null;
  last_failed_refresh_at: number | null;
  last_refresh_error: string | null;
  next_refresh_at: number | null;
  fetch_options: SubscriptionFetchOptionsView;
  created_at: number;
  updated_at: number;
}

export interface SubscriptionProfilesApplyResult {
  profiles: SubscriptionProfilesState;
  state: AgentState;
  message: string;
}

export interface LocalProfilePreview {
  display_name: string;
  source_file_name: string | null;
  format: SubscriptionFormat;
  node_count: number;
  decoded_size_bytes: number;
  import_ready: boolean;
  warning: string | null;
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

export interface RuntimeReadinessResponse {
  agent: AgentServiceStatus;
  mihomo_ready: boolean;
  zapret_ready: boolean;
  needs_zapret: boolean;
  components_ready: boolean;
  ready: boolean;
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
  process_path: string | null;
  rule: string | null;
  rule_payload: string | null;
  rule_source: string | null;
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
  api_name?: string;
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
  return invokeCommand<AgentState>("status");
}

export function startConnection(): Promise<AgentState> {
  return invokeCommand<AgentState>("start");
}

export function stopConnection(): Promise<AgentState> {
  return invokeCommand<AgentState>("stop");
}

export function restartConnection(): Promise<AgentState> {
  return invokeCommand<AgentState>("restart");
}

export function setSubscription(url: string): Promise<AgentState> {
  return invokeCommand<AgentState>("set_subscription", { url });
}

export function refreshSubscription(): Promise<AgentState> {
  return invokeCommand<AgentState>("refresh_subscription");
}

export function getSubscriptionProfiles(): Promise<SubscriptionProfilesState> {
  return invokeCommand<SubscriptionProfilesState>("subscription_profiles");
}

export function addSubscriptionProfile(url: string, name?: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("add_subscription_profile", { url, name: name ?? null });
}

export function selectSubscriptionProfile(id: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("select_subscription_profile", { id });
}

export function removeSubscriptionProfile(id: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("remove_subscription_profile", { id });
}

export function updateSubscriptionProfileMetadata(
  id: string,
  description?: string | null,
): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("update_subscription_profile_metadata", {
    id,
    description: description ?? null,
  });
}

export function updateSubscriptionProfileFetchOptions(
  id: string,
  timeoutSeconds: number,
  proxyMode: SubscriptionFetchProxyMode,
  customProxyUrl?: string,
  userAgent?: string | null,
): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("update_subscription_profile_fetch_options", {
    id,
    timeoutSeconds,
    proxyMode,
    customProxyUrl: customProxyUrl ?? null,
    userAgent: userAgent ?? null,
  });
}

export function checkComponentUpdates(): Promise<ComponentUpdateReport> {
  return invokeCommand<ComponentUpdateReport>("check_component_updates");
}

export function getRuntimeReadiness(): Promise<RuntimeReadinessResponse> {
  return invokeCommand<RuntimeReadinessResponse>("runtime_readiness");
}

export function getSettings(): Promise<AppSettings> {
  return invokeCommand<AppSettings>("get_settings");
}

export function saveSettings(settings: SettingsPatch): Promise<SettingsApplyResult> {
  return invokeCommand<SettingsApplyResult>("save_settings", { settings });
}

export function resetSettings(): Promise<SettingsApplyResult> {
  return invokeCommand<SettingsApplyResult>("reset_settings");
}

export function getAgentServiceStatus(): Promise<AgentServiceStatus> {
  return invokeCommand<AgentServiceStatus>("agent_service_status");
}

export function installAgentService(): Promise<AgentServiceStatus> {
  return invokeCommand<AgentServiceStatus>("install_agent_service");
}

export function removeAgentService(): Promise<AgentServiceStatus> {
  return invokeCommand<AgentServiceStatus>("remove_agent_service");
}

export function getZapretProfileState(): Promise<ZapretProfileState> {
  return invokeCommand<ZapretProfileState>("zapret_profile_state");
}

export function getZapretServiceStatus(): Promise<ZapretServiceStatus> {
  return invokeCommand<ZapretServiceStatus>("zapret_service_status");
}

export function setZapretProfile(profile: string): Promise<ZapretProfileState> {
  return invokeCommand<ZapretProfileState>("set_zapret_profile", { profile });
}

export function runDiagnostics(): Promise<RuntimeDiagnosticsReport> {
  return invokeCommand<RuntimeDiagnosticsReport>("run_diagnostics");
}

export function updateRuntimeComponents(): Promise<RuntimeUpdateResult> {
  return invokeCommand<RuntimeUpdateResult>("update_runtime_components");
}

export function getConnectionsSnapshot(): Promise<ConnectionsSnapshot> {
  return invokeCommand<ConnectionsSnapshot>("connections_snapshot");
}

export function closeConnection(id: string): Promise<ConnectionsSnapshot> {
  return invokeCommand<ConnectionsSnapshot>("close_connection", { id });
}

export function closeAllConnections(): Promise<ConnectionsSnapshot> {
  return invokeCommand<ConnectionsSnapshot>("close_all_connections");
}

export function clearClosedConnections(): Promise<ConnectionsSnapshot> {
  return invokeCommand<ConnectionsSnapshot>("clear_closed_connections");
}

export function getProxyCatalog(): Promise<ProxyCatalog> {
  return invokeCommand<ProxyCatalog>("proxy_catalog");
}

export function selectProxy(group: string, proxy: string): Promise<ProxyCatalog> {
  return invokeCommand<ProxyCatalog>("select_proxy", { group, proxy });
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
  source_group: string;
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
  return invokeCommand<PolicySummaryResponse>("policy_summary");
}

export interface OperatorSnapshot {
  generated_at: number;
  providers: ProviderCatalog;
  resources: ResourceCatalog;
  logs: RuntimeLogSnapshot;
  config: RuntimeConfigSnapshot;
  health: ZapretHealthReport;
  game_profiles: GameProfilesCatalog;
  backups: BackupHistory;
}

export interface ProviderCatalog {
  rule_providers: ProviderView[];
  proxy_providers: ProviderView[];
  update_status: string;
  provider_editing: string;
}

export interface ProviderView {
  name: string;
  provider_type: string;
  behavior: string;
  path: string | null;
  url_redacted: string | null;
  interval_seconds: number | null;
  vehicle: string | null;
  health_check: string | null;
  consumed_by_bpn: boolean;
}

export interface ResourceCatalog {
  resources: OperatorResource[];
}

export interface OperatorResource {
  id: string;
  label: string;
  kind: string;
  path: string;
  installed: boolean;
  version: string | null;
  last_modified: number | null;
  source: string;
  update_supported: boolean;
  rollback_available: boolean;
  verification_status: string;
}

export interface ResourceActionResult {
  changed: boolean;
  message: string;
  resources: ResourceCatalog;
}

export interface RuntimeLogSnapshot {
  sources: RuntimeLogSource[];
}

export interface RuntimeLogSource {
  id: string;
  label: string;
  path: string;
  lines: RuntimeLogLine[];
  error: string | null;
}

export interface RuntimeLogLine {
  source: string;
  level: string;
  text: string;
}

export interface RuntimeConfigSnapshot {
  source_profile: RedactedTextArtifact;
  runtime_yaml: RedactedTextArtifact;
  diff: RedactedTextArtifact;
  read_only: boolean;
}

export interface RedactedTextArtifact {
  label: string;
  path: string | null;
  text: string;
  line_count: number;
  redacted: boolean;
  error: string | null;
}

export interface ZapretHealthReport {
  checked_at: number;
  checks: ZapretHealthCheck[];
}

export interface ZapretHealthCheck {
  id: string;
  label: string;
  domain: string;
  route_path: string;
  dns_result: string;
  probe_result: string;
  zapret_list: string;
  recovery_action: string;
  status: string;
}

export interface GameProfilesCatalog {
  known: RuntimeGameProfile[];
  detected: RuntimeGameProfile[];
  learned: RuntimeGameProfile[];
}

export interface BackupHistory {
  backups: BackupFileView[];
  support_bundles: BackupFileView[];
}

export interface BackupFileView {
  name: string;
  path: string;
  modified_at: number | null;
}

export interface BackupActionResult {
  message: string;
  path: string | null;
  history: BackupHistory;
}

export function getOperatorSnapshot(): Promise<OperatorSnapshot> {
  return invokeCommand<OperatorSnapshot>("operator_snapshot");
}

export function pickExecutablePath(): Promise<string | null> {
  return invokeCommand<string | null>("pick_executable_path");
}

export function runZapretHealthChecks(customDomain?: string): Promise<ZapretHealthReport> {
  return invokeCommand<ZapretHealthReport>("run_zapret_health_checks", { customDomain: customDomain ?? null });
}

export function repairWindowsNetwork(): Promise<AgentState> {
  return invokeCommand<AgentState>("repair_windows_network");
}

export function updateOperatorResource(id: string): Promise<ResourceActionResult> {
  return invokeCommand<ResourceActionResult>("update_operator_resource", { id });
}

export function updateAllOperatorResources(): Promise<ResourceActionResult> {
  return invokeCommand<ResourceActionResult>("update_all_operator_resources");
}

export function rollbackOperatorResource(id: string): Promise<ResourceActionResult> {
  return invokeCommand<ResourceActionResult>("rollback_operator_resource", { id });
}

export function previewLocalProfileFromText(name: string, body: string): Promise<LocalProfilePreview> {
  return invokeCommand<LocalProfilePreview>("preview_local_profile_from_text", { name, body });
}

export function previewLocalProfileFromPath(path: string, name?: string): Promise<LocalProfilePreview> {
  return invokeCommand<LocalProfilePreview>("preview_local_profile_from_path", { path, name: name ?? null });
}

export function importLocalProfileFromText(name: string, body: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("import_local_profile_from_text", { name, body });
}

export function importLocalProfileFromPath(path: string, name?: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("import_local_profile_from_path", { path, name: name ?? null });
}

export function importProfileDeepLink(link: string): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("import_profile_deep_link", { link });
}

export function refreshAllSubscriptionProfiles(): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("refresh_all_subscription_profiles");
}

export function refreshDueSubscriptionProfiles(): Promise<SubscriptionProfilesApplyResult> {
  return invokeCommand<SubscriptionProfilesApplyResult>("refresh_due_subscription_profiles");
}

export function exportBackupBundle(): Promise<BackupActionResult> {
  return invokeCommand<BackupActionResult>("export_backup_bundle");
}

export function restoreBackupBundleFromPath(path: string): Promise<BackupActionResult> {
  return invokeCommand<BackupActionResult>("restore_backup_bundle_from_path", { path });
}

export function exportSupportBundle(): Promise<BackupActionResult> {
  return invokeCommand<BackupActionResult>("export_support_bundle");
}

export function openOperatorDirectory(kind: "app_data" | "runtime" | "logs" | "backups"): Promise<string> {
  return invokeCommand<string>("open_operator_directory", { kind });
}
