import type {
  AgentServiceStatus,
  AgentState,
  AppSettings,
  ComponentUpdate,
  ComponentUpdateReport,
  ConnectionPath,
  ConnectionsSnapshot,
  BackupActionResult,
  OperatorSnapshot,
  PolicyRuleView,
  PolicySummaryResponse,
  ProxyCatalog,
  ResourceActionResult,
  RuntimeDiagnosticsReport,
  RuntimeReadinessResponse,
  RuntimeUpdateResult,
  ZapretHealthReport,
  SettingsApplyResult,
  SubscriptionProfilesApplyResult,
  SubscriptionProfilesState,
  SubscriptionState,
  TrackedConnection,
  ZapretProfileState,
  ZapretServiceStatus,
} from "./agentClient";

type InvokeArgs = Record<string, unknown>;

let mockSettings = createMockSettings();
let mockConnected = true;
let mockSelectedProxy = "NL Amsterdam";

export function mockInvoke(command: string, args?: InvokeArgs): unknown {
  switch (command) {
    case "status":
    case "start":
    case "restart":
      mockConnected = true;
      return createMockState();
    case "stop":
      mockConnected = false;
      return createMockState();
    case "set_subscription":
    case "refresh_subscription":
      return createMockState();
    case "subscription_profiles":
      return createMockProfiles();
    case "add_subscription_profile":
    case "select_subscription_profile":
    case "remove_subscription_profile":
      return { profiles: createMockProfiles(), state: createMockState(), message: "Mock profile action applied." } satisfies SubscriptionProfilesApplyResult;
    case "check_component_updates":
      return { components: mockComponents() } satisfies ComponentUpdateReport;
    case "runtime_readiness":
      return createMockReadiness();
    case "get_settings":
      return mockSettings;
    case "save_settings":
      mockSettings = args?.settings as AppSettings;
      return { settings: mockSettings, restart_required: true, state: createMockState(), message: "Mock settings saved." } satisfies SettingsApplyResult;
    case "reset_settings":
      mockSettings = createMockSettings();
      return { settings: mockSettings, restart_required: true, state: createMockState(), message: "Mock settings reset." } satisfies SettingsApplyResult;
    case "agent_service_status":
    case "install_agent_service":
      return mockAgentStatus();
    case "remove_agent_service":
      return { ...mockAgentStatus(), installed: false, running: false, ipc_ready: false, message: "Mock agent removed." } satisfies AgentServiceStatus;
    case "zapret_profile_state":
    case "set_zapret_profile":
      return {
        selected: "auto",
        options: [{ id: "auto", label: "Auto", description: "Mock automatic Flowseal profile.", selected: true }],
      } satisfies ZapretProfileState;
    case "zapret_service_status":
      return mockZapretStatus();
    case "run_diagnostics":
      return mockDiagnostics();
    case "update_runtime_components":
      return { changed: false, messages: ["Mock runtime is already up to date."], state: createMockState() } satisfies RuntimeUpdateResult;
    case "connections_snapshot":
    case "close_connection":
    case "close_all_connections":
    case "clear_closed_connections":
      return mockConnections();
    case "proxy_catalog":
      return mockProxyCatalog();
    case "select_proxy":
      mockSelectedProxy = String(args?.proxy ?? mockSelectedProxy);
      return mockProxyCatalog();
    case "policy_summary":
      return mockPolicySummary();
    case "operator_snapshot":
      return mockOperatorSnapshot();
    case "pick_executable_path":
      return "C:\\Games\\MockGame\\MockGame.exe";
    case "run_zapret_health_checks":
      return mockHealthReport();
    case "update_operator_resource":
    case "update_all_operator_resources":
    case "rollback_operator_resource":
      return { changed: true, message: "Mock resource action applied.", resources: mockOperatorSnapshot().resources } satisfies ResourceActionResult;
    case "import_local_profile_from_text":
    case "import_local_profile_from_path":
    case "import_profile_deep_link":
    case "refresh_all_subscription_profiles":
      return { profiles: createMockProfiles(), state: createMockState(), message: "Mock profile import applied." } satisfies SubscriptionProfilesApplyResult;
    case "export_backup_bundle":
    case "restore_backup_bundle_from_path":
    case "export_support_bundle":
      return { message: "Mock backup action complete.", path: "C:\\Users\\mock\\AppData\\Roaming\\BadVpn\\backups\\mock.json", history: mockOperatorSnapshot().backups } satisfies BackupActionResult;
    case "open_operator_directory":
      return "C:\\Users\\mock\\AppData\\Roaming\\BadVpn";
    default:
      throw new Error(`Mock Tauri command is not implemented: ${command}`);
  }
}

function createMockState(): AgentState {
  return {
    installed: true,
    running: mockConnected,
    phase: mockConnected ? "connected" : "ready",
    subscription: mockSubscription(),
    connection: {
      connected: mockConnected,
      status: mockConnected ? "running" : "idle",
      selected_profile: "mock-profile",
      selected_proxy: mockSelectedProxy,
      route_mode: mockSettings.core.route_mode,
    },
    metrics: {
      upload_bytes: 128 * 1024 * 1024,
      download_bytes: 2048 * 1024 * 1024,
    },
    diagnostics: {
      mihomo_healthy: true,
      zapret_healthy: mockSettings.core.route_mode === "smart",
      message: mockConnected ? "connected via mock runtime" : null,
    },
    last_error: null,
  };
}

function mockSubscription(): SubscriptionState {
  return {
    url: null,
    is_valid: true,
    validation_error: null,
    last_refreshed_at: new Date().toISOString(),
    profile_title: "Mock BPN profile",
    announce: "Mock mode is active for browser QA.",
    announce_url: null,
    support_url: null,
    profile_web_page_url: null,
    update_interval_hours: 24,
    user_info: {
      upload_bytes: 128 * 1024 * 1024,
      download_bytes: 2048 * 1024 * 1024,
      total_bytes: 100 * 1024 * 1024 * 1024,
      expire_at: Math.floor(Date.now() / 1000) + 86400 * 30,
    },
    node_count: 5,
    format: "clash_yaml",
  };
}

function createMockSettings(): AppSettings {
  return {
    core: {
      route_mode: "smart",
      log_level: "info",
      mixed_port: 7890,
      controller_port: 9090,
      allow_lan: false,
      ipv6: false,
    },
    tun: {
      enabled: true,
      stack: "mixed",
      strict_route: true,
      auto_route: true,
      auto_detect_interface: true,
      mtu: 1500,
      dns_hijack: ["any:53", "tcp://any:53"],
      excluded_routes: [],
    },
    dns: {
      mode: "fake-ip",
      preset: "cloudflare_google",
      fake_ip_range: "198.18.0.1/16",
      fake_ip_filter: ["+.lan", "+.local"],
      nameserver_policy: [],
    },
    sniffer: {
      enabled: true,
      http: true,
      tls: true,
      quic: true,
      force_domains: [],
      skip_domains: [],
      skip_src_cidrs: [],
      skip_dst_cidrs: [],
    },
    zapret: {
      enabled: true,
      run_mode: "service",
      strategy: "auto",
      game_filter: "off",
      game_bypass_mode: "auto",
      game_filter_mode: "udp_first",
      learned_game_profiles: [],
      ipset_filter: "none",
      auto_profile_fallback: true,
      fallback_to_vpn_on_failed_probe: true,
    },
    routing_policy: {
      local_overrides_enabled: true,
      local_overrides: {
        version: 1,
        rules: [
          {
            id: "mock-game",
            enabled: true,
            title: "Mock game",
            path: "direct",
            target_kind: "app",
            value: "MockGame.exe",
            executable_path: "C:\\Games\\MockGame\\MockGame.exe",
            process_name: "MockGame.exe",
            source: "user",
            created_at: Math.floor(Date.now() / 1000),
            updated_at: Math.floor(Date.now() / 1000),
            last_applied_at: null,
            last_policy_trace_id: null,
          },
        ],
      },
      force_vpn_domains: ["openai.com"],
      force_vpn_cidrs: [],
      force_zapret_domains: ["youtube.com"],
      force_zapret_cidrs: [],
      force_zapret_processes: ["Discord.exe"],
      force_zapret_tcp_ports: ["443"],
      force_zapret_udp_ports: ["50000-50100"],
      force_direct_domains: ["example.local"],
      force_direct_cidrs: [],
      force_direct_processes: ["Game.exe"],
      smart_presets: {
        youtube_discord_zapret: true,
        games_zapret: true,
        ai_vpn: true,
        social_vpn: true,
        telegram_vpn_from_provider: true,
      },
      coverage: "curated",
    },
    updates: {
      auto_flowseal_list_refresh: true,
    },
    diagnostics: {
      runtime_checks_after_connect: true,
      discord_youtube_probes: true,
    },
  };
}

function mockOperatorSnapshot(): OperatorSnapshot {
  return {
    generated_at: Math.floor(Date.now() / 1000),
    providers: {
      rule_providers: [
        { name: "provider-rules", provider_type: "http", behavior: "domain", path: "%USERPROFILE%\\rules.yaml", url_redacted: "https://provider.example/...", interval_seconds: 86400, vehicle: "yaml", health_check: null, consumed_by_bpn: false },
      ],
      proxy_providers: [],
      update_status: "Providers are read-only in mock mode.",
      provider_editing: "Provider editing is disabled.",
    },
    resources: {
      resources: [
        { id: "flowseal-general", label: "Flowseal general hostlist", kind: "zapret_list", path: "%USERPROFILE%\\BadVpn\\zapret\\lists\\list-general.txt", installed: true, version: "1024 bytes", last_modified: Math.floor(Date.now() / 1000), source: "Flowseal", update_supported: true, rollback_available: true, verification_status: "content-hash=mock" },
        { id: "runtime-components", label: "Mihomo + zapret binaries", kind: "runtime", path: "%USERPROFILE%\\BadVpn\\components", installed: true, version: "mihomo=mock, zapret=mock", last_modified: Math.floor(Date.now() / 1000), source: "BPN", update_supported: true, rollback_available: false, verification_status: "content-hash=mock" },
      ],
    },
    logs: {
      sources: [
        { id: "app", label: "BPN Client", path: "%USERPROFILE%\\BadVpn\\logs\\badvpn.log", error: null, lines: [
          { source: "app", level: "info", text: "mock app log line" },
          { source: "app", level: "warning", text: "mock warning with https://provider.example/..." },
        ] },
      ],
    },
    config: {
      read_only: true,
      source_profile: { label: "Source subscription profile", path: null, text: "proxies:\\n  - name: Mock", line_count: 2, redacted: true, error: null },
      runtime_yaml: { label: "Generated runtime YAML", path: "%USERPROFILE%\\BadVpn\\mihomo\\config.yaml", text: "secret: <redacted>\\nrules:\\n  - MATCH,PROXY", line_count: 3, redacted: true, error: null },
      diff: { label: "Source -> runtime diff", path: null, text: "+ rules:\\n+   - MATCH,PROXY", line_count: 2, redacted: true, error: null },
    },
    health: mockHealthReport(),
    game_profiles: {
      known: [
        { id: "steam", title: "Steam games", process_names: ["steam.exe"], domains: ["steamcontent.com"], cidrs: [], tcp_ports: [], udp_ports: ["27000-27100"], filter_mode: "udp_first", risk_level: "normal", detected: false, enabled: true },
      ],
      detected: [],
      learned: mockSettings.zapret.learned_game_profiles,
    },
    backups: {
      backups: [],
      support_bundles: [],
    },
  };
}

function mockHealthReport(): ZapretHealthReport {
  return {
    checked_at: Math.floor(Date.now() / 1000),
    checks: [
      { id: "youtube", label: "YouTube", domain: "youtube.com", route_path: "zapret", dns_result: "A+AAAA", probe_result: "ok-http-200", zapret_list: "present", recovery_action: "Refresh lists and reconnect Smart mode.", status: "ok" },
      { id: "openai", label: "ChatGPT/OpenAI", domain: "chatgpt.com", route_path: "vpn", dns_result: "A", probe_result: "ok-http-403", zapret_list: "not-required", recovery_action: "Check selected VPN node.", status: "ok" },
    ],
  };
}

function createMockProfiles(): SubscriptionProfilesState {
  return {
    active_id: "mock-profile",
    profiles: [
      {
        id: "mock-profile",
        name: "Mock BPN profile",
        active: true,
        redacted_url: "https://provider.example/sub/***",
        subscription: mockSubscription(),
        created_at: Date.now() - 86400_000,
        updated_at: Date.now(),
      },
    ],
  };
}

function mockAgentStatus(): AgentServiceStatus {
  return {
    service_name: "BadVpnAgent",
    installed: true,
    running: true,
    state: "Running",
    ipc_ready: true,
    message: "Mock agent is ready.",
  };
}

function mockZapretStatus(): ZapretServiceStatus {
  return {
    service_name: "BadVpnZapret",
    installed: false,
    running: false,
    state: null,
    config_hash: null,
    expected_hash: null,
    repair_required: false,
    message: "Legacy zapret service is not installed.",
  };
}

function createMockReadiness(): RuntimeReadinessResponse {
  return {
    agent: mockAgentStatus(),
    mihomo_ready: true,
    zapret_ready: true,
    needs_zapret: mockSettings.core.route_mode === "smart",
    components_ready: true,
    ready: true,
    message: "Mock runtime is ready.",
  };
}

function mockComponents(): ComponentUpdate[] {
  return [
    { name: "mihomo", current_version: "mock-1.0.0", latest_version: null, release_url: null, update_available: false, error: null },
    { name: "zapret", current_version: "mock-1.0.0", latest_version: null, release_url: null, update_available: false, error: null },
  ];
}

function mockDiagnostics(): RuntimeDiagnosticsReport {
  return {
    checked_at: Date.now(),
    mihomo_healthy: true,
    zapret_healthy: true,
    summary: "Mock diagnostics passed.",
    checks: [
      { id: "mihomo", label: "Mihomo", status: "ok", message: "Controller responds." },
      { id: "zapret", label: "zapret", status: "ok", message: "Mock winws profile is ready." },
    ],
  };
}

function mockConnections(): ConnectionsSnapshot {
  return {
    active: [
      mockConnection("1", "youtube.com", "142.250.74.206:443", "chrome.exe", "zapret", "DOMAIN-SUFFIX", "youtube.com", ["DIRECT"]),
      mockConnection("2", "api.openai.com", "104.18.33.45:443", "ChatGPT.exe", "vpn", "DOMAIN-SUFFIX", "openai.com", ["NL Amsterdam"]),
      mockConnection("3", "game.example", "203.0.113.25:50000", "Game.exe", "direct", "PROCESS-NAME", "Game.exe", ["DIRECT"]),
    ],
    closed: [mockConnection("4", "discord.com", "162.159.135.234:443", "Discord.exe", "zapret", "PROCESS-NAME", "Discord.exe", ["DIRECT"], Date.now() - 90_000)],
    upload_total: 18 * 1024 * 1024,
    download_total: 310 * 1024 * 1024,
    refreshed_at: Date.now(),
    error: null,
  };
}

function mockConnection(
  id: string,
  host: string,
  destination: string,
  process: string,
  path: ConnectionPath,
  rule: string,
  rulePayload: string,
  chains: string[],
  closedAt: number | null = null,
): TrackedConnection {
  return {
    id,
    state: closedAt ? "closed" : "active",
    host,
    destination,
    network: destination.endsWith(":443") ? "tcp" : "udp",
    connection_type: "http",
    process,
    process_path: `C:\\Mock\\${process}`,
    rule,
    rule_payload: rulePayload,
    rule_source: rule === "PROCESS-NAME" ? "local override or app/game rule" : "provider/geodata rule",
    chains,
    upload_bytes: 1024 * 1024,
    download_bytes: 24 * 1024 * 1024,
    started_at: new Date(Date.now() - 300_000).toISOString(),
    closed_at: closedAt,
    path,
    path_label: path === "vpn" ? "VPN" : path === "zapret" ? "zapret" : "DIRECT",
    path_note: path === "vpn" ? "Routed through selected proxy" : path === "zapret" ? "DIRECT plus zapret bypass" : "Direct route",
  };
}

function mockProxyCatalog(): ProxyCatalog {
  return {
    running: true,
    refreshed_at: Date.now(),
    error: null,
    groups: [
      {
        name: "Выбор сервера",
        group_type: "select",
        selected: mockSelectedProxy,
        nodes: [
          { name: "NL Amsterdam", proxy_type: "trojan", server: "nl.example", delay_ms: 42, alive: true, is_group: false, selected: mockSelectedProxy === "NL Amsterdam" },
          { name: "DE Frankfurt", proxy_type: "vless", server: "de.example", delay_ms: 55, alive: true, is_group: false, selected: mockSelectedProxy === "DE Frankfurt" },
          { name: "US New York", proxy_type: "ss", server: "us.example", delay_ms: 118, alive: true, is_group: false, selected: mockSelectedProxy === "US New York" },
        ],
      },
      {
        name: "AI",
        group_type: "url-test",
        selected: "NL Amsterdam",
        nodes: [
          { name: "NL Amsterdam", proxy_type: "trojan", server: "nl.example", delay_ms: 42, alive: true, is_group: false, selected: true },
          { name: "DE Frankfurt", proxy_type: "vless", server: "de.example", delay_ms: 55, alive: true, is_group: false, selected: false },
        ],
      },
    ],
  };
}

function mockPolicySummary(): PolicySummaryResponse {
  const policyRules: PolicyRuleView[] = [
    mockPolicyRule("DomainSuffix", "youtube.com", "ZapretDirect", "SmartPreset", "DOMAIN-SUFFIX,youtube.com,DIRECT", "hostlist", "system"),
    mockPolicyRule("DomainSuffix", "openai.com", "VpnProxy", "LocalUserOverride", "DOMAIN-SUFFIX,openai.com,Выбор сервера", "none", "proxy"),
    mockPolicyRule("ProcessName", "Game.exe", "DirectSafe", "LocalUserOverride", "PROCESS-NAME,Game.exe,DIRECT", "none", "system"),
    mockPolicyRule("TcpPort", "443", "ZapretDirect", "LocalUserOverride", "AND,((NETWORK,TCP),(DST-PORT,443)),DIRECT", "port", "system"),
  ];
  return {
    available: true,
    mode: mockSettings.core.route_mode,
    main_proxy_group: "Выбор сервера",
    final_rule: "MATCH,Выбор сервера",
    mihomo_rules: policyRules.map((rule) => rule.mihomo_rule).concat("MATCH,Выбор сервера"),
    zapret_hostlist: ["youtube.com"],
    zapret_hostlist_exclude: ["openai.com"],
    zapret_ipset: [],
    zapret_ipset_exclude: [],
    dns_nameserver_policy: [{ pattern: "+.openai.com", nameservers: ["1.1.1.1", "8.8.8.8"] }],
    policy_rules: policyRules,
    suppressed_rules: [
      {
        original_rule: "DOMAIN-SUFFIX,youtube.com,Выбор сервера",
        chosen_rule: "DOMAIN-SUFFIX,youtube.com,DIRECT",
        reason: "Smart zapret preset overrides provider proxy rule.",
      },
    ],
    diagnostics_expectations: policyRules.map((rule) => ({
      target: `${rule.target_kind},${rule.target_value}`,
      expected_path: rule.path,
      expected_mihomo_action: rule.path === "VpnProxy" ? "Выбор сервера" : "DIRECT",
      expected_zapret: rule.path === "ZapretDirect",
      source: rule.source,
    })),
    diagnostics_messages: [],
    managed_proxy_groups: [{ name: "Выбор сервера", proxies: ["NL Amsterdam", "DE Frankfurt", "US New York"] }],
    rule_count: policyRules.length + 1,
    suppressed_count: 1,
    warnings_count: 0,
    zapret_domain_count: 1,
  };
}

function mockPolicyRule(
  targetKind: string,
  targetValue: string,
  path: string,
  source: string,
  mihomoRule: string,
  zapretEffect: string,
  dnsEffect: string,
): PolicyRuleView {
  return {
    target_kind: targetKind,
    target_value: targetValue,
    path,
    path_group: path === "VpnProxy" ? "Выбор сервера" : null,
    source,
    priority: source === "LocalUserOverride" ? 900 : 500,
    original_rule: null,
    tags: source === "LocalUserOverride" ? ["local"] : ["smart"],
    mihomo_rule: mihomoRule,
    zapret_effect: zapretEffect,
    dns_effect: dnsEffect,
  };
}
