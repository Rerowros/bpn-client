import {
  Activity,
  AlertTriangle,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  CirclePause,
  Copy,
  Download,
  ExternalLink,
  Gauge,
  Globe2,
  History,
  LifeBuoy,
  ListTree,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Power,
  RefreshCw,
  Router,
  Server,
  Settings,
  Shield,
  SlidersHorizontal,
  Upload,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { CSSProperties, FormEvent, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  buildLocalOverridePatch,
  formatLocalOverrideKind,
  localOverrideExists,
  localOverridePlaceholder,
  localOverrideTargetKindsForRoute,
  previewLocalOverride,
} from "./localOverrides";
import type { LocalOverrideRoute, LocalOverrideTargetKind } from "./localOverrides";
import {
  countPolicySources,
  formatPolicyRuleForCopy,
  policyPathOptions,
  policyPathTone,
  policyRuleSearchText,
  suppressedRuleSearchText,
} from "./policyView";
import type { PolicyPathFilter } from "./policyView";
import { AppNotification, NotificationCenter, NotificationTone } from "./ui/NotificationCenter";
import {
  AgentState,
  AppSettings,
  AgentServiceStatus,
  ComponentUpdate,
  ConnectionPath,
  ConnectionsSnapshot,
  BackupHistory,
  GameProfilesCatalog,
  LocalProfilePreview,
  OperatorSnapshot,
  ResourceCatalog,
  PolicyRuleView,
  PolicySummaryResponse,
  ProxyCatalog,
  ProxyGroupView,
  ProxyNodeView,
  RuntimeDiagnosticsReport,
  RuntimeReadinessResponse,
  SubscriptionFetchProxyMode,
  SubscriptionProfileView,
  SubscriptionProfilesState,
  TrackedConnection,
  ZapretServiceStatus,
  ZapretHealthReport,
  addSubscriptionProfile,
  checkComponentUpdates,
  clearClosedConnections,
  closeAllConnections,
  closeConnection,
  getConnectionsSnapshot,
  getOperatorSnapshot,
  getPolicySummary,
  getProxyCatalog,
  getRuntimeReadiness,
  getSettings,
  getStatus,
  getSubscriptionProfiles,
  getAgentServiceStatus,
  getZapretServiceStatus,
  installAgentService,
  exportBackupBundle,
  exportSupportBundle,
  importLocalProfileFromText,
  importLocalProfileFromPath,
  importProfileDeepLink,
  openOperatorDirectory,
  pickExecutablePath,
  previewLocalProfileFromPath,
  previewLocalProfileFromText,
  refreshAllSubscriptionProfiles,
  refreshDueSubscriptionProfiles,
  repairWindowsNetwork,
  removeAgentService,
  removeSubscriptionProfile,
  refreshSubscription,
  restartConnection,
  runDiagnostics,
  resetSettings,
  restoreBackupBundleFromPath,
  rollbackOperatorResource,
  runZapretHealthChecks,
  saveSettings,
  selectProxy,
  selectSubscriptionProfile,
  setSubscription,
  startConnection,
  stopConnection,
  updateAllOperatorResources,
  updateOperatorResource,
  updateSubscriptionProfileMetadata,
  updateSubscriptionProfileFetchOptions,
  updateRuntimeComponents,
} from "./services/agentClient";
import { AppUpdateStatus, checkAppUpdate, installAppUpdate } from "./services/updateClient";

type AppView = "overview" | "connections" | "servers" | "policy" | "settings";
type ConnectionTab = "active" | "closed";
type ConnectionPathFilter = "all" | ConnectionPath;
type ConnectionGroupMode = "flows" | "processes";
type SettingsSection = "basic" | "advanced" | "operator" | "updates";
type ConnectionAttempt = { action: "connect" | "disconnect"; startedAt: number };
type ServerNodeSort = "profile" | "name" | "latency" | "alive" | "selected";
type LocalOverrideSummaryItem = {
  id?: string;
  enabled?: boolean;
  route: string;
  kind: string;
  value: string;
};
type TrafficSample = { at: number; upload: number; download: number };

const emptyState: AgentState = {
  installed: false,
  running: false,
  phase: "init",
  subscription: {
    url: null,
    is_valid: null,
    validation_error: null,
    last_refreshed_at: null,
    profile_title: null,
    announce: null,
    announce_url: null,
    support_url: null,
    profile_web_page_url: null,
    update_interval_hours: null,
    user_info: {
      upload_bytes: null,
      download_bytes: null,
      total_bytes: null,
      expire_at: null,
    },
    node_count: 0,
    format: "unknown",
  },
  connection: {
    connected: false,
    status: "idle",
    selected_profile: null,
    selected_proxy: null,
    route_mode: "smart",
  },
  metrics: {
    upload_bytes: 0,
    download_bytes: 0,
  },
  diagnostics: {
    mihomo_healthy: false,
    zapret_healthy: false,
    message: null,
  },
  last_error: null,
};

const defaultSettings: AppSettings = {
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
    fake_ip_filter: ["+.lan", "+.local", "localhost.ptlogin2.qq.com"],
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
      rules: [],
    },
    force_vpn_domains: [],
    force_vpn_cidrs: [],
    force_zapret_domains: [],
    force_zapret_cidrs: [],
    force_zapret_processes: [],
    force_zapret_tcp_ports: [],
    force_zapret_udp_ports: [],
    force_direct_domains: [],
    force_direct_cidrs: [],
    force_direct_processes: [],
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
    safe_resource_auto_update_interval_hours: 24,
  },
  diagnostics: {
    runtime_checks_after_connect: true,
    discord_youtube_probes: true,
  },
};

const zapretStrategyOptions: Array<[AppSettings["zapret"]["strategy"], string]> = [
  ["auto", "Auto"],
  ["general", "Flowseal general"],
  ["alt", "Flowseal ALT"],
  ["alt2", "Flowseal ALT2"],
  ["alt3", "Flowseal ALT3"],
  ["alt4", "Flowseal ALT4"],
  ["alt5", "Flowseal ALT5"],
  ["alt6", "Flowseal ALT6"],
  ["alt7", "Flowseal ALT7"],
  ["alt8", "Flowseal ALT8"],
  ["alt9", "Flowseal ALT9"],
  ["alt10", "Flowseal ALT10"],
  ["alt11", "Flowseal ALT11"],
  ["fake_tls_auto", "Fake TLS auto"],
  ["fake_tls_auto_alt", "Fake TLS auto ALT"],
  ["fake_tls_auto_alt2", "Fake TLS auto ALT2"],
  ["fake_tls_auto_alt3", "Fake TLS auto ALT3"],
  ["simple_fake", "Simple fake"],
  ["simple_fake_alt", "Simple fake ALT"],
  ["simple_fake_alt2", "Simple fake ALT2"],
];

const connectionPathOptions: Array<[ConnectionPathFilter, string]> = [
  ["all", "All"],
  ["vpn", "VPN"],
  ["zapret", "zapret"],
  ["direct", "DIRECT"],
  ["blocked", "Blocked"],
  ["unknown", "Unknown"],
];

const serverNodeSortOptions: Array<[ServerNodeSort, string]> = [
  ["profile", "Profile order"],
  ["selected", "Selected first"],
  ["latency", "Lowest latency"],
  ["alive", "Alive first"],
  ["name", "Name"],
];

export function App() {
  const [state, setState] = useState<AgentState>(emptyState);
  const [view, setView] = useState<AppView>("overview");
  const [subscriptionUrl, setSubscriptionUrl] = useState("");
  const [profileUrl, setProfileUrl] = useState("");
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [railExpanded, setRailExpanded] = useState(true);
  const [subscriptionProfiles, setSubscriptionProfiles] = useState<SubscriptionProfilesState>({
    active_id: null,
    profiles: [],
  });
  const [profilesBusy, setProfilesBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [appUpdate, setAppUpdate] = useState<AppUpdateStatus>({ state: "idle" });
  const [componentUpdates, setComponentUpdates] = useState<ComponentUpdate[]>([]);
  const [updateBusy, setUpdateBusy] = useState(false);
  const [connections, setConnections] = useState<ConnectionsSnapshot | null>(null);
  const [connectionTab, setConnectionTab] = useState<ConnectionTab>("active");
  const [connectionPathFilter, setConnectionPathFilter] = useState<ConnectionPathFilter>("all");
  const [connectionGroupMode, setConnectionGroupMode] = useState<ConnectionGroupMode>("flows");
  const [connectionSearch, setConnectionSearch] = useState("");
  const [connectionsBusy, setConnectionsBusy] = useState(false);
  const [catalog, setCatalog] = useState<ProxyCatalog | null>(null);
  const [lastCatalogError, setLastCatalogError] = useState<string | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [serverSearch, setServerSearch] = useState("");
  const [serverNodeSort, setServerNodeSort] = useState<ServerNodeSort>("profile");
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [runtimeDiagnostics, setRuntimeDiagnostics] = useState<RuntimeDiagnosticsReport | null>(null);
  const [runtimeReadiness, setRuntimeReadiness] = useState<RuntimeReadinessResponse | null>(null);
  const [diagnosticBusy, setDiagnosticBusy] = useState(false);
  const [policySummary, setPolicySummary] = useState<PolicySummaryResponse | null>(null);
  const [policySearch, setPolicySearch] = useState("");
  const [policyPathFilter, setPolicyPathFilter] = useState<PolicyPathFilter>("all");
  const [policySourceFilter, setPolicySourceFilter] = useState("all");
  const [policyBusy, setPolicyBusy] = useState(false);
  const [operatorSnapshot, setOperatorSnapshot] = useState<OperatorSnapshot | null>(null);
  const [operatorBusy, setOperatorBusy] = useState(false);
  const [operatorLogPaused, setOperatorLogPaused] = useState(false);
  const [operatorLogAutoScroll, setOperatorLogAutoScroll] = useState(true);
  const [operatorLogViewCleared, setOperatorLogViewCleared] = useState(false);
  const [operatorLogSourceFilter, setOperatorLogSourceFilter] = useState("all");
  const [operatorLogLevelFilter, setOperatorLogLevelFilter] = useState("all");
  const [operatorCustomDomain, setOperatorCustomDomain] = useState("");
  const [operatorHealthHistory, setOperatorHealthHistory] = useState<ZapretHealthReport[]>([]);
  const [operatorProfileName, setOperatorProfileName] = useState("");
  const [operatorProfilePath, setOperatorProfilePath] = useState("");
  const [operatorProfileText, setOperatorProfileText] = useState("");
  const [operatorProfilePreview, setOperatorProfilePreview] = useState<LocalProfilePreview | null>(null);
  const [operatorDeepLink, setOperatorDeepLink] = useState("");
  const [operatorBackupPath, setOperatorBackupPath] = useState("");
  const [manualGameProfile, setManualGameProfile] = useState({
    title: "",
    executable: "",
    domains: "",
    cidrs: "",
    tcpPorts: "",
    udpPorts: "",
  });
  const [agentService, setAgentService] = useState<AgentServiceStatus | null>(null);
  const [agentServiceBusy, setAgentServiceBusy] = useState(false);
  const [zapretService, setZapretService] = useState<ZapretServiceStatus | null>(null);
  const [zapretServiceBusy, setZapretServiceBusy] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("basic");
  const [localOverrideRoute, setLocalOverrideRoute] = useState<LocalOverrideRoute>("direct");
  const [localOverrideKind, setLocalOverrideKind] = useState<LocalOverrideTargetKind>("process");
  const [localOverrideValue, setLocalOverrideValue] = useState("");
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [settingsRestartRequired, setSettingsRestartRequired] = useState(false);
  const [lastConnectionsError, setLastConnectionsError] = useState<string | null>(null);
  const [connectionAttempt, setConnectionAttempt] = useState<ConnectionAttempt | null>(null);
  const [progressNow, setProgressNow] = useState(() => Date.now());
  const [showConnectionDetails, setShowConnectionDetails] = useState(false);
  const [connectionFailureStage, setConnectionFailureStage] = useState<string | null>(null);
  const [trafficSamples, setTrafficSamples] = useState<TrafficSample[]>([]);

  function pushNotification({
    tone,
    title,
    message,
    actionLabel,
    action,
    autoDismiss = tone === "info" || tone === "success",
  }: {
    tone: NotificationTone;
    title: string;
    message: string;
    actionLabel?: string;
    action?: () => void;
    autoDismiss?: boolean;
  }) {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setNotifications((current) => [
      {
        id,
        tone,
        title,
        message,
        actionLabel,
        action,
        createdAt: Date.now(),
        autoDismiss,
      },
      ...current,
    ].slice(0, 4));
  }

  function dismissNotification(id: string) {
    setNotifications((current) => current.filter((notification) => notification.id !== id));
  }

  function notifyFromError(title: string, error: unknown) {
    pushNotification({
      tone: "error",
      title,
      message: error instanceof Error ? error.message : String(error),
      autoDismiss: false,
    });
  }

  function notifyAgentError(title: string, nextState: AgentState) {
    if (!nextState.last_error) {
      return;
    }
    pushNotification({
      tone: "error",
      title,
      message: nextState.last_error,
      actionLabel: "Details",
      action: () => {
        setView("overview");
        setShowConnectionDetails(true);
      },
      autoDismiss: false,
    });
  }

  useEffect(() => {
    if (!notifications.some((notification) => notification.autoDismiss)) {
      return;
    }
    const timer = window.setInterval(() => {
      const now = Date.now();
      setNotifications((current) =>
        current.filter((notification) => !notification.autoDismiss || now - notification.createdAt < 5200),
      );
    }, 500);
    return () => window.clearInterval(timer);
  }, [notifications]);

  useEffect(() => {
    void runAction(() => getStatus(), false);
    void loadSettings();
    void refreshSubscriptionProfiles(false);
    void refreshAgentService(false);
    void refreshZapretService(false);
    void refreshRuntimeReadiness(false);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => void runAction(() => getStatus(), false), 5000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!connectionAttempt) {
      return;
    }
    const timer = window.setInterval(() => setProgressNow(Date.now()), 450);
    return () => window.clearInterval(timer);
  }, [connectionAttempt]);

  useEffect(() => {
    if (!connectionAttempt || state.connection.status === "starting" || state.connection.status === "stopping") {
      return;
    }
    const timer = window.setTimeout(() => setConnectionAttempt(null), 700);
    return () => window.clearTimeout(timer);
  }, [connectionAttempt, state.connection.status]);

  useEffect(() => {
    if (!state.connection.connected || !settings.diagnostics.runtime_checks_after_connect) {
      return;
    }
    const timer = window.setTimeout(() => void handleRunDiagnostics(), 2500);
    return () => window.clearTimeout(timer);
  }, [settings.diagnostics.runtime_checks_after_connect, state.connection.connected]);

  useEffect(() => {
    setSubscriptionUrl(state.subscription.url ?? "");
  }, [state.subscription.url]);

  useEffect(() => {
    const shouldPollConnections = view === "connections" || (view === "overview" && state.connection.connected);
    if (!shouldPollConnections) {
      return;
    }
    void refreshConnections(false);
    const timer = window.setInterval(() => void refreshConnections(false), 2500);
    return () => window.clearInterval(timer);
  }, [state.connection.connected, view]);

  useEffect(() => {
    if (view === "servers" || view === "overview") {
      void refreshCatalog(false);
    }
    if (view === "policy") {
      void refreshPolicySummary(false);
    }
    if (view === "settings" && settingsSection === "operator") {
      void refreshOperatorSnapshot(false);
    }
  }, [view, settingsSection]);

  useEffect(() => {
    if (
      view !== "settings" ||
      settingsSection !== "operator" ||
      !operatorLogAutoScroll ||
      operatorLogPaused ||
      operatorLogViewCleared
    ) {
      return;
    }
    const viewer = document.getElementById("operator-log-viewer");
    if (viewer) {
      viewer.scrollTop = viewer.scrollHeight;
    }
  }, [
    operatorLogAutoScroll,
    operatorLogLevelFilter,
    operatorLogPaused,
    operatorLogSourceFilter,
    operatorLogViewCleared,
    operatorSnapshot,
    settingsSection,
    view,
  ]);

  useEffect(() => {
    if (!catalog?.groups.length) {
      setSelectedGroup(null);
      return;
    }
    setSelectedGroup((current) => current ?? catalog.groups[0].name);
  }, [catalog]);

  useEffect(() => {
    const upload = state.metrics.upload_bytes;
    const download = state.metrics.download_bytes;
    setTrafficSamples((current) => {
      const now = Date.now();
      const last = current[current.length - 1];
      if (last && last.upload === upload && last.download === download && now - last.at < 2500) {
        return current;
      }
      return [...current, { at: now, upload, download }].slice(-12);
    });
  }, [state.metrics.download_bytes, state.metrics.upload_bytes]);

  const hasSubscription =
    state.subscription.is_valid !== false &&
    (state.subscription.node_count > 0 ||
      state.subscription.format !== "unknown" ||
      Boolean(state.subscription.profile_title));
  const isOnboarding = !hasSubscription || state.phase === "onboarding";
  const quota = getQuota(state);
  const supportUrl = state.subscription.support_url;
  const providerAnnouncement = providerAnnouncementMetadata(state.subscription);
  const providerLinks = providerMetadataLinks(state.subscription);
  const isRuntimeTransitioning = state.connection.status === "starting" || state.connection.status === "stopping";
  const isConnected = state.connection.connected && state.connection.status === "running";
  const smartFallbackActive =
    isConnected && settings.core.route_mode === "smart" && state.connection.route_mode === "vpn_only";
  const agentReady = Boolean(agentService?.installed && agentService.ipc_ready);
  const zapretReady = Boolean(runtimeReadiness?.zapret_ready || state.diagnostics.zapret_healthy);
  const needsZapret = runtimeReadiness?.needs_zapret ?? settings.core.route_mode === "smart";
  const agentHomeStatus = agentReady ? "Ready" : agentService?.installed ? "IPC недоступен" : "Нужна установка";
  const zapretHomeStatus = !needsZapret ? "Не нужен в VPN Only" : zapretReady ? "Готов" : "Standby / check";
  const runtimeComponentStatus = getRuntimeComponentStatus(componentUpdates, runtimeReadiness);
  const connectionProgress = getConnectionProgress({
    attempt: connectionAttempt,
    now: progressNow,
    routeMode: settings.core.route_mode,
    status: state.connection.status,
    connected: isConnected,
    fallbackActive: smartFallbackActive,
    lastError: state.last_error,
  });
  const statusLabel = useMemo(() => {
    if (state.connection.status === "starting") {
      return "Starting";
    }
    if (state.connection.status === "stopping") {
      return "Stopping";
    }
    if (isConnected) {
      return "Connected";
    }
    if (state.last_error) {
      return "Action required";
    }
    if (hasSubscription) {
      return "Ready";
    }
    return "Not configured";
  }, [hasSubscription, isConnected, state.connection.status, state.last_error]);

  const routeSummary = getHomeRouteSummary(settings.core.route_mode, smartFallbackActive);
  const startupTimeline = parseStartupTimeline(state.diagnostics.message);
  const catalogSelectedNode = getSelectedCatalogNode(catalog);
  const currentNode = state.connection.selected_proxy ?? catalogSelectedNode?.name ?? "Автовыбор провайдера";
  const activeHomeGroup = getActiveHomeGroup(catalog, selectedGroup);
  const currentServerName = activeHomeGroup?.selected ?? catalogSelectedNode?.name ?? currentNode;
  const currentServer = parseServerIdentity(currentServerName);
  const homeGroups = catalog?.groups ?? [];
  const homeNodes = activeHomeGroup
    ? sortProxyNodes(activeHomeGroup.nodes, "selected", activeHomeGroup.selected ?? currentNode).slice(0, 14)
    : [];
  const trafficStats = getTrafficStats(trafficSamples, state);
  const heroTitle = isConnected
    ? "Соединение активно"
    : state.connection.status === "starting"
      ? "Подключаем защиту"
      : state.connection.status === "stopping"
        ? "Отключаем защиту"
        : "Готово к подключению";
  const heroSubtitle = isConnected
    ? `${currentServer.label} активен. Маршруты применены через ${formatRouteMode(state.connection.route_mode)}.`
    : hasSubscription
      ? "Профиль готов. Подключите VPN, чтобы применить Smart-маршрутизацию и локальные правила."
      : "Добавьте подписку, чтобы BadVpn подготовил профиль Mihomo.";
  const heroModeLabel = smartFallbackActive ? "VPN Only fallback" : formatRouteMode(state.connection.route_mode || settings.core.route_mode);
  const overrideCount = countLocalRoutingOverrides(settings.routing_policy);
  const activeSmartPresets = [
    { label: "YouTube / Discord", enabled: settings.routing_policy.smart_presets.youtube_discord_zapret },
    { label: "Игры", enabled: settings.routing_policy.smart_presets.games_zapret },
    { label: "AI через VPN", enabled: settings.routing_policy.smart_presets.ai_vpn },
    { label: "Соцсети через VPN", enabled: settings.routing_policy.smart_presets.social_vpn },
  ].filter((preset) => preset.enabled);

  async function runAction(action: () => Promise<AgentState>, showBusy = true) {
    if (showBusy) {
      setBusy(true);
    }
    try {
      const nextState = await action();
      setState(nextState);
      if (showBusy) {
        notifyAgentError("Action failed", nextState);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setState((current) => ({
        ...current,
        phase: "error",
        last_error: message,
      }));
      if (showBusy) {
        pushNotification({ tone: "error", title: "Action failed", message, autoDismiss: false });
      }
    } finally {
      if (showBusy) {
        setBusy(false);
      }
    }
  }

  async function handlePrimaryConnectionAction() {
    const action = isConnected ? "disconnect" : "connect";
    const attempt = { action, startedAt: Date.now() } satisfies ConnectionAttempt;
    setConnectionAttempt(attempt);
    setProgressNow(Date.now());
    setShowConnectionDetails(false);
    setConnectionFailureStage(null);
    setBusy(true);
    setState((current) => ({
      ...current,
      phase: action === "connect" ? "connecting" : "disconnecting",
      last_error: null,
      connection: {
        ...current.connection,
        status: action === "connect" ? "starting" : "stopping",
      },
      diagnostics: {
        ...current.diagnostics,
        message: action === "connect" ? "Preparing policy..." : "Disconnecting...",
      },
    }));

    try {
      const nextState = await (action === "connect" ? startConnection() : stopConnection());
      setState(nextState);
      if (nextState.last_error) {
        setConnectionFailureStage(
          getConnectionProgress({
            attempt,
            now: Date.now(),
            routeMode: settings.core.route_mode,
            status: nextState.connection.status,
            connected: nextState.connection.connected,
            fallbackActive: false,
            lastError: null,
          })?.label ?? null,
        );
        notifyAgentError(action === "connect" ? "Connect failed" : "Disconnect failed", nextState);
        setShowConnectionDetails(true);
      } else if (
        action === "connect" &&
        settings.core.route_mode === "smart" &&
        nextState.connection.connected &&
        nextState.connection.route_mode === "vpn_only"
      ) {
        pushNotification({
          tone: "warning",
          title: "Smart fallback active",
          message: "Connected in VPN Only because zapret is not ready.",
          actionLabel: "Details",
          action: () => {
            setView("policy");
          },
          autoDismiss: false,
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setConnectionFailureStage(
        getConnectionProgress({
          attempt,
          now: Date.now(),
          routeMode: settings.core.route_mode,
          status: action === "connect" ? "starting" : "stopping",
          connected: false,
          fallbackActive: false,
          lastError: null,
        })?.label ?? null,
      );
      setState((current) => ({
        ...current,
        phase: "error",
        connection: {
          ...current.connection,
          status: "error",
        },
        last_error: message,
        diagnostics: {
          ...current.diagnostics,
          message,
        },
      }));
      pushNotification({
        tone: "error",
        title: action === "connect" ? "Connect failed" : "Disconnect failed",
        message,
        actionLabel: "Details",
        action: () => {
          setView("overview");
          setShowConnectionDetails(true);
        },
        autoDismiss: false,
      });
      setShowConnectionDetails(true);
    } finally {
      setBusy(false);
    }
  }

  async function loadSettings() {
    try {
      setSettings(await getSettings());
    } catch (error) {
      notifyFromError("Settings unavailable", error);
    }
  }

  async function persistSettings(nextSettings: AppSettings) {
    setSettings(nextSettings);
    setSettingsBusy(true);
    try {
      const result = await saveSettings(nextSettings);
      setSettings(result.settings);
      setState(result.state);
      setSettingsRestartRequired(result.restart_required);
      pushNotification({ tone: "success", title: "Settings saved", message: result.message });
      await refreshZapretService(false);
    } catch (error) {
      notifyFromError("Settings save failed", error);
    } finally {
      setSettingsBusy(false);
    }
  }

  function updateSettings(nextSettings: AppSettings) {
    void persistSettings(nextSettings);
  }

  async function handleResetSettings() {
    setSettingsBusy(true);
    try {
      const result = await resetSettings();
      setSettings(result.settings);
      setState(result.state);
      setSettingsRestartRequired(result.restart_required);
      pushNotification({ tone: "success", title: "Settings reset", message: result.message });
    } catch (error) {
      notifyFromError("Settings reset failed", error);
    } finally {
      setSettingsBusy(false);
    }
  }

  async function handleApplySettingsRestart() {
    setSettingsBusy(true);
    try {
      await runAction(restartConnection, false);
      setSettingsRestartRequired(false);
      pushNotification({ tone: "success", title: "Settings applied", message: "Settings applied after reconnect." });
    } finally {
      setSettingsBusy(false);
    }
  }

  async function submitSubscription(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const nextState = await setSubscription(subscriptionUrl);
      setState(nextState);
      setSubscriptionProfiles(await getSubscriptionProfiles());
      if (nextState.subscription.is_valid) {
        pushNotification({
          tone: "success",
          title: "Subscription imported",
          message: nextState.subscription.profile_title ?? "Profile is ready.",
        });
      } else {
        notifyAgentError("Subscription needs attention", nextState);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setState((current) => ({
        ...current,
        phase: "error",
        last_error: message,
      }));
      pushNotification({ tone: "error", title: "Subscription import failed", message, autoDismiss: false });
    } finally {
      setBusy(false);
    }
  }

  async function handleCheckUpdates() {
    setUpdateBusy(true);
    setAppUpdate({ state: "checking" });
    try {
      const [nextAppUpdate, componentReport] = await Promise.all([
        checkAppUpdate(),
        checkComponentUpdates(),
      ]);
      setAppUpdate(nextAppUpdate);
      setComponentUpdates(componentReport.components);
      await refreshRuntimeReadiness(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setAppUpdate({
        state: "error",
        message,
      });
      pushNotification({ tone: "error", title: "Update check failed", message, autoDismiss: false });
    } finally {
      setUpdateBusy(false);
    }
  }

  async function handleInstallAppUpdate() {
    setUpdateBusy(true);
    setAppUpdate({ state: "downloading", progress: null });
    try {
      const next = await installAppUpdate((progress) => {
        setAppUpdate({ state: "downloading", progress });
      });
      setAppUpdate(next);
      if (next.state === "installed") {
        pushNotification({ tone: "success", title: "App update installed", message: "Restart BadVpn to finish applying the update." });
      } else if (next.state === "error") {
        pushNotification({ tone: "error", title: "App update failed", message: next.message, autoDismiss: false });
      }
    } catch (error) {
      notifyFromError("App update failed", error);
    } finally {
      setUpdateBusy(false);
    }
  }

  async function handleRuntimeUpdate() {
    setUpdateBusy(true);
    try {
      const result = await updateRuntimeComponents();
      setState(result.state);
      pushNotification({
        tone: "success",
        title: "Runtime updated",
        message: result.messages.join(" ") || "Runtime components are current.",
      });
      const componentReport = await checkComponentUpdates();
      setComponentUpdates(componentReport.components);
      await refreshRuntimeReadiness(false);
      await refreshZapretService(false);
    } catch (error) {
      notifyFromError("Runtime update failed", error);
    } finally {
      setUpdateBusy(false);
    }
  }

  async function refreshSubscriptionProfiles(showBusy = true) {
    if (showBusy) {
      setProfilesBusy(true);
    }
    try {
      setSubscriptionProfiles(await getSubscriptionProfiles());
    } finally {
      if (showBusy) {
        setProfilesBusy(false);
      }
    }
  }

  async function handleRefreshSubscription() {
    setBusy(true);
    try {
      const nextState = await refreshSubscription();
      setState(nextState);
      setSubscriptionProfiles(await getSubscriptionProfiles());
      pushNotification({ tone: "success", title: "Subscription refreshed", message: "Active profile refreshed." });
    } catch (error) {
      notifyFromError("Subscription refresh failed", error);
    } finally {
      setBusy(false);
    }
  }

  async function handleAddSubscriptionProfile() {
    const url = profileUrl.trim();
    if (!url) {
      return;
    }
    setProfilesBusy(true);
    try {
      const result = await addSubscriptionProfile(url);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Profile added", message: result.message });
      setProfileUrl("");
    } catch (error) {
      notifyFromError("Profile add failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function handleSelectSubscriptionProfile(id: string) {
    setProfilesBusy(true);
    try {
      const result = await selectSubscriptionProfile(id);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Profile selected", message: result.message });
    } catch (error) {
      notifyFromError("Profile selection failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function handleRemoveSubscriptionProfile(id: string) {
    setProfilesBusy(true);
    try {
      const result = await removeSubscriptionProfile(id);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Profile removed", message: result.message });
    } catch (error) {
      notifyFromError("Profile removal failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function refreshAgentService(showBusy = true) {
    if (showBusy) {
      setAgentServiceBusy(true);
    }
    try {
      setAgentService(await getAgentServiceStatus());
    } finally {
      if (showBusy) {
        setAgentServiceBusy(false);
      }
    }
  }

  async function handleInstallAgentService() {
    setAgentServiceBusy(true);
    try {
      const status = await installAgentService();
      setAgentService(status);
      setRuntimeReadiness((current) => current ? { ...current, agent: status, ready: status.ipc_ready && current.components_ready } : current);
      pushNotification({ tone: "success", title: "Agent service updated", message: status.message });
      await refreshRuntimeReadiness(false);
      await runAction(() => getStatus(), false);
    } catch (error) {
      notifyFromError("Agent service failed", error);
    } finally {
      setAgentServiceBusy(false);
    }
  }

  async function handleRemoveAgentService() {
    setAgentServiceBusy(true);
    try {
      const status = await removeAgentService();
      setAgentService(status);
      pushNotification({ tone: "success", title: "Agent service removed", message: status.message });
      await runAction(() => getStatus(), false);
    } catch (error) {
      notifyFromError("Agent removal failed", error);
    } finally {
      setAgentServiceBusy(false);
    }
  }

  async function refreshZapretService(showBusy = true) {
    if (showBusy) {
      setZapretServiceBusy(true);
    }
    try {
      setZapretService(await getZapretServiceStatus());
    } finally {
      if (showBusy) {
        setZapretServiceBusy(false);
      }
    }
  }

  async function refreshRuntimeReadiness(showBusy = true) {
    if (showBusy) {
      setUpdateBusy(true);
    }
    try {
      const readiness = await getRuntimeReadiness();
      setRuntimeReadiness(readiness);
      setAgentService(readiness.agent);
    } catch (error) {
      notifyFromError("Runtime readiness failed", error);
    } finally {
      if (showBusy) {
        setUpdateBusy(false);
      }
    }
  }

  async function handleRunDiagnostics() {
    setDiagnosticBusy(true);
    try {
      const report = await runDiagnostics();
      setRuntimeDiagnostics(report);
      await refreshZapretService(false);
      await runAction(() => getStatus(), false);
      const failed = report.checks.filter((check) => check.status === "error").length;
      const warnings = report.checks.filter((check) => check.status === "warning").length;
      pushNotification({
        tone: failed ? "error" : warnings ? "warning" : "success",
        title: "Diagnostics complete",
        message: failed || warnings ? `${failed} failed, ${warnings} warning.` : "All runtime checks passed.",
        autoDismiss: failed === 0 && warnings === 0,
      });
    } catch (error) {
      notifyFromError("Diagnostics failed", error);
    } finally {
      setDiagnosticBusy(false);
    }
  }

  async function handleCopyText(label: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      pushNotification({ tone: "success", title: "Copied", message: `${label} copied to clipboard.` });
    } catch (error) {
      notifyFromError(`Copy ${label} failed`, error);
    }
  }

  async function refreshConnections(showBusy = true) {
    if (showBusy) {
      setConnectionsBusy(true);
    }
    try {
      const snapshot = await getConnectionsSnapshot();
      setConnections(snapshot);
      setLastConnectionsError((current) => {
        if (snapshot.error && snapshot.error !== current) {
          pushNotification({ tone: "warning", title: "Connections unavailable", message: snapshot.error, autoDismiss: false });
          return snapshot.error;
        }
        return snapshot.error ? current : null;
      });
    } catch (error) {
      notifyFromError("Connections refresh failed", error);
    } finally {
      if (showBusy) {
        setConnectionsBusy(false);
      }
    }
  }

  async function handleCloseConnection(id: string) {
    setConnectionsBusy(true);
    try {
      setConnections(await closeConnection(id));
      pushNotification({ tone: "success", title: "Connection closed", message: "The selected Mihomo flow was closed." });
    } catch (error) {
      notifyFromError("Connection close failed", error);
    } finally {
      setConnectionsBusy(false);
    }
  }

  async function handleCloseConnections(ids: string[]) {
    if (ids.length === 0) {
      return;
    }
    setConnectionsBusy(true);
    try {
      let snapshot: ConnectionsSnapshot | null = null;
      for (const id of ids) {
        snapshot = await closeConnection(id);
      }
      if (snapshot) {
        setConnections(snapshot);
      }
      pushNotification({ tone: "success", title: "Connections closed", message: `${ids.length} Mihomo flows were closed.` });
    } catch (error) {
      notifyFromError("Close process flows failed", error);
    } finally {
      setConnectionsBusy(false);
    }
  }

  async function handleCloseAllConnections() {
    setConnectionsBusy(true);
    try {
      setConnections(await closeAllConnections());
      pushNotification({ tone: "success", title: "Connections closed", message: "All active Mihomo flows were closed." });
    } catch (error) {
      notifyFromError("Close all failed", error);
    } finally {
      setConnectionsBusy(false);
    }
  }

  async function handleClearClosedConnections() {
    try {
      setConnections(await clearClosedConnections());
      pushNotification({ tone: "success", title: "History cleared", message: "Closed connection history was cleared." });
    } catch (error) {
      notifyFromError("Clear history failed", error);
    }
  }

  function handleCreateOverrideFromConnection(connection: TrackedConnection) {
    const route = connection.path === "vpn" ? "vpn" : connection.path === "zapret" ? "zapret" : "direct";
    const process = connection.process?.trim();
    const target = process || connection.host || connection.destination;
    setLocalOverrideRoute(route);
    setLocalOverrideKind(process ? "process" : "domain");
    setLocalOverrideValue(target);
    setSettingsSection("advanced");
    setView("settings");
    pushNotification({
      tone: "info",
      title: "Override draft ready",
      message: process ? `${process} is prefilled as a process override.` : `${target} is prefilled as a domain override.`,
    });
  }

  function handleCreateOverrideFromPolicyRule(rule: PolicyRuleView) {
    const draft = localOverrideDraftFromPolicyRule(rule);
    if (!draft) {
      pushNotification({
        tone: "warning",
        title: "Override not supported",
        message: `${rule.target_kind} cannot be converted to a local override yet.`,
      });
      return;
    }
    setLocalOverrideRoute(draft.route);
    setLocalOverrideKind(draft.kind);
    setLocalOverrideValue(draft.value);
    setSettingsSection("advanced");
    setView("settings");
    pushNotification({
      tone: "info",
      title: "Override draft ready",
      message: `${draft.value} is prefilled from the policy rule.`,
    });
  }

  async function refreshCatalog(showBusy = true) {
    if (showBusy) {
      setCatalogBusy(true);
    }
    try {
      const nextCatalog = await getProxyCatalog();
      setCatalog(nextCatalog);
      setLastCatalogError((current) => {
        if (nextCatalog.error && nextCatalog.error !== current) {
          pushNotification({ tone: "warning", title: "Server catalog unavailable", message: nextCatalog.error, autoDismiss: false });
          return nextCatalog.error;
        }
        return nextCatalog.error ? current : null;
      });
    } catch (error) {
      notifyFromError("Server catalog failed", error);
    } finally {
      if (showBusy) {
        setCatalogBusy(false);
      }
    }
  }

  async function refreshPolicySummary(showBusy = true) {
    if (showBusy) {
      setPolicyBusy(true);
    }
    try {
      setPolicySummary(await getPolicySummary());
    } catch (error) {
      notifyFromError("Policy summary failed", error);
    } finally {
      if (showBusy) {
        setPolicyBusy(false);
      }
    }
  }

  async function refreshOperatorSnapshot(showBusy = true) {
    if (operatorLogPaused && operatorSnapshot) {
      return;
    }
    if (showBusy) {
      setOperatorBusy(true);
    }
    try {
      setOperatorSnapshot(await getOperatorSnapshot());
      setOperatorLogViewCleared(false);
    } catch (error) {
      notifyFromError("Operator snapshot failed", error);
    } finally {
      if (showBusy) {
        setOperatorBusy(false);
      }
    }
  }

  async function handlePickExecutable() {
    try {
      const path = await pickExecutablePath();
      if (!path) {
        return;
      }
      if (settingsSection === "operator") {
        setManualGameProfile((current) => ({ ...current, executable: path }));
      } else {
        setLocalOverrideKind("process");
        setLocalOverrideValue(path);
      }
    } catch (error) {
      notifyFromError("Executable picker failed", error);
    }
  }

  async function handleRunZapretChecks() {
    setOperatorBusy(true);
    try {
      const report = await runZapretHealthChecks(operatorCustomDomain.trim() || undefined);
      setOperatorSnapshot((current) => current ? { ...current, health: report } : current);
      setOperatorHealthHistory((current) => [report, ...current].slice(0, 5));
      pushNotification({ tone: "success", title: "Checks finished", message: `${report.checks.length} route checks updated.` });
    } catch (error) {
      notifyFromError("Zapret checks failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleRepairWindowsNetwork() {
    setOperatorBusy(true);
    try {
      const nextState = await repairWindowsNetwork();
      setState(nextState);
      pushNotification({
        tone: "success",
        title: "Network recovery finished",
        message: nextState.diagnostics.message ?? "badvpn-agent completed Windows network recovery.",
      });
      await refreshOperatorSnapshot(false);
    } catch (error) {
      notifyFromError("Network recovery failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleResourceUpdate(id: string) {
    setOperatorBusy(true);
    try {
      const result = await updateOperatorResource(id);
      setOperatorSnapshot((current) => current ? { ...current, resources: result.resources } : current);
      pushNotification({ tone: "success", title: "Resource updated", message: result.message });
    } catch (error) {
      notifyFromError("Resource update failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleResourceUpdateAll() {
    setOperatorBusy(true);
    try {
      const result = await updateAllOperatorResources();
      setOperatorSnapshot((current) => current ? { ...current, resources: result.resources } : current);
      pushNotification({ tone: "success", title: "Resources updated", message: result.message || "Safe resources updated." });
    } catch (error) {
      notifyFromError("Resource update failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleResourceRollback(id: string) {
    setOperatorBusy(true);
    try {
      const result = await rollbackOperatorResource(id);
      setOperatorSnapshot((current) => current ? { ...current, resources: result.resources } : current);
      pushNotification({ tone: "success", title: "Resource restored", message: result.message });
    } catch (error) {
      notifyFromError("Resource rollback failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleImportLocalProfile(mode: "path" | "text" | "link") {
    setOperatorBusy(true);
    try {
      const result =
        mode === "path"
          ? await importLocalProfileFromPath(operatorProfilePath, operatorProfileName || undefined)
          : mode === "text"
            ? await importLocalProfileFromText(operatorProfileName || "Local profile", operatorProfileText)
            : await importProfileDeepLink(operatorDeepLink);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      setOperatorProfilePreview(null);
      pushNotification({ tone: "success", title: "Profile imported", message: result.message });
      await refreshOperatorSnapshot(false);
    } catch (error) {
      notifyFromError("Profile import failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handlePreviewLocalProfile(mode: "path" | "text") {
    setOperatorBusy(true);
    try {
      const preview =
        mode === "path"
          ? await previewLocalProfileFromPath(operatorProfilePath, operatorProfileName || undefined)
          : await previewLocalProfileFromText(operatorProfileName || "Local profile", operatorProfileText);
      setOperatorProfilePreview(preview);
      pushNotification({
        tone: preview.import_ready ? "success" : "warning",
        title: "Profile preview ready",
        message: preview.warning ?? `${preview.node_count} node(s), ${formatRouteMode(preview.format)}.`,
      });
    } catch (error) {
      setOperatorProfilePreview(null);
      notifyFromError("Profile preview failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleRefreshAllProfiles() {
    setProfilesBusy(true);
    try {
      const result = await refreshAllSubscriptionProfiles();
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Profiles refreshed", message: result.message });
    } catch (error) {
      notifyFromError("Refresh all failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function handleRefreshDueProfiles() {
    setProfilesBusy(true);
    try {
      const result = await refreshDueSubscriptionProfiles();
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Due profiles refreshed", message: result.message });
    } catch (error) {
      notifyFromError("Due refresh failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function handleProfileFetchProxyMode(profile: SubscriptionProfileView, proxyMode: SubscriptionFetchProxyMode) {
    let customProxyUrl: string | undefined;
    if (proxyMode === "custom") {
      const hasStoredCustomProxy = Boolean(profile.fetch_options.custom_proxy_redacted);
      const value = window.prompt(
        hasStoredCustomProxy
          ? "Custom HTTP(S) proxy URL (leave empty to keep saved proxy)"
          : "Custom HTTP(S) proxy URL",
        hasStoredCustomProxy ? "" : "http://127.0.0.1:8080",
      );
      if (value === null) {
        return;
      }
      const trimmed = value.trim();
      if (!trimmed) {
        if (!hasStoredCustomProxy) {
          return;
        }
      } else {
        customProxyUrl = trimmed;
      }
    }
    await applyProfileFetchOptions(profile, profile.fetch_options.timeout_seconds, proxyMode, customProxyUrl);
  }

  async function handleProfileNotes(profile: SubscriptionProfileView) {
    const value = window.prompt("Subscription profile notes", profile.description ?? "");
    if (value === null) {
      return;
    }
    setProfilesBusy(true);
    try {
      const result = await updateSubscriptionProfileMetadata(profile.id, value);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Profile notes saved", message: result.message });
    } catch (error) {
      notifyFromError("Profile notes failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  async function handleProfileFetchUserAgent(profile: SubscriptionProfileView) {
    const value = window.prompt(
      "Subscription fetch user-agent. Leave empty to use default.",
      profile.fetch_options.user_agent ?? "",
    );
    if (value === null) {
      return;
    }
    await applyProfileFetchOptions(
      profile,
      profile.fetch_options.timeout_seconds,
      profile.fetch_options.proxy_mode,
      undefined,
      value,
    );
  }

  async function handleProfileFetchTimeout(profile: SubscriptionProfileView) {
    const value = window.prompt("Subscription fetch timeout, seconds", String(profile.fetch_options.timeout_seconds));
    if (!value?.trim()) {
      return;
    }
    const timeoutSeconds = Number(value);
    if (!Number.isFinite(timeoutSeconds)) {
      pushNotification({ tone: "warning", title: "Invalid timeout", message: "Timeout must be a number of seconds." });
      return;
    }
    await applyProfileFetchOptions(profile, timeoutSeconds, profile.fetch_options.proxy_mode);
  }

  async function applyProfileFetchOptions(
    profile: SubscriptionProfileView,
    timeoutSeconds: number,
    proxyMode: SubscriptionFetchProxyMode,
    customProxyUrl?: string,
    userAgent?: string | null,
  ) {
    setProfilesBusy(true);
    try {
      const result = await updateSubscriptionProfileFetchOptions(profile.id, timeoutSeconds, proxyMode, customProxyUrl, userAgent);
      setSubscriptionProfiles(result.profiles);
      setState(result.state);
      pushNotification({ tone: "success", title: "Fetch options saved", message: result.message });
    } catch (error) {
      notifyFromError("Fetch options failed", error);
    } finally {
      setProfilesBusy(false);
    }
  }

  function handleDroppedProfile(file: File) {
    setOperatorProfileName((current) => current || file.name.replace(/\.(ya?ml|json|txt)$/i, ""));
    file.text()
      .then(setOperatorProfileText)
      .catch((error) => notifyFromError("Dropped file read failed", error));
  }

  function handleAddManualGameProfile() {
    const processName = normalizeProcessName(manualGameProfile.executable);
    if (!processName) {
      pushNotification({ tone: "warning", title: "Executable required", message: "Pick or enter a .exe before saving the game profile." });
      return;
    }
    const now = Date.now().toString(36);
    const nextProfile = {
      id: `manual-${processName.toLocaleLowerCase().replace(/[^a-z0-9]+/g, "-")}-${now}`,
      title: manualGameProfile.title.trim() || processName,
      process_names: [processName],
      domains: textToList(manualGameProfile.domains),
      cidrs: textToList(manualGameProfile.cidrs),
      tcp_ports: textToList(manualGameProfile.tcpPorts),
      udp_ports: textToList(manualGameProfile.udpPorts),
      filter_mode: settings.zapret.game_filter_mode,
      risk_level: "manual",
      detected: false,
      enabled: true,
    };
    updateSettings({
      ...settings,
      zapret: {
        ...settings.zapret,
        game_bypass_mode: "manual",
        learned_game_profiles: [...settings.zapret.learned_game_profiles, nextProfile],
      },
    });
    setManualGameProfile({ title: "", executable: "", domains: "", cidrs: "", tcpPorts: "", udpPorts: "" });
  }

  async function handleBackupAction(action: "export" | "support" | "restore") {
    setOperatorBusy(true);
    try {
      const result =
        action === "export"
          ? await exportBackupBundle()
          : action === "support"
            ? await exportSupportBundle()
            : await restoreBackupBundleFromPath(operatorBackupPath);
      setOperatorSnapshot((current) => current ? { ...current, backups: result.history } : current);
      pushNotification({ tone: "success", title: "Backup", message: result.message });
      if (action === "restore") {
        await loadSettings();
        const [nextState, nextProfiles, nextCatalog, nextSnapshot] = await Promise.all([
          getStatus(),
          getSubscriptionProfiles(),
          getProxyCatalog(),
          getOperatorSnapshot(),
        ]);
        setState(nextState);
        setSubscriptionProfiles(nextProfiles);
        setCatalog(nextCatalog);
        setOperatorSnapshot(nextSnapshot);
      }
    } catch (error) {
      notifyFromError("Backup action failed", error);
    } finally {
      setOperatorBusy(false);
    }
  }

  async function handleOpenDirectory(kind: "app_data" | "runtime" | "logs" | "backups") {
    try {
      await openOperatorDirectory(kind);
    } catch (error) {
      notifyFromError("Open directory failed", error);
    }
  }

  async function handleSelectProxy(group: string, proxy: string) {
    setCatalogBusy(true);
    try {
      const nextCatalog = await selectProxy(group, proxy);
      setCatalog(nextCatalog);
      await runAction(() => getStatus(), false);
      pushNotification({ tone: "success", title: "Server selected", message: `${proxy} selected for ${group}.` });
    } catch (error) {
      notifyFromError("Server selection failed", error);
    } finally {
      setCatalogBusy(false);
    }
  }

  function renderWorkspace() {
    switch (view) {
      case "connections":
        return renderConnectionsPage({
          connections,
          connectionTab,
          setConnectionTab,
          connectionPathFilter,
          setConnectionPathFilter,
          connectionGroupMode,
          setConnectionGroupMode,
          connectionSearch,
          setConnectionSearch,
          refresh: () => void refreshConnections(),
          closeOne: (id) => void handleCloseConnection(id),
          closeMany: (ids) => void handleCloseConnections(ids),
          createOverride: handleCreateOverrideFromConnection,
          closeAll: () => void handleCloseAllConnections(),
          clearClosed: () => void handleClearClosedConnections(),
          busy: connectionsBusy,
        });
      case "servers":
        return renderServersPage({
          catalog,
          selectedGroup,
          setSelectedGroup,
          serverSearch,
          setServerSearch,
          serverNodeSort,
          setServerNodeSort,
          refresh: () => void refreshCatalog(),
          select: (group, proxy) => void handleSelectProxy(group, proxy),
          busy: catalogBusy,
        });
      case "policy":
        return renderPolicyPage({
          policySummary,
          policySearch,
          setPolicySearch,
          policyPathFilter,
          setPolicyPathFilter,
          policySourceFilter,
          setPolicySourceFilter,
          copyText: (label, text) => void handleCopyText(label, text),
          createOverride: handleCreateOverrideFromPolicyRule,
          refresh: () => void refreshPolicySummary(),
          busy: policyBusy,
        });
      case "settings":
        return renderSettingsPage({
          state,
          hasSubscription,
          settings,
          settingsSection,
          appUpdate,
          componentUpdates,
          runtimeDiagnostics,
          runtimeReadiness,
          operatorSnapshot,
          operatorBusy,
          operatorLogPaused,
          operatorLogAutoScroll,
          operatorLogViewCleared,
          operatorLogSourceFilter,
          operatorLogLevelFilter,
          operatorCustomDomain,
          operatorHealthHistory,
          operatorProfileName,
          operatorProfilePath,
          operatorProfileText,
          operatorProfilePreview,
          operatorDeepLink,
          operatorBackupPath,
          manualGameProfile,
          subscriptionProfiles,
          profileUrl,
          agentService,
          zapretService,
          settingsRestartRequired,
          localOverrideRoute,
          setLocalOverrideRoute,
          localOverrideKind,
          setLocalOverrideKind,
          localOverrideValue,
          setLocalOverrideValue,
          updateBusy,
          diagnosticBusy,
          profilesBusy,
          agentServiceBusy,
          zapretServiceBusy,
          settingsBusy,
          busy,
          setSettingsSection,
          setOperatorLogPaused,
          setOperatorLogAutoScroll,
          clearOperatorLogView: () => setOperatorLogViewCleared(true),
          setOperatorLogSourceFilter,
          setOperatorLogLevelFilter,
          setOperatorCustomDomain,
          setOperatorProfileName,
          setOperatorProfilePath,
          setOperatorProfileText: (value) => {
            setOperatorProfileText(value);
            setOperatorProfilePreview(null);
          },
          setOperatorDeepLink,
          setOperatorBackupPath,
          setManualGameProfile,
          updateSettings,
          resetSettings: () => void handleResetSettings(),
          applySettingsRestart: () => void handleApplySettingsRestart(),
          refreshSubscription: () => void handleRefreshSubscription(),
          checkUpdates: () => void handleCheckUpdates(),
          installUpdate: () => void handleInstallAppUpdate(),
          updateRuntime: () => void handleRuntimeUpdate(),
          refreshOperatorSnapshot: () => void refreshOperatorSnapshot(),
          pickExecutable: () => void handlePickExecutable(),
          runZapretChecks: () => void handleRunZapretChecks(),
          repairWindowsNetwork: () => void handleRepairWindowsNetwork(),
          updateResource: (id) => void handleResourceUpdate(id),
          updateAllResources: () => void handleResourceUpdateAll(),
          rollbackResource: (id) => void handleResourceRollback(id),
          previewLocalProfile: (mode) => void handlePreviewLocalProfile(mode),
          importLocalProfile: (mode) => void handleImportLocalProfile(mode),
          refreshAllProfiles: () => void handleRefreshAllProfiles(),
          refreshDueProfiles: () => void handleRefreshDueProfiles(),
          droppedProfile: handleDroppedProfile,
          addManualGameProfile: handleAddManualGameProfile,
          backupAction: (action) => void handleBackupAction(action),
          openDirectory: (kind) => void handleOpenDirectory(kind),
          setProfileUrl,
          addSubscriptionProfile: () => void handleAddSubscriptionProfile(),
          selectSubscriptionProfile: (id) => void handleSelectSubscriptionProfile(id),
          removeSubscriptionProfile: (id) => void handleRemoveSubscriptionProfile(id),
          updateProfileNotes: (profile) => void handleProfileNotes(profile),
          updateProfileFetchProxyMode: (profile, proxyMode) => void handleProfileFetchProxyMode(profile, proxyMode),
          updateProfileFetchTimeout: (profile) => void handleProfileFetchTimeout(profile),
          updateProfileFetchUserAgent: (profile) => void handleProfileFetchUserAgent(profile),
          runDiagnostics: () => void handleRunDiagnostics(),
          copyText: (label, text) => void handleCopyText(label, text),
          refreshAgentService: () => void refreshAgentService(),
          installAgentService: () => void handleInstallAgentService(),
          removeAgentService: () => void handleRemoveAgentService(),
          refreshZapretService: () => void refreshZapretService(),
          openServers: () => setView("servers"),
          policySummary,
        });
      default:
        return renderOverview();
    }
  }

  function renderOverview() {
    return (
      <div className={isOnboarding ? "workspace setupMode" : "workspace dashboardWorkspace"}>
        {isOnboarding ? (
          <section className="setupPane">
            <div className="setupHeader">
              <Shield size={34} aria-hidden="true" />
              <div>
                <h1>Connect subscription</h1>
                <p>BadVpn will generate a Mihomo profile after import.</p>
              </div>
            </div>

            <form className="setupForm" onSubmit={submitSubscription}>
              <label htmlFor="subscription">Subscription URL</label>
              <div className="setupInputRow">
                <input
                  id="subscription"
                  value={subscriptionUrl}
                  onChange={(event) => setSubscriptionUrl(event.currentTarget.value)}
                  placeholder="https://global.badvpn.pro/sub/..."
                  spellCheck={false}
                />
                <button type="submit" disabled={busy || !subscriptionUrl.trim()}>
                  Import
                </button>
              </div>
              {state.subscription.validation_error ? (
                <span className="inlineError">{subscriptionFailureCopy(state.subscription.validation_error)}</span>
              ) : null}
            </form>

            <div className="setupReadiness" aria-label="First run readiness">
              <SetupStep
                title="Subscription"
                status={hasSubscription ? "ready" : state.subscription.validation_error ? "blocked" : "pending"}
                detail={
                  hasSubscription
                    ? `${state.subscription.node_count || "Imported"} nodes ready`
                    : state.subscription.validation_error
                      ? subscriptionFailureCopy(state.subscription.validation_error)
                    : "Paste your BPN Clash/Mihomo subscription URL first."
                }
              />
              <SetupStep
                title="Agent"
                status={agentReady ? "ready" : agentService?.installed ? "pending" : "blocked"}
                detail={
                  agentReady
                    ? "badvpn-agent is installed and reachable."
                    : agentService?.installed
                      ? agentService.message
                      : "Install the privileged agent once; the GUI will stay non-admin after setup."
                }
                action={
                  agentReady ? null : (
                    <button className="subtleButton" type="button" onClick={() => void handleInstallAgentService()} disabled={agentServiceBusy}>
                      <Shield size={15} aria-hidden="true" />
                      Install / repair
                    </button>
                  )
                }
              />
              <SetupStep
                title="Runtime"
                status={runtimeComponentStatus.status}
                detail={runtimeComponentStatus.detail}
                action={
                  <div className="buttonRow">
                    <button className="subtleButton" type="button" onClick={() => void handleCheckUpdates()} disabled={updateBusy}>
                      <RefreshCw size={15} aria-hidden="true" />
                      Check
                    </button>
                    <button className="subtleButton" type="button" onClick={() => void handleRuntimeUpdate()} disabled={updateBusy}>
                      <Download size={15} aria-hidden="true" />
                      Prepare
                    </button>
                  </div>
                }
              />
              <SetupStep
                title="Mode"
                status="ready"
                detail={
                  settings.core.route_mode === "smart"
                    ? "Smart starts as default and falls back to VPN Only if zapret is not ready."
                    : "VPN Only is selected; zapret is skipped."
                }
              />
            </div>
          </section>
        ) : (
          <section className="connectionPane dashboardPane">
            <div className="slothProfileHeader">
              <div>
                <span>Активный профиль</span>
                <strong>{state.subscription.profile_title ?? "BPN subscription"}</strong>
                <small>Подписка</small>
              </div>
              <div className="slothHeaderActions">
                <button className="slothGhostButton" type="button" onClick={() => setState((current) => ({ ...current, phase: "onboarding" }))}>
                  <Plus size={15} aria-hidden="true" />
                  Добавить подписку
                </button>
                {supportUrl ? (
                  <a className="slothSupportButton" href={supportUrl} target="_blank" rel="noreferrer">
                    Поддержка
                  </a>
                ) : (
                  <button className="slothSupportButton" type="button" onClick={() => setView("settings")}>
                    Поддержка
                  </button>
                )}
              </div>
            </div>

            <div className="homeAlertStack">
              <ConnectionProgressView progress={connectionProgress} />
              {smartFallbackActive ? (
                <div className="connectionNotice warning">
                  <AlertTriangle size={16} aria-hidden="true" />
                  <span>Smart fallback: VPN Only активен, потому что zapret сейчас не готов.</span>
                  <button type="button" onClick={() => setView("policy")}>
                    Details
                  </button>
                </div>
              ) : null}
              {state.last_error ? (
                <div className="connectionNotice error">
                  <AlertTriangle size={16} aria-hidden="true" />
                  <span>
                    {connectionFailureStage ? `Failed at ${connectionFailureStage}. ` : ""}
                    {showConnectionDetails ? state.last_error : conciseError(state.last_error)}
                  </span>
                  <button type="button" onClick={() => setShowConnectionDetails((visible) => !visible)}>
                    {showConnectionDetails ? "Hide" : "Details"}
                  </button>
                </div>
              ) : null}
            </div>

            <section className="slothCenterControl">
              <button
                className={isConnected ? "connectButton connected" : isRuntimeTransitioning ? "connectButton pending" : "connectButton"}
                type="button"
                onClick={() => void handlePrimaryConnectionAction()}
                disabled={busy || isRuntimeTransitioning}
                aria-label={isConnected ? "Disconnect" : "Connect"}
              >
                {isRuntimeTransitioning ? <RefreshCw size={50} /> : isConnected ? <CirclePause size={52} /> : <Power size={52} />}
              </button>
              <strong>{isConnected ? "Подключено" : statusLabel}</strong>
              <span className="slothStatusPill">{heroModeLabel}</span>
            </section>

            <section className="slothControlRow">
              <div className="slothSegmentBlock">
                <span>Режим</span>
                <div className="slothSegmented">
                  <button className={settings.core.route_mode === "smart" ? "active" : ""} type="button" onClick={() => updateSettings({ ...settings, core: { ...settings.core, route_mode: "smart" } })}>
                    Rule
                  </button>
                  <button className={settings.core.route_mode === "vpn_only" ? "active" : ""} type="button" onClick={() => updateSettings({ ...settings, core: { ...settings.core, route_mode: "vpn_only" } })}>
                    Global
                  </button>
                </div>
              </div>

              <button className="slothServerPill" type="button" onClick={() => setView("servers")}>
                <IdentityBadge identity={currentServer} className="serverMedallion" size={24} />
                <strong>{currentServer.label}</strong>
                <span aria-hidden="true">›</span>
              </button>

              <div className="slothSegmentBlock alignEnd">
                <span>Трафик</span>
                <div className="slothSegmented">
                  <button type="button">Прокси</button>
                  <button className="active" type="button">TUN</button>
                </div>
              </div>
            </section>

            <section className="slothNoticeGrid">
              <section className="slothAnnouncement">
                <div className="slothAnnouncementHeader">
                  <div className="providerAnnouncementMeta">
                    <strong>Provider</strong>
                    <small>{providerAnnouncement.timestamp}</small>
                  </div>
                  {providerAnnouncement.href ? (
                    <a href={providerAnnouncement.href} target="_blank" rel="noreferrer">
                      <ExternalLink size={13} aria-hidden="true" />
                      {formatExternalLinkHost(providerAnnouncement.href)}
                    </a>
                  ) : null}
                </div>
                <span>{providerAnnouncement.message}</span>
                <div className="bpnAnnouncementLine">
                  <strong>BPN</strong>
                  <span>Signed product announcements are not active.</span>
                </div>
              </section>

              <section className="slothAgentCard">
                <div className="slothAgentHeader">
                  <Shield size={17} aria-hidden="true" />
                  <div>
                    <strong>badvpn-agent</strong>
                    <span>служба для Mihomo, TUN и zapret/winws</span>
                  </div>
                </div>
                <div className="slothAgentRows">
                  <StatusRow label="Agent" value={agentHomeStatus} good={agentReady} />
                  <StatusRow label="zapret" value={zapretHomeStatus} good={!needsZapret || zapretReady} />
                </div>
                <div className="slothAgentActions">
                  {!agentReady ? (
                    <button className="slothTextButton" type="button" onClick={() => void handleInstallAgentService()} disabled={agentServiceBusy || busy}>
                      Install / repair
                    </button>
                  ) : null}
                  <button className="slothTextButton" type="button" onClick={() => void handleRunZapretChecks()} disabled={busy}>
                    Check zapret
                  </button>
                </div>
              </section>
            </section>

            <section className="slothStatusGrid">
              <div className="slothInfoPanel">
                <StatusRow label="Сервис" value={state.running ? "Mihomo running" : "Stopped"} good={state.running} />
                <StatusRow label="Активная группа" value={activeHomeGroup ? parseServerIdentity(activeHomeGroup.name).label : "—"} />
                <StatusRow label="Сервер" value={currentServer.label} />
                <StatusRow label="Latency" value={catalogSelectedNode?.delay_ms !== null && catalogSelectedNode?.delay_ms !== undefined ? `${catalogSelectedNode.delay_ms} ms` : "—"} />
              </div>

              <div className="slothInfoPanel">
                <StatusRow label="Speed" value={`↑ ${trafficStats.uploadSpeed} ↓ ${trafficStats.downloadSpeed}`} />
                <StatusRow label="Сессия" value={`↑ ${trafficStats.uploadTotal} ↓ ${trafficStats.downloadTotal}`} />
                <StatusRow label="Осталось" value={quota.trafficLeft} />
                <StatusRow label="Истекает" value={quota.expires} />
              </div>
            </section>

            <section className="slothGroupsPanel">
              <div className="slothGroupHeader">
                <span>Proxy-groups</span>
                <button className="slothTextButton" type="button" onClick={() => void refreshCatalog()} disabled={catalogBusy}>
                  <RefreshCw size={14} aria-hidden="true" />
                  Обновить
                </button>
              </div>
              <div className="slothGroupList">
                {homeGroups.length ? (
                  homeGroups.map((group) => {
                    const identity = parseServerIdentity(group.name);
                    return (
                      <button
                        className={group.name === activeHomeGroup?.name ? "slothGroupChip active" : "slothGroupChip"}
                        type="button"
                        key={group.name}
                        onClick={() => setSelectedGroup(group.name)}
                      >
                        <IdentityBadge identity={identity} className="groupEmoji" size={14} fallback={<ListTree size={14} aria-hidden="true" />} />
                        <strong>{identity.label}</strong>
                        <small>{group.selected ? parseServerIdentity(group.selected).label : `${group.nodes.length} nodes`}</small>
                      </button>
                    );
                  })
                ) : (
                  <EmptyList icon={<Server size={22} />} title="Каталог недоступен" text={lastCatalogError ?? "Запустите runtime или обновите подписку, чтобы увидеть proxy-groups."} />
                )}
              </div>
              <div className="slothNodeList">
                {homeNodes.slice(0, 6).map((node) => (
                  <HomeNodeButton
                    key={`${activeHomeGroup?.name}-${node.name}`}
                    group={activeHomeGroup?.name ?? ""}
                    node={node}
                    selected={node.selected || node.name === activeHomeGroup?.selected || node.name === currentNode}
                    busy={catalogBusy}
                    select={handleSelectProxy}
                  />
                ))}
              </div>
            </section>
          </section>
        )}

        <aside className="inspector dashboardInspector">
          <Panel title="Runtime">
            <StatusRow label="Mihomo" value={state.running ? "Owned process" : "Stopped"} good={state.running} />
            <StatusRow
              label="zapret"
              value={state.diagnostics.zapret_healthy ? "Running" : "Standby"}
              good={state.diagnostics.zapret_healthy}
            />
            <p className="diagnosticText">{state.diagnostics.message ?? "No diagnostics yet."}</p>
            {startupTimeline.length > 0 ? (
              <div className="timelineChips" aria-label="Startup timeline">
                {startupTimeline.slice(0, 6).map((item) => (
                  <span key={item.name}>
                    {formatTimelineKey(item.name)} <strong>{item.value} ms</strong>
                  </span>
                ))}
              </div>
            ) : null}
          </Panel>

          <Panel title="Subscription">
            {hasSubscription ? (
              <>
                <StatusRow label="Nodes" value={String(state.subscription.node_count)} good />
                <StatusRow label="Format" value={formatRouteMode(state.subscription.format)} />
                <StatusRow label="Refresh" value={formatRefreshInterval(state.subscription.update_interval_hours)} />
                {providerLinks.length > 0 ? (
                  <div className="providerLinkList">
                    {providerLinks.map((link) => (
                      <a key={`${link.label}-${link.href}`} href={link.href} target="_blank" rel="noreferrer">
                        <ExternalLink size={13} aria-hidden="true" />
                        <span>{link.label}</span>
                        <small>{formatExternalLinkHost(link.href)}</small>
                      </a>
                    ))}
                  </div>
                ) : null}
                <button className="subtleButton" type="button" onClick={() => void handleRefreshSubscription()} disabled={busy}>
                  <RefreshCw size={15} aria-hidden="true" />
                  Refresh
                </button>
              </>
            ) : (
              <p className="diagnosticText">No subscription imported.</p>
            )}
          </Panel>

          <Panel title="Routes">
            {routeSummary.map((item) => (
              <StatusRow key={item.label} label={item.label} value={item.value} good={item.good} />
            ))}
            <p className="diagnosticText">
              {smartFallbackActive ? "Smart direct routes are paused until zapret recovers." : "Connections page shows active flow paths."}
            </p>
          </Panel>
        </aside>
      </div>
    );
  }

  return (
    <main className={railExpanded ? "appWindow railExpanded" : "appWindow"}>
      <aside className="rail" aria-label="BadVpn navigation">
        <div className="railBrand" title="BadVpn">
          <Shield size={24} aria-hidden="true" />
          <span>BadVpn</span>
        </div>
        <button
          className="railToggle"
          type="button"
          onClick={() => setRailExpanded((expanded) => !expanded)}
          aria-label={railExpanded ? "Collapse navigation" : "Expand navigation"}
          title={railExpanded ? "Collapse navigation" : "Expand navigation"}
        >
          {railExpanded ? <PanelLeftClose size={17} aria-hidden="true" /> : <PanelLeftOpen size={17} aria-hidden="true" />}
          <span>{railExpanded ? "Collapse" : "Expand"}</span>
        </button>
        <nav className="railNav">
          <RailButton active={view === "overview"} title="Overview" onClick={() => setView("overview")}>
            <Gauge size={19} aria-hidden="true" />
          </RailButton>
          <RailButton active={view === "connections"} title="Connections" onClick={() => setView("connections")}>
            <Activity size={19} aria-hidden="true" />
          </RailButton>
          <RailButton active={view === "servers"} title="Servers" onClick={() => setView("servers")}>
            <ListTree size={19} aria-hidden="true" />
          </RailButton>
          <RailButton active={view === "policy"} title="Policy" onClick={() => setView("policy")}>
            <BookOpen size={19} aria-hidden="true" />
          </RailButton>
          <RailButton active={view === "settings"} title="Settings" onClick={() => setView("settings")}>
            <Settings size={19} aria-hidden="true" />
          </RailButton>
        </nav>
        <div className="railStatusCard" title={heroModeLabel}>
          <span className={isConnected ? "railLed on" : "railLed"} />
          <div>
            <strong>{heroModeLabel}</strong>
            <span>{state.connection.status}</span>
          </div>
        </div>
      </aside>

      <section className={view === "overview" ? "appPane overviewPane" : "appPane"}>
        <header className="appHeader">
          <div className="titleGroup">
            <strong>{viewTitle(view)}</strong>
            <span>{statusLabel}</span>
          </div>
          <div className="headerActions">
            <StatusBadge connected={isConnected} pending={isRuntimeTransitioning} status={statusLabel} />
            {supportUrl ? (
              <a className="iconAction" href={supportUrl} target="_blank" rel="noreferrer" title="Support">
                <LifeBuoy size={16} aria-hidden="true" />
              </a>
            ) : null}
          </div>
        </header>

        {renderWorkspace()}

        <footer className="statusBar">
          <span>{hasSubscription ? state.subscription.profile_title ?? "Subscription ready" : "Waiting for subscription"}</span>
          <div>
            {hasSubscription ? (
              <button className="textAction" type="button" onClick={() => setView("servers")}>
                Servers
              </button>
            ) : null}
            {hasSubscription ? (
              <button className="textAction" type="button" onClick={() => setState((current) => ({ ...current, phase: "onboarding" }))}>
                Edit subscription
              </button>
            ) : null}
            {hasSubscription ? (
              <button className="textAction" type="button" onClick={() => void runAction(restartConnection)} disabled={busy}>
                Restart
              </button>
            ) : null}
          </div>
        </footer>
      </section>
      <NotificationCenter notifications={notifications} dismiss={dismissNotification} />
    </main>
  );
}

type ConnectionProgressModel = {
  label: string;
  steps: Array<{ label: string; state: "done" | "active" | "pending" }>;
};

function SetupStep({
  title,
  status,
  detail,
  action,
}: {
  title: string;
  status: "ready" | "pending" | "blocked";
  detail: string;
  action?: ReactNode;
}) {
  const icon =
    status === "ready" ? (
      <CheckCircle2 size={18} aria-hidden="true" />
    ) : status === "blocked" ? (
      <AlertTriangle size={18} aria-hidden="true" />
    ) : (
      <RefreshCw size={18} aria-hidden="true" />
    );

  return (
    <div className={`setupStep ${status}`}>
      <span className="setupStepIcon">{icon}</span>
      <div>
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      {action ? <div className="setupStepAction">{action}</div> : null}
    </div>
  );
}

function ConnectionProgressView({ progress }: { progress: ConnectionProgressModel | null }) {
  if (!progress) {
    return null;
  }

  return (
    <div className="connectionProgress" aria-live="polite">
      <span>{progress.label}</span>
      <div className="progressSteps">
        {progress.steps.map((step) => (
          <span key={step.label} className={`progressStep ${step.state}`}>
            {step.state === "done" ? <CheckCircle2 size={12} aria-hidden="true" /> : null}
            {step.state === "active" ? <RefreshCw size={12} aria-hidden="true" /> : null}
            {step.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function RailButton({
  active,
  title,
  onClick,
  children,
}: {
  active: boolean;
  title: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className={active ? "railItem active" : "railItem"} type="button" title={title} aria-label={title} onClick={onClick}>
      {children}
      <span>{title}</span>
    </button>
  );
}

function renderConnectionsPage({
  connections,
  connectionTab,
  setConnectionTab,
  connectionPathFilter,
  setConnectionPathFilter,
  connectionGroupMode,
  setConnectionGroupMode,
  connectionSearch,
  setConnectionSearch,
  refresh,
  closeOne,
  closeMany,
  createOverride,
  closeAll,
  clearClosed,
  busy,
}: {
  connections: ConnectionsSnapshot | null;
  connectionTab: ConnectionTab;
  setConnectionTab: (tab: ConnectionTab) => void;
  connectionPathFilter: ConnectionPathFilter;
  setConnectionPathFilter: (filter: ConnectionPathFilter) => void;
  connectionGroupMode: ConnectionGroupMode;
  setConnectionGroupMode: (mode: ConnectionGroupMode) => void;
  connectionSearch: string;
  setConnectionSearch: (value: string) => void;
  refresh: () => void;
  closeOne: (id: string) => void;
  closeMany: (ids: string[]) => void;
  createOverride: (connection: TrackedConnection) => void;
  closeAll: () => void;
  clearClosed: () => void;
  busy: boolean;
}) {
  const active = connections?.active ?? [];
  const closed = connections?.closed ?? [];
  const rows = connectionTab === "active" ? active : closed;
  const pathCounts = connectionPathOptions.map(([path]) => [
    path,
    path === "all" ? rows.length : rows.filter((connection) => connection.path === path).length,
  ] as const);
  const connectionQuery = connectionSearch.trim().toLocaleLowerCase();
  const visibleRows = rows.filter((connection) => {
    return (
      (connectionPathFilter === "all" || connection.path === connectionPathFilter) &&
      (!connectionQuery || connectionMatchesSearch(connection, connectionQuery))
    );
  });
  const processGroups = groupConnectionsByProcess(visibleRows);
  const visibleActiveIds = visibleRows.filter((connection) => connection.state === "active").map((connection) => connection.id);

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel connectionsPanel">
        <div className="pageHeader">
          <div>
            <h1>Connections</h1>
            <p>Live Mihomo flows plus closed-session history tracked by BadVpn.</p>
          </div>
          <div className="buttonRow">
            <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
              <RefreshCw size={15} aria-hidden="true" />
              Refresh
            </button>
            {connectionTab === "active" ? (
              <button className="subtleButton danger" type="button" onClick={closeAll} disabled={busy || active.length === 0}>
                <X size={15} aria-hidden="true" />
                Close all
              </button>
            ) : (
              <button className="subtleButton" type="button" onClick={clearClosed} disabled={closed.length === 0}>
                <History size={15} aria-hidden="true" />
                Clear
              </button>
            )}
          </div>
        </div>

        <div className="pathLegend">
          <LegendItem tone="vpn" title="VPN" text="Mihomo proxy chain; traffic exits through selected server." />
          <LegendItem tone="zapret" title="zapret" text="DIRECT in Mihomo plus Flowseal/winws DPI bypass for Discord, YouTube, and game targets." />
          <LegendItem tone="direct" title="DIRECT" text="No VPN proxy and not matched by zapret list." />
        </div>

        <div className="connectionToolbar">
          <label className="searchField connectionSearchField">
            <span>Search</span>
            <input
              type="search"
              value={connectionSearch}
              placeholder="Host, process, rule, chain"
              spellCheck={false}
              onChange={(event) => setConnectionSearch(event.currentTarget.value)}
            />
          </label>
          <div
            className="segmented fluidSegmented connectionTabs"
            style={{ "--segment-count": 2, "--segment-index": connectionTab === "active" ? 0 : 1 } as CSSProperties}
          >
            <button className={connectionTab === "active" ? "active" : ""} type="button" onClick={() => setConnectionTab("active")}>
              Current <span>{active.length}</span>
            </button>
            <button className={connectionTab === "closed" ? "active" : ""} type="button" onClick={() => setConnectionTab("closed")}>
              Closed <span>{closed.length}</span>
            </button>
          </div>
          <div className="pathFilter" aria-label="Connection route filter">
            {connectionPathOptions.map(([path, label]) => {
              const count = pathCounts.find(([countPath]) => countPath === path)?.[1] ?? 0;
              return (
                <button
                  key={path}
                  className={connectionPathFilter === path ? `active ${path}` : path}
                  type="button"
                  onClick={() => setConnectionPathFilter(path)}
                  title={`Show ${label} connections`}
                >
                  {label}
                  <span>{count}</span>
                </button>
              );
            })}
          </div>
          {connectionTab === "active" && connectionPathFilter !== "all" && visibleActiveIds.length > 0 ? (
            <button className="subtleButton danger" type="button" onClick={() => closeMany(visibleActiveIds)} disabled={busy}>
              <X size={15} aria-hidden="true" />
              Close filtered
            </button>
          ) : null}
          <div
            className="segmented compactSegmented"
            style={{ "--segment-count": 2, "--segment-index": connectionGroupMode === "flows" ? 0 : 1 } as CSSProperties}
          >
            <button className={connectionGroupMode === "flows" ? "active" : ""} type="button" onClick={() => setConnectionGroupMode("flows")}>
              Flows
            </button>
            <button
              className={connectionGroupMode === "processes" ? "active" : ""}
              type="button"
              onClick={() => setConnectionGroupMode("processes")}
            >
              Processes
            </button>
          </div>
        </div>

        <div className="connectionList">
          {rows.length === 0 ? (
            <EmptyList icon={<Activity size={24} />} title="No connections" text="Start the VPN and open an app to see live routes here." />
          ) : visibleRows.length === 0 ? (
            <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching connections" text="Change search or route filter to show hidden flows." />
          ) : connectionGroupMode === "processes" ? (
            processGroups.map((group) => (
              <ConnectionProcessGroup key={group.key} group={group} closeOne={closeOne} closeMany={closeMany} createOverride={createOverride} />
            ))
          ) : (
            visibleRows.map((connection) => (
              <ConnectionRow
                key={`${connection.state}-${connection.id}-${connection.closed_at ?? "open"}`}
                connection={connection}
                closeOne={closeOne}
                createOverride={createOverride}
              />
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function renderServersPage({
  catalog,
  selectedGroup,
  setSelectedGroup,
  serverSearch,
  setServerSearch,
  serverNodeSort,
  setServerNodeSort,
  refresh,
  select,
  busy,
}: {
  catalog: ProxyCatalog | null;
  selectedGroup: string | null;
  setSelectedGroup: (group: string) => void;
  serverSearch: string;
  setServerSearch: (value: string) => void;
  serverNodeSort: ServerNodeSort;
  setServerNodeSort: (value: ServerNodeSort) => void;
  refresh: () => void;
  select: (group: string, proxy: string) => void;
  busy: boolean;
}) {
  const groups = catalog?.groups ?? [];
  const query = serverSearch.trim().toLocaleLowerCase();
  const filteredGroups = query ? groups.filter((group) => proxyGroupMatchesSearch(group, query)) : groups;
  const activeGroup = filteredGroups.find((group) => group.name === selectedGroup) ?? filteredGroups[0] ?? null;
  const activeGroupMatchesQuery = activeGroup ? proxyGroupText(activeGroup).includes(query) : false;
  const visibleNodes = activeGroup
    ? sortProxyNodes(
        activeGroup.nodes.filter((node) => !query || activeGroupMatchesQuery || proxyNodeMatchesSearch(node, query)),
        serverNodeSort,
        activeGroup.selected,
      )
    : [];

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel serverPanel">
        <div className="pageHeader">
          <div>
            <h1>Servers</h1>
            <p>Proxy groups from the generated Mihomo profile.</p>
          </div>
          <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </button>
        </div>

        <div className="serverToolbar">
          <label className="searchField">
            <span>Search</span>
            <input
              value={serverSearch}
              onChange={(event) => setServerSearch(event.currentTarget.value)}
              placeholder="Group, node, host..."
              spellCheck={false}
            />
          </label>
          <label className="selectField compactField">
            <span>Sort nodes</span>
            <select value={serverNodeSort} onChange={(event) => setServerNodeSort(event.currentTarget.value as ServerNodeSort)}>
              {serverNodeSortOptions.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {groups.length === 0 ? (
          <EmptyList icon={<Server size={24} />} title="No server groups" text="Import a valid subscription to view Mihomo groups." />
        ) : filteredGroups.length === 0 ? (
          <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching servers" text="Clear search to show all proxy groups and nodes." />
        ) : (
          <div className="serverGrid">
            <div className="groupList">
              {filteredGroups.map((group) => (
                <GroupButton key={group.name} group={group} active={activeGroup?.name === group.name} onClick={() => setSelectedGroup(group.name)} />
              ))}
            </div>
            <div className="nodeList">
              <div className="nodeHeader">
                <div>
                  <strong>{activeGroup ? parseServerIdentity(activeGroup.name).label : ""}</strong>
                  <span>
                    {activeGroup?.group_type} group · {visibleNodes.length}/{activeGroup?.nodes.length ?? 0} nodes
                  </span>
                </div>
                <span>{activeGroup?.selected ? `Selected: ${parseServerIdentity(activeGroup.selected).label}` : "No runtime selection"}</span>
              </div>
              {activeGroup && visibleNodes.length > 0 ? (
                visibleNodes.map((node) => (
                  <NodeRow key={node.name} group={activeGroup.name} node={node} busy={busy} select={select} />
                ))
              ) : (
                <EmptyList icon={<Server size={22} />} title="No matching nodes" text="Change search or sorting to inspect this group." />
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function renderPolicyPage({
  policySummary,
  policySearch,
  setPolicySearch,
  policyPathFilter,
  setPolicyPathFilter,
  policySourceFilter,
  setPolicySourceFilter,
  copyText,
  createOverride,
  refresh,
  busy,
}: {
  policySummary: PolicySummaryResponse | null;
  policySearch: string;
  setPolicySearch: (value: string) => void;
  policyPathFilter: PolicyPathFilter;
  setPolicyPathFilter: (filter: PolicyPathFilter) => void;
  policySourceFilter: string;
  setPolicySourceFilter: (source: string) => void;
  copyText: (label: string, text: string) => void;
  createOverride: (rule: PolicyRuleView) => void;
  refresh: () => void;
  busy: boolean;
}) {
  const policy = policySummary;
  const notAvailable = !policy || !policy.available;
  const policyQuery = policySearch.trim().toLocaleLowerCase();
  const pathCounts = policyPathOptions.map(([path]) => [
    path,
    !policy
      ? 0
      : path === "all"
        ? policy.policy_rules.length
        : policy.policy_rules.filter((rule) => policyPathTone(rule.path) === path).length,
  ] as const);
  const sourceCounts = policy ? countPolicySources(policy.policy_rules, compareText, formatRouteMode) : [];
  const filteredPolicyRules = policy
    ? policy.policy_rules.filter((rule) => {
        const tone = policyPathTone(rule.path) as PolicyPathFilter;
        return (
          (policyPathFilter === "all" || tone === policyPathFilter) &&
          (policySourceFilter === "all" || rule.source === policySourceFilter) &&
          (!policyQuery || policyRuleSearchText(rule).includes(policyQuery))
        );
      })
    : [];
  const filteredMihomoRules = policy
    ? policyQuery
      ? policy.mihomo_rules.filter((rule) => rule.toLocaleLowerCase().includes(policyQuery))
      : policy.mihomo_rules
    : [];
  const filteredSuppressedRules = policy
    ? policyQuery
      ? policy.suppressed_rules.filter((rule) => suppressedRuleSearchText(rule).includes(policyQuery))
      : policy.suppressed_rules
    : [];

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel policyPanel">
        <div className="pageHeader">
          <div>
            <h1>Effective policy</h1>
            <p>Read-only view of the compiled routing policy. Reflects last subscription import or connect.</p>
          </div>
          <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </button>
        </div>

        {notAvailable ? (
          <EmptyList
            icon={<BookOpen size={24} />}
            title="No policy compiled yet"
            text="Import a subscription and connect at least once to see the effective routing policy."
          />
        ) : (
          <>
            <div className="policySummaryCards">
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Mode</span>
                <strong className="policySummaryValue">{policy.mode}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Main proxy group</span>
                <strong className="policySummaryValue">{policy.main_proxy_group || "—"}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Rules</span>
                <strong className="policySummaryValue">{policy.rule_count}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Suppressed</span>
                <strong className={policy.suppressed_count > 0 ? "policySummaryValue warn" : "policySummaryValue"}>
                  {policy.suppressed_count}
                </strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">zapret domains</span>
                <strong className="policySummaryValue">{policy.zapret_domain_count}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Warnings</span>
                <strong className={policy.warnings_count > 0 ? "policySummaryValue warn" : "policySummaryValue"}>
                  {policy.warnings_count}
                </strong>
              </div>
              <div className="policySummaryCard span2">
                <span className="policySummaryLabel">Final rule</span>
                <strong className="policySummaryValue mono">{policy.final_rule || "—"}</strong>
              </div>
            </div>

            {policy.policy_rules.length > 0 ? (
              <div className="policyToolbar">
                <label className="searchField">
                  <span>Search rules</span>
                  <input
                    type="search"
                    value={policySearch}
                    placeholder="Domain, CIDR, process, source, generated rule"
                    spellCheck={false}
                    onChange={(event) => setPolicySearch(event.currentTarget.value)}
                  />
                </label>
                <label className="compactField">
                  <span>Source</span>
                  <select value={policySourceFilter} onChange={(event) => setPolicySourceFilter(event.currentTarget.value)}>
                    <option value="all">All sources ({policy.policy_rules.length})</option>
                    {sourceCounts.map(([source, count]) => (
                      <option key={source} value={source}>
                        {formatRouteMode(source)} ({count})
                      </option>
                    ))}
                  </select>
                </label>
                <div className="pathFilter policyPathFilter" aria-label="Policy path filter">
                  {policyPathOptions.map(([path, label]) => {
                    const count = pathCounts.find(([countPath]) => countPath === path)?.[1] ?? 0;
                    return (
                      <button
                        key={path}
                        className={policyPathFilter === path ? `active ${path}` : path}
                        type="button"
                        onClick={() => setPolicyPathFilter(path)}
                        title={`Show ${label} policy rules`}
                      >
                        {label}
                        <span>{count}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : null}

            {policy.policy_rules.length > 0 ? (
              <div className="policyQuickStats">
                {pathCounts
                  .filter(([path, count]) => path !== "all" && count > 0)
                  .map(([path, count]) => (
                    <span key={path} className={path}>
                      {formatRouteMode(path)} {count}
                    </span>
                  ))}
                {sourceCounts.map(([source, count]) => (
                  <span key={source}>
                    {formatRouteMode(source)} {count}
                  </span>
                ))}
              </div>
            ) : null}

            {policy.policy_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Policy rules <span className="policyCount">{filteredPolicyRules.length}</span>
                  <span className="policyCount muted">{policy.policy_rules.length} total</span>
                </h2>
                {filteredPolicyRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching policy rules" text="Change search or path filter to show hidden rules." />
                ) : (
                  <div className="policyTableWrap">
                    <table className="policyTable" id="policy-rules-table">
                      <thead>
                        <tr>
                          <th>Target</th>
                          <th>Value</th>
                          <th>Path</th>
                          <th>Source</th>
                          <th>Mihomo rule</th>
                          <th>zapret</th>
                          <th>DNS</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPolicyRules.map((rule, index) => (
                          <tr key={`${rule.priority}-${rule.target_kind}-${rule.target_value}-${index}`} className={policyPathTone(rule.path)}>
                            <td className="mono">{rule.target_kind}</td>
                            <td className="mono wrap">{rule.target_value}</td>
                            <td>
                              <span className={`policyPathBadge ${policyPathTone(rule.path)}`}>
                                {rule.path}
                              </span>
                            </td>
                            <td>{rule.source}</td>
                            <td className="mono wrap">{rule.mihomo_rule}</td>
                            <td>{rule.zapret_effect}</td>
                            <td>{rule.dns_effect}</td>
                            <td className="policyActions">
                              <button className="iconSmall" type="button" onClick={() => copyText("Policy rule", formatPolicyRuleForCopy(rule))} title="Copy policy rule details">
                                <Copy size={13} aria-hidden="true" />
                              </button>
                              {localOverrideDraftFromPolicyRule(rule) ? (
                                <button className="iconSmall" type="button" onClick={() => createOverride(rule)} title="Create local override from this policy rule">
                                  <Plus size={13} aria-hidden="true" />
                                </button>
                              ) : null}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : null}

            {policy.suppressed_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Suppressed rules <span className="policyCount">{filteredSuppressedRules.length}</span>
                  <span className="policyCount muted">{policy.suppressed_rules.length} total</span>
                </h2>
                {filteredSuppressedRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching suppressed rules" text="Clear search to inspect all suppressed provider rules." />
                ) : (
                  <div className="policyTableWrap">
                    <table className="policyTable" id="policy-suppressed-table">
                      <thead>
                        <tr>
                          <th>Original rule</th>
                          <th>Chosen rule</th>
                          <th>Reason</th>
                          <th>Copy</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredSuppressedRules.map((rule, index) => (
                          <tr key={`${rule.original_rule}-${index}`}>
                            <td className="mono wrap">{rule.original_rule}</td>
                            <td className="mono wrap">{rule.chosen_rule}</td>
                            <td>{rule.reason}</td>
                            <td>
                              <button className="iconSmall" type="button" onClick={() => copyText("Suppressed rule", rule.chosen_rule)} title="Copy chosen rule">
                                <Copy size={13} aria-hidden="true" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : null}

            {policy.mihomo_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Mihomo rules <span className="policyCount">{filteredMihomoRules.length}</span>
                  <span className="policyCount muted">{policy.mihomo_rules.length} total</span>
                </h2>
                {filteredMihomoRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching Mihomo rules" text="Clear search to show the generated rules." />
                ) : (
                  <div className="policyRuleList" id="policy-mihomo-rules">
                    {filteredMihomoRules.map((rule, index) => (
                      <div key={`${rule}-${index}`} className="policyRuleLine">
                        <span className="policyRuleIndex">{index + 1}</span>
                        <code>{rule}</code>
                        <button className="iconSmall" type="button" onClick={() => copyText("Mihomo rule", rule)} title="Copy Mihomo rule">
                          <Copy size={13} aria-hidden="true" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : null}

            {policy.diagnostics_expectations.length > 0 ? (
              <div className="policySection">
                <h2>Route expectations <span className="policyCount">{policy.diagnostics_expectations.length}</span></h2>
                <div className="policyTableWrap">
                  <table className="policyTable" id="policy-expectations-table">
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Expected path</th>
                        <th>Mihomo action</th>
                        <th>zapret expected</th>
                        <th>Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.diagnostics_expectations.map((exp, index) => (
                        <tr key={index}>
                          <td className="mono">{exp.target}</td>
                          <td>{exp.expected_path}</td>
                          <td className="mono">{exp.expected_mihomo_action}</td>
                          <td>{exp.expected_zapret ? "Yes" : "—"}</td>
                          <td>{exp.source}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.zapret_hostlist.length > 0 || policy.zapret_ipset.length > 0 ? (
              <div className="policySection">
                <h2>zapret artifacts</h2>
                <div className="policyArtifactGrid">
                  {policy.zapret_hostlist.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>Hostlist <span className="policyCount">{policy.zapret_hostlist.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_hostlist.map((host, index) => (
                          <code key={index}>{host}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_hostlist_exclude.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>Hostlist exclude <span className="policyCount">{policy.zapret_hostlist_exclude.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_hostlist_exclude.map((host, index) => (
                          <code key={index}>{host}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_ipset.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>IPSet <span className="policyCount">{policy.zapret_ipset.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_ipset.map((cidr, index) => (
                          <code key={index}>{cidr}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_ipset_exclude.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>IPSet exclude <span className="policyCount">{policy.zapret_ipset_exclude.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_ipset_exclude.map((cidr, index) => (
                          <code key={index}>{cidr}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {policy.dns_nameserver_policy.length > 0 ? (
              <div className="policySection">
                <h2>DNS policy <span className="policyCount">{policy.dns_nameserver_policy.length}</span></h2>
                <div className="policyTableWrap">
                  <table className="policyTable" id="policy-dns-table">
                    <thead>
                      <tr>
                        <th>Pattern</th>
                        <th>Nameservers</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.dns_nameserver_policy.map((rule, index) => (
                        <tr key={index}>
                          <td className="mono">{rule.pattern}</td>
                          <td className="mono wrap">{rule.nameservers.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.managed_proxy_groups.length > 0 ? (
              <div className="policySection">
                <h2>Managed proxy groups <span className="policyCount">{policy.managed_proxy_groups.length}</span></h2>
                {policy.managed_proxy_groups.map((group, index) => (
                  <div key={index} className="policyManagedGroup">
                    <strong>{group.name}</strong>
                    <span>{group.proxies.join(", ") || "No proxies"}</span>
                  </div>
                ))}
              </div>
            ) : null}

            {policy.diagnostics_messages.length > 0 ? (
              <div className="policySection">
                <h2>Warnings <span className="policyCount warn">{policy.diagnostics_messages.length}</span></h2>
                <div className="policyWarningList">
                  {policy.diagnostics_messages.map((message, index) => (
                    <div key={index} className="policyWarning">
                      <AlertTriangle size={14} aria-hidden="true" />
                      <span>{message}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </>
        )}
      </section>
    </div>
  );
}

function renderSettingsPage({
  state,
  hasSubscription,
  settings,
  settingsSection,
  appUpdate,
  componentUpdates,
  runtimeDiagnostics,
  runtimeReadiness,
  operatorSnapshot,
  operatorBusy,
  operatorLogPaused,
  operatorLogAutoScroll,
  operatorLogViewCleared,
  operatorLogSourceFilter,
  operatorLogLevelFilter,
  operatorCustomDomain,
  operatorHealthHistory,
  operatorProfileName,
  operatorProfilePath,
  operatorProfileText,
  operatorProfilePreview,
  operatorDeepLink,
  operatorBackupPath,
  manualGameProfile,
  subscriptionProfiles,
  profileUrl,
  agentService,
  zapretService,
  settingsRestartRequired,
  localOverrideRoute,
  setLocalOverrideRoute,
  localOverrideKind,
  setLocalOverrideKind,
  localOverrideValue,
  setLocalOverrideValue,
  updateBusy,
  diagnosticBusy,
  profilesBusy,
  agentServiceBusy,
  zapretServiceBusy,
  settingsBusy,
  busy,
  setSettingsSection,
  setOperatorLogPaused,
  setOperatorLogAutoScroll,
  clearOperatorLogView,
  setOperatorLogSourceFilter,
  setOperatorLogLevelFilter,
  setOperatorCustomDomain,
  setOperatorProfileName,
  setOperatorProfilePath,
  setOperatorProfileText,
  setOperatorDeepLink,
  setOperatorBackupPath,
  setManualGameProfile,
  updateSettings,
  resetSettings,
  applySettingsRestart,
  refreshSubscription,
  checkUpdates,
  installUpdate,
  updateRuntime,
  refreshOperatorSnapshot,
  pickExecutable,
  runZapretChecks,
  repairWindowsNetwork,
  updateResource,
  updateAllResources,
  rollbackResource,
  previewLocalProfile,
  importLocalProfile,
  refreshAllProfiles,
  refreshDueProfiles,
  droppedProfile,
  addManualGameProfile,
  backupAction,
  openDirectory,
  setProfileUrl,
  addSubscriptionProfile,
  selectSubscriptionProfile,
  removeSubscriptionProfile,
  updateProfileNotes,
  updateProfileFetchProxyMode,
  updateProfileFetchTimeout,
  updateProfileFetchUserAgent,
  runDiagnostics,
  copyText,
  refreshAgentService,
  installAgentService,
  removeAgentService,
  refreshZapretService,
  openServers,
  policySummary,
}: {
  state: AgentState;
  hasSubscription: boolean;
  settings: AppSettings;
  settingsSection: SettingsSection;
  appUpdate: AppUpdateStatus;
  componentUpdates: ComponentUpdate[];
  runtimeDiagnostics: RuntimeDiagnosticsReport | null;
  runtimeReadiness: RuntimeReadinessResponse | null;
  operatorSnapshot: OperatorSnapshot | null;
  operatorBusy: boolean;
  operatorLogPaused: boolean;
  operatorLogAutoScroll: boolean;
  operatorLogViewCleared: boolean;
  operatorLogSourceFilter: string;
  operatorLogLevelFilter: string;
  operatorCustomDomain: string;
  operatorHealthHistory: ZapretHealthReport[];
  operatorProfileName: string;
  operatorProfilePath: string;
  operatorProfileText: string;
  operatorProfilePreview: LocalProfilePreview | null;
  operatorDeepLink: string;
  operatorBackupPath: string;
  manualGameProfile: {
    title: string;
    executable: string;
    domains: string;
    cidrs: string;
    tcpPorts: string;
    udpPorts: string;
  };
  subscriptionProfiles: SubscriptionProfilesState;
  profileUrl: string;
  agentService: AgentServiceStatus | null;
  zapretService: ZapretServiceStatus | null;
  settingsRestartRequired: boolean;
  localOverrideRoute: LocalOverrideRoute;
  setLocalOverrideRoute: (route: LocalOverrideRoute) => void;
  localOverrideKind: LocalOverrideTargetKind;
  setLocalOverrideKind: (kind: LocalOverrideTargetKind) => void;
  localOverrideValue: string;
  setLocalOverrideValue: (value: string) => void;
  updateBusy: boolean;
  diagnosticBusy: boolean;
  profilesBusy: boolean;
  agentServiceBusy: boolean;
  zapretServiceBusy: boolean;
  settingsBusy: boolean;
  busy: boolean;
  setSettingsSection: (section: SettingsSection) => void;
  setOperatorLogPaused: (paused: boolean) => void;
  setOperatorLogAutoScroll: (enabled: boolean) => void;
  clearOperatorLogView: () => void;
  setOperatorLogSourceFilter: (source: string) => void;
  setOperatorLogLevelFilter: (level: string) => void;
  setOperatorCustomDomain: (value: string) => void;
  setOperatorProfileName: (value: string) => void;
  setOperatorProfilePath: (value: string) => void;
  setOperatorProfileText: (value: string) => void;
  setOperatorDeepLink: (value: string) => void;
  setOperatorBackupPath: (value: string) => void;
  setManualGameProfile: (value: {
    title: string;
    executable: string;
    domains: string;
    cidrs: string;
    tcpPorts: string;
    udpPorts: string;
  }) => void;
  updateSettings: (settings: AppSettings) => void;
  resetSettings: () => void;
  applySettingsRestart: () => void;
  refreshSubscription: () => void;
  checkUpdates: () => void;
  installUpdate: () => void;
  updateRuntime: () => void;
  refreshOperatorSnapshot: () => void;
  pickExecutable: () => void;
  runZapretChecks: () => void;
  repairWindowsNetwork: () => void;
  updateResource: (id: string) => void;
  updateAllResources: () => void;
  rollbackResource: (id: string) => void;
  previewLocalProfile: (mode: "path" | "text") => void;
  importLocalProfile: (mode: "path" | "text" | "link") => void;
  refreshAllProfiles: () => void;
  refreshDueProfiles: () => void;
  droppedProfile: (file: File) => void;
  addManualGameProfile: () => void;
  backupAction: (action: "export" | "support" | "restore") => void;
  openDirectory: (kind: "app_data" | "runtime" | "logs" | "backups") => void;
  setProfileUrl: (value: string) => void;
  addSubscriptionProfile: () => void;
  selectSubscriptionProfile: (id: string) => void;
  removeSubscriptionProfile: (id: string) => void;
  updateProfileNotes: (profile: SubscriptionProfileView) => void;
  updateProfileFetchProxyMode: (profile: SubscriptionProfileView, proxyMode: SubscriptionFetchProxyMode) => void;
  updateProfileFetchTimeout: (profile: SubscriptionProfileView) => void;
  updateProfileFetchUserAgent: (profile: SubscriptionProfileView) => void;
  runDiagnostics: () => void;
  copyText: (label: string, text: string) => void;
  refreshAgentService: () => void;
  installAgentService: () => void;
  removeAgentService: () => void;
  refreshZapretService: () => void;
  openServers: () => void;
  policySummary: PolicySummaryResponse | null;
}) {
  const updateCore = (patch: Partial<AppSettings["core"]>) =>
    updateSettings({ ...settings, core: { ...settings.core, ...patch } });
  const updateTun = (patch: Partial<AppSettings["tun"]>) =>
    updateSettings({ ...settings, tun: { ...settings.tun, ...patch } });
  const updateDns = (patch: Partial<AppSettings["dns"]>) =>
    updateSettings({ ...settings, dns: { ...settings.dns, ...patch } });
  const updateSniffer = (patch: Partial<AppSettings["sniffer"]>) =>
    updateSettings({ ...settings, sniffer: { ...settings.sniffer, ...patch } });
  const updateZapret = (patch: Partial<AppSettings["zapret"]>) =>
    updateSettings({ ...settings, zapret: { ...settings.zapret, ...patch } });
  const updateRoutingPolicy = (patch: Partial<AppSettings["routing_policy"]>) =>
    updateSettings({ ...settings, routing_policy: { ...settings.routing_policy, ...patch } });
  const updateSmartPresets = (patch: Partial<AppSettings["routing_policy"]["smart_presets"]>) =>
    updateRoutingPolicy({
      smart_presets: { ...settings.routing_policy.smart_presets, ...patch },
    });
  const updateUpdates = (patch: Partial<AppSettings["updates"]>) =>
    updateSettings({ ...settings, updates: { ...settings.updates, ...patch } });
  const updateDiagnostics = (patch: Partial<AppSettings["diagnostics"]>) =>
    updateSettings({ ...settings, diagnostics: { ...settings.diagnostics, ...patch } });
  const toggleLearnedGameProfile = (id: string, enabled: boolean) =>
    updateZapret({
      learned_game_profiles: settings.zapret.learned_game_profiles.map((profile) =>
        profile.id === id ? { ...profile, enabled } : profile
      ),
    });
  const localOverrideKinds = localOverrideTargetKindsForRoute(localOverrideRoute);
  const localOverridePreview = previewLocalOverride(localOverrideRoute, localOverrideKind, localOverrideValue);
  const localOverrideAllowed = localOverrideKinds.includes(localOverrideKind);
  const localOverrideDuplicate = localOverrideExists(settings.routing_policy, localOverrideRoute, localOverrideKind, localOverrideValue);
  const providerLinks = providerMetadataLinks(state.subscription);
  const addLocalOverride = () => {
    const patch = buildLocalOverridePatch(settings.routing_policy, localOverrideRoute, localOverrideKind, localOverrideValue);
    if (!patch) {
      return;
    }
    updateRoutingPolicy(patch);
    setLocalOverrideValue("");
  };
  const toggleLocalOverrideRule = (id: string, enabled: boolean) => {
    const rule = settings.routing_policy.local_overrides.rules.find((item) => item.id === id);
    const patch: Partial<AppSettings["routing_policy"]> = {
      local_overrides: {
        version: settings.routing_policy.local_overrides.version,
        rules: settings.routing_policy.local_overrides.rules.map((rule) =>
          rule.id === id ? { ...rule, enabled, updated_at: Math.floor(Date.now() / 1000) } : rule,
        ),
      },
    };
    if (rule && !enabled) {
      Object.assign(patch, removeLegacyOverrideValue(settings.routing_policy, rule.path, rule.target_kind, rule.process_name ?? rule.value));
    }
    updateRoutingPolicy(patch);
  };
  const deleteLocalOverrideRule = (id: string) => {
    const rule = settings.routing_policy.local_overrides.rules.find((item) => item.id === id);
    const nextRules = settings.routing_policy.local_overrides.rules.filter((item) => item.id !== id);
    const patch: Partial<AppSettings["routing_policy"]> = {
      local_overrides: {
        version: settings.routing_policy.local_overrides.version,
        rules: nextRules,
      },
    };
    if (rule) {
      Object.assign(patch, removeLegacyOverrideValue(settings.routing_policy, rule.path, rule.target_kind, rule.process_name ?? rule.value));
    }
    updateRoutingPolicy(patch);
  };

  return (
    <div className="workspace pageWorkspace">
      <section className="settingsShell">
        <div className="settingsSide">
          <SettingsTab active={settingsSection === "basic"} icon={<SlidersHorizontal size={16} />} label="Basic" onClick={() => setSettingsSection("basic")} />
          <SettingsTab active={settingsSection === "advanced"} icon={<Router size={16} />} label="Advanced" onClick={() => setSettingsSection("advanced")} />
          <SettingsTab active={settingsSection === "operator"} icon={<ListTree size={16} />} label="Operator" onClick={() => setSettingsSection("operator")} />
          <SettingsTab active={settingsSection === "updates"} icon={<RefreshCw size={16} />} label="Updates" onClick={() => setSettingsSection("updates")} />
        </div>

        <div className="settingsContent">
          {settingsRestartRequired ? (
            <div className="settingsBanner">
              <AlertTriangle size={17} aria-hidden="true" />
              <span>Restart required</span>
              <button className="primarySmall" type="button" onClick={applySettingsRestart} disabled={settingsBusy || busy}>
                Save & restart
              </button>
            </div>
          ) : null}

          {settingsSection === "basic" ? (
            <section className="settingsPanels">
              <Panel title="Connection">
                <SegmentedControl
                  label="Mode"
                  value={settings.core.route_mode}
                  options={[
                    ["smart", "Smart"],
                    ["vpn_only", "VPN Only"],
                  ]}
                  onChange={(value) =>
                    updateSettings({
                      ...settings,
                      core: { ...settings.core, route_mode: value as AppSettings["core"]["route_mode"] },
                      zapret: { ...settings.zapret, enabled: value === "smart" },
                    })
                  }
                  disabled={settingsBusy}
                />
                <p className="diagnosticText">
                  {settings.core.route_mode === "smart"
                    ? "Smart is the default: video, Discord, and games use DIRECT + zapret while protected provider routes stay on VPN."
                    : "VPN Only skips zapret and keeps external traffic on VPN paths."}
                </p>
                <StatusRow label="Selected" value={state.connection.selected_proxy ?? "Provider default"} good={hasSubscription} />
                <button className="subtleButton" type="button" onClick={openServers} disabled={!hasSubscription}>
                  <Server size={15} aria-hidden="true" />
                  Servers
                </button>
              </Panel>
              <Panel title="Smart presets">
                <ToggleRow label="YouTube + Discord via zapret" checked={settings.routing_policy.smart_presets.youtube_discord_zapret} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ youtube_discord_zapret: checked })} />
                <ToggleRow label="Games via zapret" checked={settings.routing_policy.smart_presets.games_zapret} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ games_zapret: checked })} />
                <ToggleRow label="AI via VPN" checked={settings.routing_policy.smart_presets.ai_vpn} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ ai_vpn: checked })} />
                <ToggleRow label="Social via VPN" checked={settings.routing_policy.smart_presets.social_vpn} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ social_vpn: checked })} />
                <ToggleRow label="Telegram from provider" checked={settings.routing_policy.smart_presets.telegram_vpn_from_provider} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ telegram_vpn_from_provider: checked })} />
              </Panel>
              <Panel title="Quick actions">
                <StatusRow label="Agent" value={agentService?.ipc_ready ? "Ready" : "Needs setup"} good={agentService?.ipc_ready ?? false} />
                <StatusRow label="Runtime" value={formatRuntimeComponentStatus(componentUpdates, runtimeReadiness)} good={runtimeReadiness?.components_ready} />
                <div className="buttonRow">
                  <button className="subtleButton" type="button" onClick={refreshSubscription} disabled={busy || !hasSubscription}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh profile
                  </button>
                  <button className="subtleButton" type="button" onClick={runDiagnostics} disabled={diagnosticBusy}>
                    <Activity size={15} aria-hidden="true" />
                    Diagnostics
                  </button>
                </div>
              </Panel>
            </section>
          ) : null}

          {settingsSection === "advanced" ? (
            <section className="settingsPanels">
              <Panel title="Core">
                <SegmentedControl
                  label="Route"
                  value={settings.core.route_mode}
                  options={[
                    ["smart", "Smart"],
                    ["vpn_only", "VPN Only"],
                  ]}
                  onChange={(value) =>
                    updateSettings({
                      ...settings,
                      core: { ...settings.core, route_mode: value as AppSettings["core"]["route_mode"] },
                      zapret: { ...settings.zapret, enabled: value === "smart" },
                    })
                  }
                  disabled={settingsBusy}
                />
                <p className="diagnosticText">
                  {settings.core.route_mode === "smart"
                    ? "Умный режим для РФ: YouTube, Discord и игры идут напрямую через zapret, AI, соцсети, VPN-правила и остальной внешний трафик идут через выбранные VPN-группы."
                    : "Весь внешний трафик идёт через VPN. zapret выключен. Подходит для простого режима или временного обхода проблем Smart."}
                </p>
                <label className="selectField">
                  <span>Log level</span>
                  <select value={settings.core.log_level} onChange={(event) => updateCore({ log_level: event.currentTarget.value as AppSettings["core"]["log_level"] })} disabled={settingsBusy}>
                    <option value="error">Error</option>
                    <option value="warning">Warning</option>
                    <option value="info">Info</option>
                    <option value="debug">Debug</option>
                  </select>
                </label>
                <ToggleRow label="Allow LAN" checked={settings.core.allow_lan} disabled={settingsBusy} onChange={(checked) => updateCore({ allow_lan: checked })} />
                <ToggleRow label="IPv6" checked={settings.core.ipv6} disabled={settingsBusy} onChange={(checked) => updateCore({ ipv6: checked })} />
              </Panel>
              <Panel title="Ports">
                <NumberField label="Mixed proxy" value={settings.core.mixed_port} disabled={settingsBusy} onChange={(value) => updateCore({ mixed_port: value })} />
                <NumberField label="Controller" value={settings.core.controller_port} disabled={settingsBusy} onChange={(value) => updateCore({ controller_port: value })} />
                <StatusRow label="DNS" value="127.0.0.1:1053" />
                <button className="subtleButton" type="button" onClick={resetSettings} disabled={settingsBusy || busy}>
                  <RefreshCw size={15} aria-hidden="true" />
                  Reset
                </button>
              </Panel>
            </section>
          ) : null}

          {settingsSection === "advanced" ? (
            <section className="settingsPanels">
              <Panel title="TUN">
                <ToggleRow label="Enabled" checked={settings.tun.enabled} disabled={settingsBusy} onChange={(checked) => updateTun({ enabled: checked })} />
                <label className="selectField">
                  <span>Stack</span>
                  <select value={settings.tun.stack} onChange={(event) => updateTun({ stack: event.currentTarget.value as AppSettings["tun"]["stack"] })} disabled={settingsBusy || !settings.tun.enabled}>
                    <option value="mixed">Mixed</option>
                    <option value="gvisor">gVisor</option>
                    <option value="system">System</option>
                  </select>
                </label>
                <ToggleRow label="Strict route" checked={settings.tun.strict_route} disabled={settingsBusy || !settings.tun.enabled} onChange={(checked) => updateTun({ strict_route: checked })} />
                <ToggleRow label="Auto route" checked={settings.tun.auto_route} disabled={settingsBusy || !settings.tun.enabled} onChange={(checked) => updateTun({ auto_route: checked })} />
                <ToggleRow label="Auto interface" checked={settings.tun.auto_detect_interface} disabled={settingsBusy || !settings.tun.enabled} onChange={(checked) => updateTun({ auto_detect_interface: checked })} />
                <NumberField label="MTU" value={settings.tun.mtu} disabled={settingsBusy || !settings.tun.enabled} onChange={(value) => updateTun({ mtu: value })} />
                <TextAreaField label="DNS hijack" value={listToText(settings.tun.dns_hijack)} disabled={settingsBusy || !settings.tun.enabled} onChange={(value) => updateTun({ dns_hijack: textToList(value) })} />
                <TextAreaField label="Excluded routes" value={listToText(settings.tun.excluded_routes)} disabled={settingsBusy || !settings.tun.enabled} onChange={(value) => updateTun({ excluded_routes: textToList(value) })} />
              </Panel>
              <Panel title="DNS">
                <SegmentedControl
                  label="Mode"
                  value={settings.dns.mode}
                  options={[
                    ["fake-ip", "Fake IP"],
                    ["redir-host", "Redir Host"],
                  ]}
                  onChange={(value) => updateDns({ mode: value as AppSettings["dns"]["mode"] })}
                  disabled={settingsBusy}
                />
                <label className="selectField">
                  <span>Preset</span>
                  <select value={settings.dns.preset} onChange={(event) => updateDns({ preset: event.currentTarget.value as AppSettings["dns"]["preset"] })} disabled={settingsBusy}>
                    <option value="cloudflare_google">Cloudflare + Google</option>
                    <option value="cloudflare">Cloudflare</option>
                    <option value="google">Google</option>
                    <option value="quad9">Quad9</option>
                  </select>
                </label>
                <label className="inputField">
                  <span>Fake-IP range</span>
                  <input value={settings.dns.fake_ip_range} disabled={settingsBusy || settings.dns.mode !== "fake-ip"} onChange={(event) => updateDns({ fake_ip_range: event.currentTarget.value })} />
                </label>
                <TextAreaField label="Fake-IP filter" value={listToText(settings.dns.fake_ip_filter)} disabled={settingsBusy || settings.dns.mode !== "fake-ip"} onChange={(value) => updateDns({ fake_ip_filter: textToList(value) })} />
                <TextAreaField
                  label="Nameserver policy"
                  value={nameserverPolicyToText(settings.dns.nameserver_policy)}
                  disabled={settingsBusy}
                  onChange={(value) => updateDns({ nameserver_policy: textToNameserverPolicy(value) })}
                />
                <p className="diagnosticText">Nameserver policy format: one line per rule, `+.example.com = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query`.</p>
              </Panel>
              <Panel title="Sniffer">
                <ToggleRow label="Enabled" checked={settings.sniffer.enabled} disabled={settingsBusy} onChange={(checked) => updateSniffer({ enabled: checked })} />
                <ToggleRow label="HTTP" checked={settings.sniffer.http} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(checked) => updateSniffer({ http: checked })} />
                <ToggleRow label="TLS" checked={settings.sniffer.tls} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(checked) => updateSniffer({ tls: checked })} />
                <ToggleRow label="QUIC" checked={settings.sniffer.quic} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(checked) => updateSniffer({ quic: checked })} />
                <TextAreaField label="Force domains" value={listToText(settings.sniffer.force_domains)} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(value) => updateSniffer({ force_domains: textToList(value) })} />
                <TextAreaField label="Skip domains" value={listToText(settings.sniffer.skip_domains)} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(value) => updateSniffer({ skip_domains: textToList(value) })} />
                <TextAreaField label="Skip source CIDRs" value={listToText(settings.sniffer.skip_src_cidrs)} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(value) => updateSniffer({ skip_src_cidrs: textToList(value) })} />
                <TextAreaField label="Skip destination CIDRs" value={listToText(settings.sniffer.skip_dst_cidrs)} disabled={settingsBusy || !settings.sniffer.enabled} onChange={(value) => updateSniffer({ skip_dst_cidrs: textToList(value) })} />
              </Panel>
            </section>
          ) : null}

          {settingsSection === "advanced" ? (
            <section className="settingsPanels">
              <Panel title="zapret">
                <ToggleRow label="Smart bypass" checked={settings.zapret.enabled} disabled={settingsBusy || settings.core.route_mode === "smart"} onChange={(checked) => updateZapret({ enabled: checked })} />
                <SegmentedControl
                  label="Run"
                  value={settings.zapret.run_mode}
                  options={[
                    ["service", "Service"],
                    ["process", "Process"],
                  ]}
                  onChange={(value) => updateZapret({ run_mode: value as AppSettings["zapret"]["run_mode"] })}
                  disabled={settingsBusy || !settings.zapret.enabled}
                />
                <label className="selectField">
                  <span>Strategy</span>
                  <select value={settings.zapret.strategy} onChange={(event) => updateZapret({ strategy: event.currentTarget.value as AppSettings["zapret"]["strategy"] })} disabled={settingsBusy || !settings.zapret.enabled}>
                    {zapretStrategyOptions.map(([value, label]) => (
                      <option key={value} value={value}>{label}</option>
                    ))}
                  </select>
                </label>
                <SegmentedControl
                  label="Game bypass"
                  value={settings.zapret.game_bypass_mode}
                  options={[
                    ["off", "Off"],
                    ["auto", "Auto detect"],
                    ["manual", "Manual"],
                  ]}
                  onChange={(value) => updateZapret({ game_bypass_mode: value as AppSettings["zapret"]["game_bypass_mode"] })}
                  disabled={settingsBusy || !settings.zapret.enabled}
                />
                <SegmentedControl
                  label="Game mode"
                  value={settings.zapret.game_filter_mode}
                  options={[
                    ["udp_first", "UDP-first"],
                    ["tcp_udp", "TCP+UDP"],
                    ["aggressive", "Aggressive"],
                  ]}
                  onChange={(value) => updateZapret({ game_filter_mode: value as AppSettings["zapret"]["game_filter_mode"] })}
                  disabled={settingsBusy || !settings.zapret.enabled || settings.zapret.game_bypass_mode === "off"}
                />
                <p className="diagnosticText">Auto detect adds PROCESS-NAME DIRECT rules for known games and enables Flowseal UDP-first game filtering only while a game process is active.</p>
                <SegmentedControl
                  label="IPSet"
                  value={settings.zapret.ipset_filter}
                  options={[
                    ["none", "None"],
                    ["any", "Any"],
                    ["loaded", "Loaded"],
                  ]}
                  onChange={(value) => updateZapret({ ipset_filter: value as AppSettings["zapret"]["ipset_filter"] })}
                  disabled={settingsBusy || !settings.zapret.enabled}
                />
                <ToggleRow label="Profile fallback" checked={settings.zapret.auto_profile_fallback} disabled={settingsBusy || !settings.zapret.enabled} onChange={(checked) => updateZapret({ auto_profile_fallback: checked })} />
                <ToggleRow label="VPN fallback" checked={settings.zapret.fallback_to_vpn_on_failed_probe} disabled={settingsBusy || !settings.zapret.enabled} onChange={(checked) => updateZapret({ fallback_to_vpn_on_failed_probe: checked })} />
              </Panel>
              <Panel title="Smart policy">
                <ToggleRow label="YouTube + Discord via zapret" checked={settings.routing_policy.smart_presets.youtube_discord_zapret} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ youtube_discord_zapret: checked })} />
                <ToggleRow label="Games via zapret" checked={settings.routing_policy.smart_presets.games_zapret} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ games_zapret: checked })} />
                <ToggleRow label="AI via VPN" checked={settings.routing_policy.smart_presets.ai_vpn} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ ai_vpn: checked })} />
                <ToggleRow label="Social via VPN" checked={settings.routing_policy.smart_presets.social_vpn} disabled={settingsBusy || settings.core.route_mode !== "smart"} onChange={(checked) => updateSmartPresets({ social_vpn: checked })} />
                <SegmentedControl
                  label="Coverage"
                  value={settings.routing_policy.coverage}
                  options={[
                    ["curated", "Curated"],
                    ["broad", "Broad (Experimental)"],
                  ]}
                  onChange={(value) => updateRoutingPolicy({ coverage: value as AppSettings["routing_policy"]["coverage"] })}
                  disabled={settingsBusy || settings.core.route_mode !== "smart"}
                />
              </Panel>
              <Panel title="Overrides">
                <div className="overrideComposer">
                  <p className="diagnosticText">
                    Local overrides are stored in BadVpn settings and are applied after each subscription refresh. Executable paths are normalized to process names because Mihomo enforces `PROCESS-NAME`.
                  </p>
                  <ToggleRow
                    label="Enable local overrides"
                    checked={settings.routing_policy.local_overrides_enabled}
                    disabled={settingsBusy}
                    onChange={(checked) => updateRoutingPolicy({ local_overrides_enabled: checked })}
                  />
                  {!settings.routing_policy.local_overrides_enabled ? (
                    <div className="inlineNotice warning">
                      Local rules stay saved but are ignored until this switch is enabled again.
                    </div>
                  ) : null}
                  <div className="overrideGrid">
                    <label className="selectField">
                      <span>Route</span>
                      <select
                        value={localOverrideRoute}
                        disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                        onChange={(event) => {
                          const nextRoute = event.currentTarget.value as LocalOverrideRoute;
                          setLocalOverrideRoute(nextRoute);
                          const nextKinds = localOverrideTargetKindsForRoute(nextRoute);
                          if (!nextKinds.includes(localOverrideKind)) {
                            setLocalOverrideKind(nextKinds[0]);
                          }
                        }}
                      >
                        <option value="direct">DIRECT</option>
                        <option value="zapret">zapret</option>
                        <option value="vpn">VPN</option>
                      </select>
                    </label>
                    <label className="selectField">
                      <span>Target</span>
                      <select
                        value={localOverrideKind}
                        disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                        onChange={(event) => setLocalOverrideKind(event.currentTarget.value as LocalOverrideTargetKind)}
                      >
                        {localOverrideKinds.map((kind) => (
                          <option key={kind} value={kind}>{formatLocalOverrideKind(kind)}</option>
                        ))}
                      </select>
                    </label>
                    <label className="inputField overrideValueField">
                      <span>{formatLocalOverrideKind(localOverrideKind)}</span>
                      <input
                        type="text"
                        value={localOverrideValue}
                        disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || !localOverrideAllowed}
                        placeholder={localOverridePlaceholder(localOverrideKind)}
                        spellCheck={false}
                        onChange={(event) => setLocalOverrideValue(event.currentTarget.value)}
                      />
                    </label>
                    <button
                      className="subtleButton"
                      type="button"
                      onClick={pickExecutable}
                      disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                      title="Pick a Windows executable"
                    >
                      <Upload size={15} aria-hidden="true" />
                      .exe
                    </button>
                    <button
                      className="primarySmall"
                      type="button"
                      onClick={addLocalOverride}
                      disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || !localOverridePreview.normalized || !localOverrideAllowed || localOverrideDuplicate}
                    >
                      {localOverrideDuplicate ? "Exists" : "Add"}
                    </button>
                  </div>
                  {localOverridePreview.normalized ? (
                    <div className={localOverrideDuplicate ? "overridePreview duplicate" : "overridePreview"}>
                      <span>Preview</span>
                      <code>{localOverridePreview.preview}</code>
                      {localOverrideDuplicate ? <strong>Already saved</strong> : null}
                    </div>
                  ) : null}
                  {localOverrideKind === "process" ? (
                    <div className="inlineNotice">
                      Paste `C:\Games\App\Game.exe` or `Game.exe`; BadVpn stores `Game.exe` so refreshes from the provider cannot overwrite the rule.
                    </div>
                  ) : null}
                  <div className="overrideSummary">
                    <span>VPN {settings.routing_policy.force_vpn_domains.length + settings.routing_policy.force_vpn_cidrs.length}</span>
                    <span>
                      zapret{" "}
                      {settings.routing_policy.force_zapret_domains.length +
                        settings.routing_policy.force_zapret_cidrs.length +
                        settings.routing_policy.force_zapret_processes.length +
                        settings.routing_policy.force_zapret_tcp_ports.length +
                        settings.routing_policy.force_zapret_udp_ports.length}
                    </span>
                    <span>
                      DIRECT{" "}
                      {settings.routing_policy.force_direct_domains.length +
                        settings.routing_policy.force_direct_cidrs.length +
                        settings.routing_policy.force_direct_processes.length}
                    </span>
                  </div>
                  <div className="overrideList">
                    {localOverrideSummaryItems(settings.routing_policy).map((item) => {
                      const conflict = localOverrideConflictLabel(item, policySummary);
                      return (
                        <div key={item.id ?? `${item.route}-${item.kind}-${item.value}`} className={conflict ? `overrideRule ${item.route} conflict` : `overrideRule ${item.route}`}>
                          <label>
                            <input
                              type="checkbox"
                              checked={item.enabled ?? true}
                              disabled={settingsBusy || !item.id}
                              onChange={(event) => item.id ? toggleLocalOverrideRule(item.id, event.currentTarget.checked) : null}
                            />
                            <span>{item.route.toUpperCase()} / {item.kind}: {item.value}</span>
                          </label>
                          {conflict ? <em>{conflict}</em> : null}
                          {item.id ? (
                            <button className="iconSmall" type="button" onClick={() => deleteLocalOverrideRule(item.id!)} disabled={settingsBusy} title="Remove local override">
                              <X size={13} aria-hidden="true" />
                            </button>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                </div>
                <TextAreaField
                  label="Force VPN"
                  value={listToText(settings.routing_policy.force_vpn_domains)}
                  disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                  onChange={(value) => updateRoutingPolicy({ force_vpn_domains: textToList(value) })}
                />
                <TextAreaField
                  label="Force Zapret"
                  value={listToText(settings.routing_policy.force_zapret_domains)}
                  disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || settings.core.route_mode !== "smart"}
                  onChange={(value) => updateRoutingPolicy({ force_zapret_domains: textToList(value) })}
                />
                <TextAreaField
                  label="Force DIRECT"
                  value={listToText(settings.routing_policy.force_direct_domains)}
                  disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                  onChange={(value) => updateRoutingPolicy({ force_direct_domains: textToList(value) })}
                />
                <div className="advancedOverrideGrid">
                  <TextAreaField
                    label="Force VPN CIDRs"
                    value={listToText(settings.routing_policy.force_vpn_cidrs)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                    onChange={(value) => updateRoutingPolicy({ force_vpn_cidrs: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force Zapret CIDRs"
                    value={listToText(settings.routing_policy.force_zapret_cidrs)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || settings.core.route_mode !== "smart"}
                    onChange={(value) => updateRoutingPolicy({ force_zapret_cidrs: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force Zapret processes"
                    value={listToText(settings.routing_policy.force_zapret_processes)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || settings.core.route_mode !== "smart"}
                    onChange={(value) => updateRoutingPolicy({ force_zapret_processes: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force Zapret TCP ports"
                    value={listToText(settings.routing_policy.force_zapret_tcp_ports)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || settings.core.route_mode !== "smart"}
                    onChange={(value) => updateRoutingPolicy({ force_zapret_tcp_ports: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force Zapret UDP ports"
                    value={listToText(settings.routing_policy.force_zapret_udp_ports)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled || settings.core.route_mode !== "smart"}
                    onChange={(value) => updateRoutingPolicy({ force_zapret_udp_ports: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force DIRECT CIDRs"
                    value={listToText(settings.routing_policy.force_direct_cidrs)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                    onChange={(value) => updateRoutingPolicy({ force_direct_cidrs: textToList(value) })}
                  />
                  <TextAreaField
                    label="Force DIRECT processes"
                    value={listToText(settings.routing_policy.force_direct_processes)}
                    disabled={settingsBusy || !settings.routing_policy.local_overrides_enabled}
                    onChange={(value) => updateRoutingPolicy({ force_direct_processes: textToList(value) })}
                  />
                </div>
              </Panel>
              <Panel title="Legacy zapret service">
                <StatusRow label="Name" value={zapretService?.service_name ?? "BadVpnZapret"} />
                <StatusRow label="Status" value={zapretService?.message ?? "Not checked"} good={zapretService ? !zapretService.installed : false} />
                <StatusRow label="Mode" value="Replaced by badvpn-agent" good />
                <div className="buttonRow">
                  <button className="subtleButton" type="button" onClick={refreshZapretService} disabled={zapretServiceBusy}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh
                  </button>
                </div>
                <p className="diagnosticText">Service-first runtime starts winws inside badvpn-agent. This legacy service is detect-only in the UI and should normally stay removed.</p>
              </Panel>
              <Panel title="Routing">
                <StatusRow label="VPN" value="MATCH -> PROXY" good={hasSubscription} />
                <StatusRow label="zapret" value={state.diagnostics.zapret_healthy ? "Running" : "Standby"} good={state.diagnostics.zapret_healthy} />
                <StatusRow label="Mode" value={formatRouteMode(settings.core.route_mode)} />
                <StatusRow label="Log" value="%APPDATA%\\BadVpn\\logs\\badvpn.log" />
              </Panel>
            </section>
          ) : null}

          {settingsSection === "operator"
            ? renderOperatorTools({
                snapshot: operatorSnapshot,
                busy: operatorBusy,
                logPaused: operatorLogPaused,
                setLogPaused: setOperatorLogPaused,
                logAutoScroll: operatorLogAutoScroll,
                setLogAutoScroll: setOperatorLogAutoScroll,
                logViewCleared: operatorLogViewCleared,
                clearLogView: clearOperatorLogView,
                logSourceFilter: operatorLogSourceFilter,
                setLogSourceFilter: setOperatorLogSourceFilter,
                logLevelFilter: operatorLogLevelFilter,
                setLogLevelFilter: setOperatorLogLevelFilter,
                customDomain: operatorCustomDomain,
                setCustomDomain: setOperatorCustomDomain,
                healthHistory: operatorHealthHistory,
                profileName: operatorProfileName,
                setProfileName: setOperatorProfileName,
                profilePath: operatorProfilePath,
                setProfilePath: setOperatorProfilePath,
                profileText: operatorProfileText,
                setProfileText: setOperatorProfileText,
                profilePreview: operatorProfilePreview,
                deepLink: operatorDeepLink,
                setDeepLink: setOperatorDeepLink,
                backupPath: operatorBackupPath,
                setBackupPath: setOperatorBackupPath,
                manualGameProfile,
                setManualGameProfile,
                learnedGameProfileIds: settings.zapret.learned_game_profiles.map((profile) => profile.id),
                toggleGameProfile: toggleLearnedGameProfile,
                refresh: refreshOperatorSnapshot,
                pickExecutable,
                runZapretChecks,
                repairWindowsNetwork,
                updateResource,
                updateAllResources,
                rollbackResource,
                previewLocalProfile,
                importLocalProfile,
                refreshAllProfiles,
                refreshDueProfiles,
                droppedProfile,
                addManualGameProfile,
                backupAction,
                openDirectory,
                copyText,
              })
            : null}

          {settingsSection === "updates" ? (
            <section className="settingsPanels">
              <Panel title="Subscription">
                {hasSubscription ? (
                  <>
                    <StatusRow label="Active" value={state.subscription.profile_title ?? "Subscription"} good />
                    <StatusRow label="Nodes" value={String(state.subscription.node_count)} good />
                    <StatusRow label="Format" value={formatRouteMode(state.subscription.format)} />
                    <StatusRow label="Refresh" value={formatRefreshInterval(state.subscription.update_interval_hours)} />
                    {providerLinks.length > 0 ? (
                      <div className="providerLinkList">
                        {providerLinks.map((link) => (
                          <a key={`${link.label}-${link.href}`} href={link.href} target="_blank" rel="noreferrer">
                            <ExternalLink size={13} aria-hidden="true" />
                            <span>{link.label}</span>
                            <small>{formatExternalLinkHost(link.href)}</small>
                          </a>
                        ))}
                      </div>
                    ) : null}
                  </>
                ) : (
                  <p className="diagnosticText">No subscription imported.</p>
                )}
                <div className="profileAddRow">
                  <input
                    value={profileUrl}
                    onChange={(event) => setProfileUrl(event.currentTarget.value)}
                    placeholder="https://global.badvpn.pro/sub/..."
                    spellCheck={false}
                    disabled={profilesBusy}
                  />
                  <button className="primarySmall" type="button" onClick={addSubscriptionProfile} disabled={profilesBusy || !profileUrl.trim()}>
                    Add
                  </button>
                </div>
                <div className="buttonRow">
                  <button className="subtleButton" type="button" onClick={refreshSubscription} disabled={busy || profilesBusy || !hasSubscription}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh active
                  </button>
                  <button className="subtleButton" type="button" onClick={refreshDueProfiles} disabled={busy || profilesBusy}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh due
                  </button>
                </div>
                <div className="profileList">
                  {subscriptionProfiles.profiles.length ? (
                    subscriptionProfiles.profiles.map((profile) => (
                      <div key={profile.id} className={profile.active ? "profileRow active" : "profileRow"}>
                        <div>
                          <strong>{profile.name}</strong>
                          {profile.description ? <em>{profile.description}</em> : null}
                          <span>{profile.redacted_url ?? formatRouteMode(profile.subscription.format)}</span>
                          {profile.last_refresh_error ? (
                            <em className="profileRefreshError">
                              Last refresh failed: {subscriptionFailureCopy(profile.last_refresh_error)}
                            </em>
                          ) : (
                            <em>{formatProfileRefreshStatus(profile)}</em>
                          )}
                          <em>{formatProfileFetchOptions(profile)}</em>
                          <div className="profileFetchControls">
                            <select
                              value={profile.fetch_options.proxy_mode}
                              onChange={(event) => updateProfileFetchProxyMode(profile, event.currentTarget.value as SubscriptionFetchProxyMode)}
                              disabled={profilesBusy}
                            >
                              <option value="system">System proxy</option>
                              <option value="direct">Direct</option>
                              <option value="custom">Custom proxy</option>
                            </select>
                            <button className="textAction" type="button" onClick={() => updateProfileFetchTimeout(profile)} disabled={profilesBusy}>
                              {profile.fetch_options.timeout_seconds}s
                            </button>
                            <button className="textAction" type="button" onClick={() => updateProfileFetchUserAgent(profile)} disabled={profilesBusy}>
                              UA
                            </button>
                          </div>
                        </div>
                        <span>{profile.subscription.node_count} nodes</span>
                        <button className="subtleButton" type="button" onClick={() => selectSubscriptionProfile(profile.id)} disabled={profilesBusy || profile.active}>
                          {profile.active ? "Active" : "Select"}
                        </button>
                        <button className="subtleButton" type="button" onClick={() => updateProfileNotes(profile)} disabled={profilesBusy}>
                          Notes
                        </button>
                        <button className="subtleButton danger" type="button" onClick={() => removeSubscriptionProfile(profile.id)} disabled={profilesBusy}>
                          <X size={14} aria-hidden="true" />
                        </button>
                      </div>
                    ))
                  ) : (
                    <p className="diagnosticText">Profiles will appear here after adding subscription links.</p>
                  )}
                </div>
              </Panel>
              <Panel title="Updates">
                <ToggleRow label="Flowseal lists" checked={settings.updates.auto_flowseal_list_refresh} disabled={settingsBusy} onChange={(checked) => updateUpdates({ auto_flowseal_list_refresh: checked })} />
                <NumberField
                  label="Safe resource interval, h"
                  value={settings.updates.safe_resource_auto_update_interval_hours}
                  min={1}
                  max={168}
                  disabled={settingsBusy || !settings.updates.auto_flowseal_list_refresh}
                  onChange={(value) => updateUpdates({ safe_resource_auto_update_interval_hours: Math.min(Math.max(value, 1), 168) })}
                />
                <StatusRow label="App" value={formatAppUpdateStatus(appUpdate)} />
                {componentUpdates.slice(0, 3).map((component) => (
                  <StatusRow key={component.name} label={component.name} value={formatComponentUpdate(component)} />
                ))}
                <div className="buttonRow">
                  <button className="subtleButton" type="button" onClick={checkUpdates} disabled={updateBusy}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Check
                  </button>
                  <button className="subtleButton" type="button" onClick={updateRuntime} disabled={updateBusy || busy}>
                    <Download size={15} aria-hidden="true" />
                    Runtime
                  </button>
                  {appUpdate.state === "available" ? (
                    <button className="primarySmall" type="button" onClick={installUpdate} disabled={updateBusy}>
                      Install
                    </button>
                  ) : null}
                </div>
              </Panel>
              <Panel title="BadVpn agent">
                <StatusRow label="Service" value={agentService?.service_name ?? "badvpn-agent"} />
                <StatusRow label="Status" value={agentService?.message ?? "Not checked"} good={(agentService?.running ?? false) && (agentService?.ipc_ready ?? false)} />
                <StatusRow label="IPC" value={agentService?.ipc_ready ? "Ready" : "Not reachable"} good={agentService?.ipc_ready ?? false} />
                <div className="buttonRow">
                  <button className="subtleButton" type="button" onClick={refreshAgentService} disabled={agentServiceBusy}>
                    <RefreshCw size={15} aria-hidden="true" />
                    Refresh
                  </button>
                  <button className="primarySmall" type="button" onClick={installAgentService} disabled={agentServiceBusy || busy}>
                    Install / Repair
                  </button>
                  <button className="subtleButton danger" type="button" onClick={removeAgentService} disabled={agentServiceBusy || busy}>
                    <X size={15} aria-hidden="true" />
                    Remove
                  </button>
                </div>
                <p className="diagnosticText">This service owns Mihomo, winws, WinDivert, runtime configs, and component writes. The GUI should stay non-admin.</p>
              </Panel>
              <Panel title="Diagnostics">
                <ToggleRow label="After connect" checked={settings.diagnostics.runtime_checks_after_connect} disabled={settingsBusy} onChange={(checked) => updateDiagnostics({ runtime_checks_after_connect: checked })} />
                <ToggleRow label="Discord/YouTube probes" checked={settings.diagnostics.discord_youtube_probes} disabled={settingsBusy} onChange={(checked) => updateDiagnostics({ discord_youtube_probes: checked })} />
                <StatusRow label="Mihomo" value={state.diagnostics.mihomo_healthy ? "Healthy" : "Needs check"} good={state.diagnostics.mihomo_healthy} />
                <StatusRow label="zapret" value={state.diagnostics.zapret_healthy ? "Healthy" : "Needs check"} good={state.diagnostics.zapret_healthy} />
                <button className="subtleButton" type="button" onClick={runDiagnostics} disabled={diagnosticBusy}>
                  <Activity size={15} aria-hidden="true" />
                  Run checks
                </button>
                <button
                  className="subtleButton"
                  type="button"
                  onClick={() =>
                    copyText(
                      "Support summary",
                      buildSupportSummary({
                        state,
                        settings,
                        runtimeReadiness,
                        runtimeDiagnostics,
                        componentUpdates,
                        policySummary,
                      }),
                    )
                  }
                >
                  <Copy size={15} aria-hidden="true" />
                  Copy summary
                </button>
                {runtimeDiagnostics ? (
                  <div className="diagnosticList">
                    {runtimeDiagnostics.checks.map((check) => (
                      <div key={check.id} className={`diagnosticItem ${check.status}`}>
                        <strong>{check.label}</strong>
                        <span>{check.message}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="diagnosticText">{state.diagnostics.message ?? "No diagnostics yet."}</p>
                )}
              </Panel>
            </section>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function SettingsTab({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button className={active ? "settingsTab active" : "settingsTab"} type="button" onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
  );
}

function renderOperatorTools({
  snapshot,
  busy,
  logPaused,
  setLogPaused,
  logAutoScroll,
  setLogAutoScroll,
  logViewCleared,
  clearLogView,
  logSourceFilter,
  setLogSourceFilter,
  logLevelFilter,
  setLogLevelFilter,
  customDomain,
  setCustomDomain,
  healthHistory,
  profileName,
  setProfileName,
  profilePath,
  setProfilePath,
  profileText,
  setProfileText,
  profilePreview,
  deepLink,
  setDeepLink,
  backupPath,
  setBackupPath,
  manualGameProfile,
  setManualGameProfile,
  learnedGameProfileIds,
  toggleGameProfile,
  refresh,
  pickExecutable,
  runZapretChecks,
  repairWindowsNetwork,
  updateResource,
  updateAllResources,
  rollbackResource,
  previewLocalProfile,
  importLocalProfile,
  refreshAllProfiles,
  refreshDueProfiles,
  droppedProfile,
  addManualGameProfile,
  backupAction,
  openDirectory,
  copyText,
}: {
  snapshot: OperatorSnapshot | null;
  busy: boolean;
  logPaused: boolean;
  setLogPaused: (paused: boolean) => void;
  logAutoScroll: boolean;
  setLogAutoScroll: (enabled: boolean) => void;
  logViewCleared: boolean;
  clearLogView: () => void;
  logSourceFilter: string;
  setLogSourceFilter: (source: string) => void;
  logLevelFilter: string;
  setLogLevelFilter: (level: string) => void;
  customDomain: string;
  setCustomDomain: (value: string) => void;
  healthHistory: ZapretHealthReport[];
  profileName: string;
  setProfileName: (value: string) => void;
  profilePath: string;
  setProfilePath: (value: string) => void;
  profileText: string;
  setProfileText: (value: string) => void;
  profilePreview: LocalProfilePreview | null;
  deepLink: string;
  setDeepLink: (value: string) => void;
  backupPath: string;
  setBackupPath: (value: string) => void;
  manualGameProfile: {
    title: string;
    executable: string;
    domains: string;
    cidrs: string;
    tcpPorts: string;
    udpPorts: string;
  };
  setManualGameProfile: (value: {
    title: string;
    executable: string;
    domains: string;
    cidrs: string;
    tcpPorts: string;
    udpPorts: string;
  }) => void;
  learnedGameProfileIds: string[];
  toggleGameProfile: (id: string, enabled: boolean) => void;
  refresh: () => void;
  pickExecutable: () => void;
  runZapretChecks: () => void;
  repairWindowsNetwork: () => void;
  updateResource: (id: string) => void;
  updateAllResources: () => void;
  rollbackResource: (id: string) => void;
  previewLocalProfile: (mode: "path" | "text") => void;
  importLocalProfile: (mode: "path" | "text" | "link") => void;
  refreshAllProfiles: () => void;
  refreshDueProfiles: () => void;
  droppedProfile: (file: File) => void;
  addManualGameProfile: () => void;
  backupAction: (action: "export" | "support" | "restore") => void;
  openDirectory: (kind: "app_data" | "runtime" | "logs" | "backups") => void;
  copyText: (label: string, text: string) => void;
}) {
  const logSources = snapshot?.logs.sources ?? [];
  const logLines = logSources
    .filter((source) => logSourceFilter === "all" || source.id === logSourceFilter)
    .flatMap((source) => source.lines)
    .filter((line) => logLevelFilter === "all" || line.level === logLevelFilter);
  const visibleLogLines = logViewCleared ? [] : logLines;
  const resources = snapshot?.resources.resources ?? [];
  const providerCount = (snapshot?.providers.rule_providers.length ?? 0) + (snapshot?.providers.proxy_providers.length ?? 0);
  const learnedGameProfiles = new Set(learnedGameProfileIds);

  return (
    <section className="settingsPanels operatorPanels">
      <Panel title="Operator snapshot">
        <StatusRow label="Generated" value={snapshot ? formatTimestamp(snapshot.generated_at) : "Not loaded"} good={Boolean(snapshot)} />
        <StatusRow label="Providers" value={String(providerCount)} />
        <StatusRow label="Resources" value={String(resources.length)} />
        <div className="buttonRow">
          <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </button>
          <button className="subtleButton" type="button" onClick={() => openDirectory("app_data")}>
            <ExternalLink size={15} aria-hidden="true" />
            App data
          </button>
          <button className="subtleButton" type="button" onClick={() => openDirectory("logs")}>
            <ExternalLink size={15} aria-hidden="true" />
            Logs
          </button>
          <button className="subtleButton" type="button" onClick={() => openDirectory("runtime")}>
            <ExternalLink size={15} aria-hidden="true" />
            Runtime
          </button>
        </div>
      </Panel>

      <Panel title="Zapret health">
        <div className="profileAddRow">
          <input value={customDomain} placeholder="custom.example.com" onChange={(event) => setCustomDomain(event.currentTarget.value)} />
          <button className="primarySmall" type="button" onClick={runZapretChecks} disabled={busy}>
            <Activity size={15} aria-hidden="true" />
            Run checks
          </button>
          <button className="subtleButton" type="button" onClick={repairWindowsNetwork} disabled={busy}>
            <Router size={15} aria-hidden="true" />
            Repair network
          </button>
        </div>
        <div className="diagnosticList">
          {(snapshot?.health.checks ?? []).map((check) => (
            <div key={`${check.id}-${check.domain}`} className={`diagnosticItem ${check.status === "ok" ? "ok" : check.status === "idle" ? "warning" : check.status}`}>
              <strong>{check.label}</strong>
              <span>{check.domain} | route={check.route_path} | dns={check.dns_result} | probe={check.probe_result} | list={check.zapret_list}</span>
              <em>{check.recovery_action}</em>
            </div>
          ))}
        </div>
        {healthHistory.length ? (
          <div className="backupList">
            <strong>Recent checks</strong>
            {healthHistory.map((report) => (
              <span key={report.checked_at}>
                {formatTimestamp(report.checked_at)} | {report.checks.filter((check) => check.status === "ok").length}/{report.checks.length} ok
              </span>
            ))}
          </div>
        ) : null}
      </Panel>

      <Panel title="Rules and providers">
        <StatusRow label="Status" value={snapshot?.providers.update_status ?? "Not loaded"} />
        <StatusRow label="Editing" value={snapshot?.providers.provider_editing ?? "Read-only"} good />
        <div className="providerGrid">
          {[...(snapshot?.providers.rule_providers ?? []), ...(snapshot?.providers.proxy_providers ?? [])].map((provider) => (
            <div key={`${provider.name}-${provider.behavior}`} className={provider.consumed_by_bpn ? "providerItem active" : "providerItem"}>
              <strong>{provider.name}</strong>
              <span>{provider.provider_type} / {provider.behavior}</span>
              <span>{provider.url_redacted ?? provider.path ?? "local"}</span>
              <em>{provider.consumed_by_bpn ? "BPN overlay source" : "provider source"}</em>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Resources">
        <div className="buttonRow">
          <button className="subtleButton" type="button" onClick={updateAllResources} disabled={busy}>
            <Download size={15} aria-hidden="true" />
            Update safe lists
          </button>
        </div>
        <div className="resourceList">
          {resources.map((resource) => (
            <div key={resource.id} className={resource.installed ? "resourceItem ok" : "resourceItem warning"}>
              <div>
                <strong>{resource.label}</strong>
                <span>{resource.kind} | {resource.version ?? "missing"}</span>
                <code>{resource.path}</code>
                <em>{resource.verification_status}</em>
              </div>
              <div className="resourceActions">
                <button className="subtleButton" type="button" onClick={() => updateResource(resource.id)} disabled={busy || !resource.update_supported}>
                  Update
                </button>
                <button className="subtleButton" type="button" onClick={() => rollbackResource(resource.id)} disabled={busy || !resource.rollback_available}>
                  Rollback
                </button>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Live logs">
        <div className="policyToolbar compactToolbar">
          <label className="selectField">
            <span>Source</span>
            <select value={logSourceFilter} onChange={(event) => setLogSourceFilter(event.currentTarget.value)}>
              <option value="all">All sources</option>
              {logSources.map((source) => <option key={source.id} value={source.id}>{source.label}</option>)}
            </select>
          </label>
          <label className="selectField">
            <span>Level</span>
            <select value={logLevelFilter} onChange={(event) => setLogLevelFilter(event.currentTarget.value)}>
              <option value="all">All levels</option>
              <option value="error">Error</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
          </label>
          <ToggleRow label="Pause" checked={logPaused} onChange={setLogPaused} />
          <ToggleRow label="Auto-scroll" checked={logAutoScroll} onChange={setLogAutoScroll} />
          <button className="subtleButton" type="button" onClick={clearLogView} disabled={!visibleLogLines.length}>
            Clear view
          </button>
          <button className="subtleButton" type="button" onClick={() => copyText("Redacted logs", visibleLogLines.map((line) => line.text).join("\n"))} disabled={!visibleLogLines.length}>
            <Copy size={15} aria-hidden="true" />
            Copy
          </button>
        </div>
        <pre id="operator-log-viewer" className="logViewer">{visibleLogLines.length ? visibleLogLines.map((line) => `[${line.source}:${line.level}] ${line.text}`).join("\n") : "No redacted log lines loaded."}</pre>
      </Panel>

      <Panel title="Runtime config">
        <div className="runtimeConfigGrid">
          {[snapshot?.config.source_profile, snapshot?.config.runtime_yaml, snapshot?.config.diff].filter(Boolean).map((artifact) => (
            <div key={artifact!.label} className="runtimeArtifact">
              <div className="artifactHeader">
                <strong>{artifact!.label}</strong>
                <button className="iconSmall" type="button" onClick={() => copyText(artifact!.label, artifact!.text)} title="Copy redacted text">
                  <Copy size={13} aria-hidden="true" />
                </button>
              </div>
              <span>{artifact!.line_count} lines | read-only | redacted</span>
              {artifact!.error ? <em>{artifact!.error}</em> : null}
              {artifact!.label.includes("diff") ? (
                <pre>{renderRuntimeDiffLines(artifact!.text)}</pre>
              ) : (
                <pre>{artifact!.text || "No content."}</pre>
              )}
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Game and app bypass">
        <StatusRow label="Known" value={String(snapshot?.game_profiles.known.length ?? 0)} />
        <StatusRow label="Detected" value={String(snapshot?.game_profiles.detected.length ?? 0)} />
        <StatusRow label="Learned" value={String(snapshot?.game_profiles.learned.length ?? 0)} />
        <div className="gameProfileList">
          {[...(snapshot?.game_profiles.detected ?? []), ...(snapshot?.game_profiles.known ?? []), ...(snapshot?.game_profiles.learned ?? [])].slice(0, 10).map((profile) => (
            <div key={`${profile.id}-${profile.detected}`} className={profile.detected ? "gameProfile detected" : "gameProfile"}>
              <strong>{profile.title}</strong>
              <span>{profile.process_names.join(", ") || "No process"} | {profile.filter_mode} | risk={profile.risk_level} | {profile.enabled === false ? "disabled" : "enabled"}</span>
              <em>{[...profile.domains, ...profile.cidrs, ...profile.tcp_ports, ...profile.udp_ports].slice(0, 6).join(", ") || "Process-only route"}</em>
              {learnedGameProfiles.has(profile.id) ? (
                <ToggleRow label="Enabled" checked={profile.enabled !== false} onChange={(checked) => toggleGameProfile(profile.id, checked)} />
              ) : null}
            </div>
          ))}
        </div>
        <div className="profileAddRow">
          <input value={manualGameProfile.title} placeholder="Profile name" onChange={(event) => setManualGameProfile({ ...manualGameProfile, title: event.currentTarget.value })} />
          <input value={manualGameProfile.executable} placeholder="C:\\Games\\Game.exe" onChange={(event) => setManualGameProfile({ ...manualGameProfile, executable: event.currentTarget.value })} />
          <button className="subtleButton" type="button" onClick={pickExecutable}>
            <Upload size={15} aria-hidden="true" />
            .exe
          </button>
        </div>
        <div className="advancedOverrideGrid">
          <TextAreaField label="Domains" value={manualGameProfile.domains} onChange={(value) => setManualGameProfile({ ...manualGameProfile, domains: value })} />
          <TextAreaField label="CIDRs" value={manualGameProfile.cidrs} onChange={(value) => setManualGameProfile({ ...manualGameProfile, cidrs: value })} />
          <TextAreaField label="TCP ports" value={manualGameProfile.tcpPorts} onChange={(value) => setManualGameProfile({ ...manualGameProfile, tcpPorts: value })} />
          <TextAreaField label="UDP ports" value={manualGameProfile.udpPorts} onChange={(value) => setManualGameProfile({ ...manualGameProfile, udpPorts: value })} />
        </div>
        <button className="primarySmall" type="button" onClick={addManualGameProfile} disabled={busy || !manualGameProfile.executable.trim()}>
          <Plus size={15} aria-hidden="true" />
          Save manual profile
        </button>
      </Panel>

      <Panel title="Profile import">
        <div
          className="dropZone"
          onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => {
            event.preventDefault();
            const file = event.dataTransfer.files.item(0);
            if (file) droppedProfile(file);
          }}
        >
          Drop YAML, JSON, or TXT profile here
        </div>
        <div className="profileAddRow">
          <input value={profileName} placeholder="Display name" onChange={(event) => setProfileName(event.currentTarget.value)} />
          <input value={profilePath} placeholder="C:\\path\\profile.yaml" onChange={(event) => setProfilePath(event.currentTarget.value)} />
          <button className="subtleButton" type="button" onClick={() => previewLocalProfile("path")} disabled={busy || !profilePath.trim()}>
            Preview path
          </button>
          <button className="subtleButton" type="button" onClick={() => importLocalProfile("path")} disabled={busy || !profilePath.trim()}>
            Import path
          </button>
        </div>
        <TextAreaField label="Profile body" value={profileText} onChange={setProfileText} />
        <div className="buttonRow">
          <button className="subtleButton" type="button" onClick={() => previewLocalProfile("text")} disabled={busy || !profileText.trim()}>
            Preview text
          </button>
          <button className="subtleButton" type="button" onClick={() => importLocalProfile("text")} disabled={busy || !profileText.trim()}>
            Import text
          </button>
        </div>
        {profilePreview ? (
          <div className={profilePreview.import_ready ? "profilePreview" : "profilePreview warning"}>
            <strong>{profilePreview.display_name}</strong>
            <span>
              {formatRouteMode(profilePreview.format)} · {profilePreview.node_count} node(s) · {formatBytes(profilePreview.decoded_size_bytes)}
            </span>
            {profilePreview.source_file_name ? <small>{profilePreview.source_file_name}</small> : null}
            {profilePreview.warning ? <em>{profilePreview.warning}</em> : null}
          </div>
        ) : null}
        <div className="profileAddRow">
          <input value={deepLink} placeholder="bpn://import?url=..." onChange={(event) => setDeepLink(event.currentTarget.value)} />
          <button className="subtleButton" type="button" onClick={() => importLocalProfile("link")} disabled={busy || !deepLink.trim()}>
            Import link
          </button>
          <button className="subtleButton" type="button" onClick={refreshAllProfiles} disabled={busy}>
            Refresh all
          </button>
          <button className="subtleButton" type="button" onClick={refreshDueProfiles} disabled={busy}>
            Refresh due
          </button>
        </div>
      </Panel>

      <Panel title="Backup and support">
        <div className="bundleCategories">
          <span>Backup: settings, selected proxies, local overrides, game profiles, profile metadata</span>
          <span>Support: redacted logs, policy/runtime summary, resources, health checks, directories</span>
        </div>
        <div className="buttonRow">
          <button className="subtleButton" type="button" onClick={() => backupAction("export")} disabled={busy}>
            <Download size={15} aria-hidden="true" />
            Backup
          </button>
          <button className="subtleButton" type="button" onClick={() => backupAction("support")} disabled={busy}>
            <LifeBuoy size={15} aria-hidden="true" />
            Support bundle
          </button>
          <button className="subtleButton" type="button" onClick={() => openDirectory("backups")}>
            <ExternalLink size={15} aria-hidden="true" />
            Backup dir
          </button>
        </div>
        <div className="profileAddRow">
          <input value={backupPath} placeholder="C:\\path\\badvpn-backup.json" onChange={(event) => setBackupPath(event.currentTarget.value)} />
          <button className="subtleButton" type="button" onClick={() => backupAction("restore")} disabled={busy || !backupPath.trim()}>
            Restore
          </button>
        </div>
        <div className="backupList">
          {renderBackupFiles("Backups", snapshot?.backups.backups ?? [])}
          {renderBackupFiles("Support bundles", snapshot?.backups.support_bundles ?? [])}
        </div>
      </Panel>
    </section>
  );
}

function renderBackupFiles(title: string, files: BackupHistory["backups"]) {
  return (
    <div className="backupGroup">
      <strong>{title}</strong>
      {files.length ? files.slice(0, 5).map((file) => (
        <span key={file.path}>{file.name} {file.modified_at ? formatTimestamp(file.modified_at) : ""}</span>
      )) : <span>None</span>}
    </div>
  );
}

function renderRuntimeDiffLines(text: string) {
  if (!text.trim()) {
    return "No content.";
  }
  return text.split("\n").map((line, index) => {
    const className = line.startsWith("+ ")
      ? "diffLine added"
      : line.startsWith("- ")
        ? "diffLine removed"
        : line.startsWith("#")
          ? "diffLine heading"
          : "diffLine";
    return (
      <span key={`${index}-${line.slice(0, 12)}`} className={className}>
        {line || " "}
        {"\n"}
      </span>
    );
  });
}

function ToggleRow({
  label,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="toggleRow">
      <span>{label}</span>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.currentTarget.checked)}
      />
      <span className="toggleControl" aria-hidden="true" />
    </label>
  );
}

function SegmentedControl({
  label,
  value,
  options,
  disabled,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<[string, string]>;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  const activeIndex = Math.max(options.findIndex(([optionValue]) => optionValue === value), 0);

  return (
    <div className="settingControl">
      <span>{label}</span>
      <div
        className="segmented settingsSegmented fluidSegmented"
        style={{
          "--segment-count": options.length,
          "--segment-index": activeIndex,
          gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))`,
        } as CSSProperties}
      >
        {options.map(([optionValue, optionLabel]) => (
          <button
            key={optionValue}
            className={value === optionValue ? "active" : ""}
            type="button"
            onClick={() => onChange(optionValue)}
            disabled={disabled}
          >
            {optionLabel}
          </button>
        ))}
      </div>
    </div>
  );
}

function NumberField({
  label,
  value,
  min = 1,
  max = 65535,
  disabled,
  onChange,
}: {
  label: string;
  value: number;
  min?: number;
  max?: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}) {
  return (
    <label className="selectField">
      <span>{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </label>
  );
}

function TextAreaField({
  label,
  value,
  disabled,
  onChange,
}: {
  label: string;
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label className="textAreaField">
      <span>{label}</span>
      <textarea
        rows={4}
        value={value}
        disabled={disabled}
        spellCheck={false}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </label>
  );
}

interface ConnectionProcessGroupView {
  key: string;
  label: string;
  rows: TrackedConnection[];
  uploadBytes: number;
  downloadBytes: number;
  activeCount: number;
  paths: Array<[ConnectionPath, number]>;
}

function groupConnectionsByProcess(rows: TrackedConnection[]): ConnectionProcessGroupView[] {
  const groups = new Map<string, ConnectionProcessGroupView>();
  for (const connection of rows) {
    const label = getConnectionProcessLabel(connection);
    const key = label.toLocaleLowerCase();
    const existing = groups.get(key);
    if (existing) {
      existing.rows.push(connection);
      existing.uploadBytes += connection.upload_bytes;
      existing.downloadBytes += connection.download_bytes;
      existing.activeCount += connection.state === "active" ? 1 : 0;
      continue;
    }

    groups.set(key, {
      key,
      label,
      rows: [connection],
      uploadBytes: connection.upload_bytes,
      downloadBytes: connection.download_bytes,
      activeCount: connection.state === "active" ? 1 : 0,
      paths: [],
    });
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      paths: connectionPathOptions
        .filter(([path]) => path !== "all")
        .map(([path]) => [path, group.rows.filter((connection) => connection.path === path).length] as [ConnectionPath, number])
        .filter(([, count]) => count > 0),
    }))
    .sort((left, right) => right.rows.length - left.rows.length || compareText(left.label, right.label));
}

function getConnectionProcessLabel(connection: TrackedConnection) {
  return connection.process?.trim() || "Unknown process";
}

function connectionMatchesSearch(connection: TrackedConnection, query: string) {
  return [
    connection.host,
    connection.destination,
    connection.network,
    connection.connection_type,
    connection.process ?? "",
    connection.rule ?? "",
    connection.rule_payload ?? "",
    connection.path,
    connection.path_label,
    connection.path_note,
    connection.chains.join(" "),
  ]
    .join(" ")
    .toLocaleLowerCase()
    .includes(query);
}

function ConnectionProcessGroup({
  group,
  closeOne,
  closeMany,
  createOverride,
}: {
  group: ConnectionProcessGroupView;
  closeOne: (id: string) => void;
  closeMany: (ids: string[]) => void;
  createOverride: (connection: TrackedConnection) => void;
}) {
  const activeIds = group.rows.filter((connection) => connection.state === "active").map((connection) => connection.id);
  return (
    <section className="connectionProcessGroup">
      <div className="connectionProcessHeader">
        <div>
          <strong>{group.label}</strong>
          <span>
            {group.rows.length} flows{group.activeCount ? ` / ${group.activeCount} active` : ""} / {formatBytes(group.uploadBytes)} up /{" "}
            {formatBytes(group.downloadBytes)} down
          </span>
        </div>
        <div className="processPathCounts">
          {group.paths.map(([path, count]) => (
            <PathBadge key={path} path={path} label={`${formatPathLabel(path)} ${count}`} />
          ))}
          {activeIds.length ? (
            <button className="iconSmall danger" type="button" onClick={() => closeMany(activeIds)} title="Close active flows in this process">
              <X size={14} aria-hidden="true" />
            </button>
          ) : null}
        </div>
      </div>
      <div className="connectionProcessRows">
        {group.rows.map((connection) => (
          <ConnectionRow
            key={`${connection.state}-${connection.id}-${connection.closed_at ?? "open"}`}
            connection={connection}
            closeOne={closeOne}
            createOverride={createOverride}
          />
        ))}
      </div>
    </section>
  );
}

function ConnectionRow({
  connection,
  closeOne,
  createOverride,
}: {
  connection: TrackedConnection;
  closeOne: (id: string) => void;
  createOverride: (connection: TrackedConnection) => void;
}) {
  const isActive = connection.state === "active";
  const processLabel = getConnectionProcessLabel(connection);
  return (
    <div className="connectionRow">
      <div className="connectionMain">
        <PathBadge path={connection.path} label={connection.path_label} />
        <div>
          <strong>{connection.host || connection.destination}</strong>
          <span>{connection.destination}</span>
          <span className="connectionProcessLine">{processLabel}</span>
        </div>
      </div>
      <div className="connectionMeta">
        <span>{connection.network}</span>
        <span>{formatBytes(connection.upload_bytes)} up</span>
        <span>{formatBytes(connection.download_bytes)} down</span>
      </div>
      <div className="chainLine" title={connection.path_note}>
        {connection.chains.length ? connection.chains.join("  >  ") : connection.path_note}
      </div>
      <div className="connectionTraceLine">
        <span>{connection.rule ?? "rule unknown"}{connection.rule_payload ? ` / ${connection.rule_payload}` : ""}</span>
        <strong>{connection.path_note}</strong>
      </div>
      <details className="connectionDetails">
        <summary>Details</summary>
        <div className="connectionDetailsGrid">
          <DetailItem label="Flow ID" value={connection.id} />
          <DetailItem label="State" value={connection.state} />
          <DetailItem label="Host" value={connection.host || "unknown"} />
          <DetailItem label="Destination" value={connection.destination} />
          <DetailItem label="Process" value={processLabel} />
          <DetailItem label="Process path" value={connection.process_path ?? "not exposed"} />
          <DetailItem label="Network" value={`${connection.network} / ${connection.connection_type}`} />
          <DetailItem label="Route" value={`${connection.path_label} / ${connection.path_note}`} />
          <DetailItem label="Rule source" value={connection.rule_source ?? "unknown"} />
          <DetailItem label="Rule" value={connection.rule ?? "unknown"} />
          <DetailItem label="Payload" value={connection.rule_payload ?? "none"} />
          <DetailItem label="Chain" value={connection.chains.length ? connection.chains.join(" > ") : "none"} />
          <DetailItem label="Traffic" value={`${formatBytes(connection.upload_bytes)} up / ${formatBytes(connection.download_bytes)} down`} />
          <DetailItem label="Started" value={formatConnectionTime(connection.started_at)} />
          <DetailItem label="Closed" value={connection.closed_at ? formatTimestamp(connection.closed_at) : "not closed"} />
        </div>
      </details>
      <div className="connectionTail">
        <span>{isActive ? "Active" : "Closed"}</span>
        <button className="iconSmall" type="button" onClick={() => createOverride(connection)} title="Create local override from this connection">
          <Plus size={14} aria-hidden="true" />
        </button>
        {isActive ? (
          <button className="iconSmall danger" type="button" onClick={() => closeOne(connection.id)} title="Close connection">
            <X size={14} aria-hidden="true" />
          </button>
        ) : (
          <span>{connection.closed_at ? formatTimestamp(connection.closed_at) : "Closed"}</span>
        )}
      </div>
    </div>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="detailItem">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function GroupButton({ group, active, onClick }: { group: ProxyGroupView; active: boolean; onClick: () => void }) {
  const identity = parseServerIdentity(group.name);
  const selected = group.selected ? parseServerIdentity(group.selected).label : `${group.nodes.length} nodes`;
  return (
    <button className={active ? "groupButton active" : "groupButton"} type="button" onClick={onClick}>
      <IdentityBadge identity={identity} className="groupEmoji" size={14} fallback={<ListTree size={14} aria-hidden="true" />} />
      <div>
        <span>{identity.label}</span>
        <strong>{selected}</strong>
      </div>
    </button>
  );
}

function NodeRow({ group, node, busy, select }: { group: string; node: ProxyNodeView; busy: boolean; select: (group: string, proxy: string) => void }) {
  const identity = parseServerIdentity(node.name);
  return (
    <div className={node.selected ? "nodeRow selected" : "nodeRow"}>
      <div className="nodeIdentity">
        <IdentityBadge identity={identity} className="nodeFlag" size={17} />
        <div>
          <strong>{identity.label}</strong>
          <span>{node.proxy_type ?? "proxy"}{node.server ? ` / ${node.server}` : ""}</span>
        </div>
      </div>
      <div className="nodeMeta">
        <span>{node.delay_ms !== null ? `${node.delay_ms} ms` : "No ping"}</span>
        {node.alive === false ? <span className="bad">Down</span> : null}
        {node.selected ? (
          <span className="selectedMark"><Check size={14} /> Selected</span>
        ) : (
          <button className="subtleButton" type="button" onClick={() => select(group, node.name)} disabled={busy}>
            Use
          </button>
        )}
      </div>
    </div>
  );
}

function HomeNodeButton({
  group,
  node,
  selected,
  busy,
  select,
}: {
  group: string;
  node: ProxyNodeView;
  selected: boolean;
  busy: boolean;
  select: (group: string, proxy: string) => void;
}) {
  const identity = parseServerIdentity(node.name);
  return (
    <button
      className={selected ? "homeNodeButton selected" : "homeNodeButton"}
      type="button"
      onClick={() => select(group, node.name)}
      disabled={busy || selected}
    >
      <IdentityBadge identity={identity} className="nodeFlag" size={17} />
      <span className="homeNodeText">
        <strong>{identity.label}</strong>
        <small>{formatNodeMeta(node)}</small>
      </span>
      <span className={node.alive === false ? "nodeLatency bad" : "nodeLatency"}>{node.delay_ms !== null ? `${node.delay_ms} ms` : "—"}</span>
    </button>
  );
}

function IdentityBadge({
  identity,
  className,
  size,
  fallback,
}: {
  identity: ServerIdentity;
  className: string;
  size: number;
  fallback?: ReactNode;
}) {
  if (identity.countryCode) {
    return <span className={`${className} countryFlag flag-${identity.countryCode.toLowerCase()}`} aria-label={`${identity.countryCode} flag`} />;
  }
  return <span className={identity.flag ? `${className} hasFlag` : className}>{identity.flag ?? fallback ?? <Globe2 size={size} aria-hidden="true" />}</span>;
}

function LegendItem({ tone, title, text }: { tone: string; title: string; text: string }) {
  return (
    <div className="legendItem">
      <PathBadge path={tone} label={title} />
      <span>{text}</span>
    </div>
  );
}

function EmptyList({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <div className="emptyList">
      {icon}
      <strong>{title}</strong>
      <span>{text}</span>
    </div>
  );
}

function StatusBadge({ connected, pending, status }: { connected: boolean; pending: boolean; status: string }) {
  return (
    <div className={connected ? "statusBadge connected" : pending ? "statusBadge pending" : "statusBadge"}>
      {connected ? <CheckCircle2 size={15} aria-hidden="true" /> : pending ? <RefreshCw size={15} aria-hidden="true" /> : <Power size={15} aria-hidden="true" />}
      <span>{status}</span>
    </div>
  );
}

function PathBadge({ path, label }: { path: string; label: string }) {
  return <span className={`pathBadge ${path}`}>{label}</span>;
}

function formatPathLabel(path: ConnectionPath) {
  if (path === "vpn") {
    return "VPN";
  }
  if (path === "direct") {
    return "DIRECT";
  }
  return formatRouteMode(path);
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="metric">
      <span>{icon}{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusRow({ label, value, good }: { label: string; value: string; good?: boolean }) {
  return (
    <div className="statusRow">
      <span>{label}</span>
      <strong className={good ? "good" : undefined}>{value}</strong>
    </div>
  );
}

function viewTitle(view: AppView) {
  switch (view) {
    case "connections":
      return "Connections";
    case "servers":
      return "Servers";
    case "policy":
      return "Policy";
    case "settings":
      return "Settings";
    default:
      return "BadVpn";
  }
}

function formatRouteMode(mode: string) {
  if (mode === "smart") {
    return "Smart";
  }
  if (mode === "vpn_only") {
    return "VPN Only";
  }
  return mode
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function listToText(values: string[]) {
  return values.join("\n");
}

function textToList(value: string) {
  return value
    .split(/\r?\n|,/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function nameserverPolicyToText(values: AppSettings["dns"]["nameserver_policy"]) {
  return values.map((rule) => `${rule.pattern} = ${rule.nameservers.join(", ")}`).join("\n");
}

function textToNameserverPolicy(value: string): AppSettings["dns"]["nameserver_policy"] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [pattern, nameservers = ""] = line.split("=");
      return {
        pattern: pattern.trim(),
        nameservers: textToList(nameservers),
      };
    })
    .filter((rule) => rule.pattern && rule.nameservers.length > 0);
}

function normalizeProcessName(value: string) {
  return value.trim().replace(/^["']|["']$/g, "").split(/[\\/]/).filter(Boolean).pop()?.trim() ?? "";
}

function formatRefreshInterval(hours: number | null) {
  if (!hours) {
    return "Manual";
  }
  return `${hours} h`;
}

function formatProfileRefreshStatus(profile: SubscriptionProfileView) {
  if (profile.next_refresh_at) {
    return `Next refresh ${new Date(profile.next_refresh_at * 1000).toLocaleString()}`;
  }
  if (profile.last_successful_refresh_at) {
    return `Last refreshed ${new Date(profile.last_successful_refresh_at * 1000).toLocaleString()}`;
  }
  return `Added ${new Date(profile.created_at).toLocaleString()}`;
}

function formatProfileFetchOptions(profile: SubscriptionProfileView) {
  const mode =
    profile.fetch_options.proxy_mode === "direct"
      ? "direct"
      : profile.fetch_options.proxy_mode === "custom"
        ? `custom ${profile.fetch_options.custom_proxy_redacted ?? "proxy"}`
        : "system proxy";
  const userAgent = profile.fetch_options.user_agent ? ", custom UA" : "";
  return `Fetch: ${mode}, ${profile.fetch_options.timeout_seconds}s${userAgent}`;
}

function subscriptionFailureCopy(error: string | null) {
  if (!error) {
    return "";
  }
  const value = error.toLocaleLowerCase();
  if (/(hwid|devices?|too many devices|лимит.*устрой|устройств|устройство)/i.test(error)) {
    return "Панель провайдера отклонила профиль: достигнут лимит устройств/HWID. Откройте личный кабинет или поддержку провайдера, сбросьте привязки устройств и обновите подписку.";
  }
  if (value.includes("expired") || value.includes("истек") || value.includes("законч")) {
    return "Подписка истекла. Продлите профиль в панели провайдера, затем обновите подписку в BadVpn.";
  }
  if (value.includes("quota") || value.includes("traffic") || value.includes("трафик") || value.includes("лимит трафика")) {
    return "Лимит трафика по подписке исчерпан. Пополните или продлите тариф у провайдера, затем обновите профиль.";
  }
  if (value.includes("unauthorized") || value.includes("forbidden") || value.includes("token") || value.includes("401") || value.includes("403")) {
    return "Провайдер не принял токен подписки. Сгенерируйте свежую ссылку в панели провайдера и импортируйте ее заново.";
  }
  if (value.includes("rate-limit") || value.includes("rate limit") || value.includes("too many requests") || value.includes("429")) {
    return "Провайдер временно ограничил частоту обновлений. Подождите несколько минут и попробуйте снова.";
  }
  if (value.includes("not found") || value.includes("could not find") || value.includes("404") || value.includes("410")) {
    return "Провайдер не нашел этот профиль. Создайте новую ссылку подписки в панели провайдера.";
  }
  if (value.includes("maintenance") || value.includes("temporarily unavailable") || value.includes("502") || value.includes("503") || value.includes("504")) {
    return "Панель провайдера временно недоступна. BadVpn сохранит последний рабочий профиль; повторите обновление позже.";
  }
  if (value.includes("invalid format") || value.includes("not a supported") || value.includes("no usable nodes")) {
    return "Ответ подписки не похож на Clash/Mihomo профиль или URI-list. Проверьте формат экспорта в панели провайдера.";
  }
  if (value.includes("provider returned") || value.includes("provider rejected")) {
    return "Провайдер вернул ошибку подписки. Последний рабочий профиль сохранен; если ошибка повторится, обратитесь в поддержку провайдера.";
  }
  return error;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

function formatTimestamp(seconds: number) {
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatConnectionTime(value: string | null) {
  if (!value) {
    return "unknown";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatAppUpdateStatus(status: AppUpdateStatus) {
  switch (status.state) {
    case "idle":
      return "Not checked";
    case "checking":
      return "Checking";
    case "available":
      return `Available ${status.version}`;
    case "not_available":
      return "Current";
    case "downloading":
      return status.progress === null ? "Downloading" : `${status.progress}%`;
    case "installed":
      return "Installed";
    case "error":
      return status.message;
  }
}

function formatComponentUpdate(component: ComponentUpdate) {
  if (component.error) {
    return component.error;
  }
  if (!component.latest_version) {
    return component.current_version;
  }
  if (component.update_available) {
    return `${component.current_version} -> ${component.latest_version}`;
  }
  return component.current_version;
}

function getConnectionProgress({
  attempt,
  now,
  routeMode,
  status,
  connected,
  fallbackActive,
  lastError,
}: {
  attempt: ConnectionAttempt | null;
  now: number;
  routeMode: AppSettings["core"]["route_mode"];
  status: AgentState["connection"]["status"];
  connected: boolean;
  fallbackActive: boolean;
  lastError: string | null;
}): ConnectionProgressModel | null {
  if (lastError || status === "error") {
    return null;
  }

  if (attempt?.action === "disconnect" || status === "stopping") {
    return progressFromSteps(
      ["Stopping runtime", "Cleaning route state", "Disconnected"],
      connected ? timedProgressIndex(attempt, now, 3) : 2,
    );
  }

  if (attempt?.action !== "connect" && status !== "starting") {
    return null;
  }

  const steps =
    routeMode === "smart"
      ? ["Preparing policy", "Starting zapret", "Starting Mihomo", "Verifying connection", fallbackActive ? "VPN Only fallback" : "Connected"]
      : ["Preparing policy", "Starting Mihomo", "Verifying connection", "Connected"];
  const activeIndex = connected ? steps.length - 1 : timedProgressIndex(attempt, now, steps.length);
  return progressFromSteps(steps, activeIndex);
}

function timedProgressIndex(attempt: ConnectionAttempt | null, now: number, stepCount: number) {
  const elapsed = attempt ? Math.max(now - attempt.startedAt, 0) : 0;
  return Math.min(Math.floor(elapsed / 1200), Math.max(stepCount - 2, 0));
}

function progressFromSteps(steps: string[], activeIndex: number): ConnectionProgressModel {
  const normalizedIndex = Math.min(Math.max(activeIndex, 0), steps.length - 1);
  return {
    label: steps[normalizedIndex],
    steps: steps.map((label, index) => ({
      label,
      state: index < normalizedIndex ? "done" : index === normalizedIndex ? "active" : "pending",
    })),
  };
}

function getHomeRouteSummary(routeMode: AppSettings["core"]["route_mode"], fallbackActive: boolean) {
  if (routeMode === "vpn_only" || fallbackActive) {
    return [
      { label: "Video", value: fallbackActive ? "VPN fallback" : "VPN", good: true },
      { label: "AI/social", value: "VPN", good: true },
      { label: "RU", value: "VPN", good: true },
    ];
  }

  return [
    { label: "Video", value: "DIRECT + zapret", good: true },
    { label: "AI/social", value: "VPN", good: true },
    { label: "RU", value: "DIRECT", good: true },
  ];
}

function buildSupportSummary({
  state,
  settings,
  runtimeReadiness,
  runtimeDiagnostics,
  componentUpdates,
  policySummary,
}: {
  state: AgentState;
  settings: AppSettings;
  runtimeReadiness: RuntimeReadinessResponse | null;
  runtimeDiagnostics: RuntimeDiagnosticsReport | null;
  componentUpdates: ComponentUpdate[];
  policySummary: PolicySummaryResponse | null;
}) {
  const sourceCounts = new Map<string, number>();
  for (const rule of policySummary?.policy_rules ?? []) {
    sourceCounts.set(rule.source, (sourceCounts.get(rule.source) ?? 0) + 1);
  }
  const sourceSummary = [...sourceCounts.entries()]
    .sort((left, right) => right[1] - left[1] || compareText(left[0], right[0]))
    .map(([source, count]) => `${formatRouteMode(source)}=${count}`)
    .join(", ");
  const activePresets = Object.entries(settings.routing_policy.smart_presets)
    .filter(([, enabled]) => enabled)
    .map(([name]) => formatRouteMode(name))
    .join(", ");
  const componentSummary = componentUpdates.length
    ? componentUpdates.map((component) => `${component.name}:${component.current_version}${component.update_available ? "->update" : ""}${component.error ? ":error" : ""}`).join(", ")
    : "not checked";
  const diagnosticSummary = runtimeDiagnostics
    ? runtimeDiagnostics.checks.map((check) => `${check.label}:${check.status}`).join(", ")
    : "not run";
  const providerLinks = providerMetadataLinks(state.subscription);
  const providerLinkSummary = providerLinks.length
    ? providerLinks.map((link) => `${link.label}:${formatExternalLinkHost(link.href)}`).join(", ")
    : "none";
  const providerAnnouncement = providerAnnouncementMetadata(state.subscription);

  return [
    "BadVpn support summary",
    `generated_local=${new Date().toLocaleString()}`,
    "privacy=redacted: no subscription URL, controller secret or local credential values included",
    "",
    `[state] phase=${state.phase}; connected=${state.connection.connected}; status=${state.connection.status}; route=${formatRouteMode(state.connection.route_mode)}; selected_profile=${state.connection.selected_profile ?? "none"}; selected_proxy=${state.connection.selected_proxy ?? "auto"}`,
    `[subscription] valid=${state.subscription.is_valid ?? "unknown"}; format=${formatRouteMode(state.subscription.format)}; nodes=${state.subscription.node_count}; title=${state.subscription.profile_title ?? "none"}`,
    `[announcements] bpn_signed=none; provider_source=${providerAnnouncement.source}; provider_updated=${providerAnnouncement.timestamp}; provider_links=${providerLinkSummary}`,
    `[traffic] upload=${formatBytes(state.metrics.upload_bytes)}; download=${formatBytes(state.metrics.download_bytes)}`,
    `[settings] route_mode=${formatRouteMode(settings.core.route_mode)}; tun=${settings.tun.enabled}; dns=${settings.dns.mode}; zapret=${settings.zapret.enabled}; strategy=${settings.zapret.strategy}`,
    `[local_overrides] enabled=${settings.routing_policy.local_overrides_enabled}; total=${countLocalRoutingOverrides(settings.routing_policy)}; vpn=${settings.routing_policy.force_vpn_domains.length + settings.routing_policy.force_vpn_cidrs.length}; zapret=${settings.routing_policy.force_zapret_domains.length + settings.routing_policy.force_zapret_cidrs.length + settings.routing_policy.force_zapret_processes.length + settings.routing_policy.force_zapret_tcp_ports.length + settings.routing_policy.force_zapret_udp_ports.length}; direct=${settings.routing_policy.force_direct_domains.length + settings.routing_policy.force_direct_cidrs.length + settings.routing_policy.force_direct_processes.length}`,
    `[smart_presets] active=${activePresets || "none"}; coverage=${settings.routing_policy.coverage}`,
    `[readiness] ready=${runtimeReadiness?.ready ?? "unknown"}; components=${runtimeReadiness?.components_ready ?? "unknown"}; mihomo=${runtimeReadiness?.mihomo_ready ?? "unknown"}; zapret=${runtimeReadiness?.zapret_ready ?? "unknown"}; message=${runtimeReadiness?.message ?? "not checked"}`,
    `[components] ${componentSummary}`,
    `[diagnostics] mihomo=${runtimeDiagnostics?.mihomo_healthy ?? state.diagnostics.mihomo_healthy}; zapret=${runtimeDiagnostics?.zapret_healthy ?? state.diagnostics.zapret_healthy}; checks=${diagnosticSummary}; last_error=${state.last_error ?? "none"}`,
    `[policy] available=${policySummary?.available ?? false}; mode=${policySummary ? formatRouteMode(policySummary.mode) : "unknown"}; rules=${policySummary?.rule_count ?? 0}; suppressed=${policySummary?.suppressed_count ?? 0}; warnings=${policySummary?.warnings_count ?? 0}; zapret_domains=${policySummary?.zapret_domain_count ?? 0}; sources=${sourceSummary || "unknown"}`,
  ].join("\n");
}

function providerAnnouncementMetadata(subscription: AgentState["subscription"]) {
  const link = providerMetadataLinks(subscription).find((item) => item.label === "Announcement" || item.label === "Account");
  return {
    source: "subscription",
    timestamp: formatSubscriptionMetadataTimestamp(subscription.last_refreshed_at),
    message: subscription.announce ?? "Нет объявлений от подписки.",
    href: link?.href ?? null,
  };
}

function formatSubscriptionMetadataTimestamp(value: string | null) {
  if (!value) {
    return "not refreshed";
  }
  const numeric = Number(value);
  const date = Number.isFinite(numeric) ? new Date(numeric * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "not refreshed";
  }
  return date.toLocaleString();
}

function providerMetadataLinks(subscription: AgentState["subscription"]) {
  const links: Array<{ label: string; href: string }> = [];
  const push = (label: string, href: string | null) => {
    const value = href?.trim();
    if (!value || !/^https?:\/\//i.test(value)) {
      return;
    }
    if (links.some((link) => link.href === value)) {
      return;
    }
    links.push({ label, href: value });
  };

  push("Announcement", subscription.announce_url);
  push("Account", subscription.profile_web_page_url);
  push("Support", subscription.support_url);
  return links;
}

function formatExternalLinkHost(href: string) {
  try {
    return new URL(href).host;
  } catch {
    return "provider link";
  }
}

function countLocalRoutingOverrides(policy: AppSettings["routing_policy"]) {
  return [
    policy.force_vpn_domains,
    policy.force_vpn_cidrs,
    policy.force_zapret_domains,
    policy.force_zapret_cidrs,
    policy.force_zapret_processes,
    policy.force_zapret_tcp_ports,
    policy.force_zapret_udp_ports,
    policy.force_direct_domains,
    policy.force_direct_cidrs,
    policy.force_direct_processes,
  ].reduce((total, values) => total + values.length, 0);
}

function localOverrideSummaryItems(policy: AppSettings["routing_policy"]): LocalOverrideSummaryItem[] {
  const typed = (policy.local_overrides?.rules ?? []).map((rule) => ({
    id: rule.id,
    enabled: rule.enabled,
    route: rule.path,
    kind: rule.target_kind === "app" ? "process" : rule.target_kind.replace("_port", ""),
    value: rule.process_name ?? rule.value,
  }));
  const legacy = [
    ...policy.force_vpn_domains.map((value) => ({ route: "vpn", kind: "domain", value })),
    ...policy.force_vpn_cidrs.map((value) => ({ route: "vpn", kind: "cidr", value })),
    ...policy.force_zapret_domains.map((value) => ({ route: "zapret", kind: "domain", value })),
    ...policy.force_zapret_cidrs.map((value) => ({ route: "zapret", kind: "cidr", value })),
    ...policy.force_zapret_processes.map((value) => ({ route: "zapret", kind: "process", value })),
    ...policy.force_zapret_tcp_ports.map((value) => ({ route: "zapret", kind: "tcp", value })),
    ...policy.force_zapret_udp_ports.map((value) => ({ route: "zapret", kind: "udp", value })),
    ...policy.force_direct_domains.map((value) => ({ route: "direct", kind: "domain", value })),
    ...policy.force_direct_cidrs.map((value) => ({ route: "direct", kind: "cidr", value })),
    ...policy.force_direct_processes.map((value) => ({ route: "direct", kind: "process", value })),
  ].filter((item) => !typed.some((rule) => rule.route === item.route && rule.kind === item.kind && rule.value.toLocaleLowerCase() === item.value.toLocaleLowerCase()));
  return [...typed, ...legacy];
}

function localOverrideConflictLabel(
  item: ReturnType<typeof localOverrideSummaryItems>[number],
  policySummary: PolicySummaryResponse | null,
) {
  if (!policySummary?.available) {
    return null;
  }
  const value = item.value.toLocaleLowerCase();
  const overlappingSources = policySummary.policy_rules
    .filter((rule) => rule.source !== "LocalUserOverride" && rule.target_value.toLocaleLowerCase() === value)
    .map((rule) => formatRouteMode(rule.source));
  if (overlappingSources.length > 0) {
    return `overlap: ${[...new Set(overlappingSources)].join(", ")}`;
  }
  const suppressed = policySummary.suppressed_rules.some((rule) =>
    `${rule.original_rule} ${rule.chosen_rule}`.toLocaleLowerCase().includes(value),
  );
  return suppressed ? "suppressed provider rule" : null;
}

function removeLegacyOverrideValue(
  policy: AppSettings["routing_policy"],
  route: string,
  kind: string,
  value: string,
): Partial<AppSettings["routing_policy"]> {
  const remove = (values: string[], compareKind = kind) => {
    const target = comparableLegacyOverrideValue(value, compareKind);
    return values.filter((item) => comparableLegacyOverrideValue(item, compareKind) !== target);
  };
  if (route === "vpn" && kind === "domain") return { force_vpn_domains: remove(policy.force_vpn_domains) };
  if (route === "vpn" && kind === "cidr") return { force_vpn_cidrs: remove(policy.force_vpn_cidrs) };
  if (route === "zapret" && kind === "domain") return { force_zapret_domains: remove(policy.force_zapret_domains) };
  if (route === "zapret" && kind === "cidr") return { force_zapret_cidrs: remove(policy.force_zapret_cidrs) };
  if (route === "zapret" && (kind === "process" || kind === "app")) return { force_zapret_processes: remove(policy.force_zapret_processes, "process") };
  if (route === "zapret" && kind === "tcp_port") return { force_zapret_tcp_ports: remove(policy.force_zapret_tcp_ports) };
  if (route === "zapret" && kind === "udp_port") return { force_zapret_udp_ports: remove(policy.force_zapret_udp_ports) };
  if (route === "direct" && kind === "domain") return { force_direct_domains: remove(policy.force_direct_domains) };
  if (route === "direct" && kind === "cidr") return { force_direct_cidrs: remove(policy.force_direct_cidrs) };
  if (route === "direct" && (kind === "process" || kind === "app")) return { force_direct_processes: remove(policy.force_direct_processes, "process") };
  return {};
}

function comparableLegacyOverrideValue(value: string, kind: string) {
  const normalized = value.trim().toLocaleLowerCase();
  if (kind === "process" || kind === "app") {
    return normalized.split(/[\\/]/).pop() ?? normalized;
  }
  return normalized;
}

function localOverrideDraftFromPolicyRule(rule: PolicyRuleView): {
  route: LocalOverrideRoute;
  kind: LocalOverrideTargetKind;
  value: string;
} | null {
  const targetKind = rule.target_kind.toLocaleLowerCase();
  const route = policyPathToLocalOverrideRoute(rule.path);
  if (targetKind === "tcpport" || targetKind === "tcp_port") {
    return { route: "zapret", kind: "tcp_port", value: rule.target_value };
  }
  if (targetKind === "udpport" || targetKind === "udp_port") {
    return { route: "zapret", kind: "udp_port", value: rule.target_value };
  }
  if (targetKind.includes("processname")) {
    return route === "vpn" ? null : { route, kind: "process", value: rule.target_value };
  }
  if (targetKind.includes("cidr") || targetKind.includes("ipsuffix")) {
    return { route, kind: "cidr", value: rule.target_value };
  }
  if (targetKind.includes("domain")) {
    return { route, kind: "domain", value: rule.target_value };
  }
  return null;
}

function policyPathToLocalOverrideRoute(path: string): LocalOverrideRoute {
  if (path.includes("VpnProxy")) {
    return "vpn";
  }
  if (path.includes("ZapretDirect")) {
    return "zapret";
  }
  return "direct";
}

function getRuntimeComponentStatus(components: ComponentUpdate[], readiness: RuntimeReadinessResponse | null): {
  status: "ready" | "pending" | "blocked";
  detail: string;
} {
  if (readiness) {
    if (readiness.components_ready) {
      return {
        status: "ready",
        detail: readiness.needs_zapret
          ? "Mihomo and zapret assets are present for Smart mode."
          : "Mihomo is present. zapret is not required for VPN Only.",
      };
    }
    return {
      status: "blocked",
      detail: readiness.message,
    };
  }

  if (components.length === 0) {
    return {
      status: "pending",
      detail: "Runtime assets are not checked yet. Prepare will download or repair Mihomo and zapret assets.",
    };
  }

  const missing = components.filter((component) => component.current_version.toLowerCase().startsWith("missing"));
  if (missing.length > 0) {
    return {
      status: "blocked",
      detail: `Missing ${missing.map((component) => component.name).join(", ")}. Prepare runtime before connecting.`,
    };
  }

  const failed = components.filter((component) => component.error);
  if (failed.length > 0) {
    return {
      status: "pending",
      detail: `${failed.length} component check warning. Prepare can repair local runtime assets.`,
    };
  }

  const updates = components.filter((component) => component.update_available);
  if (updates.length > 0) {
    return {
      status: "pending",
      detail: `${updates.length} runtime update available. Current assets can run, Prepare updates them.`,
    };
  }

  return {
    status: "ready",
    detail: "Mihomo, zapret, and route lists are present.",
  };
}

function getSelectedCatalogNode(catalog: ProxyCatalog | null) {
  for (const group of catalog?.groups ?? []) {
    const selected = group.nodes.find((node) => node.selected || node.name === group.selected);
    if (selected) {
      return selected;
    }
  }
  return null;
}

function getActiveHomeGroup(catalog: ProxyCatalog | null, selectedGroup: string | null) {
  const groups = catalog?.groups ?? [];
  return (
    groups.find((group) => group.name === selectedGroup) ??
    groups.find((group) => group.name === "Выбор сервера") ??
    groups.find((group) => group.group_type === "select") ??
    groups[0] ??
    null
  );
}

type ServerIdentity = {
  countryCode: string | null;
  flag: string | null;
  label: string;
  raw: string;
};

function parseServerIdentity(name: string): ServerIdentity {
  const flag = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u)?.[0] ?? null;
  const emoji = flag ?? name.match(/[\p{Emoji_Presentation}\u{2600}-\u{27BF}]/u)?.[0] ?? null;
  const label = name
    .replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, "")
    .replace(/[\p{Emoji_Presentation}\u{2600}-\u{27BF}]/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  return {
    countryCode: detectCountryCode(name, flag),
    flag: emoji,
    label: label || name,
    raw: name,
  };
}

function detectCountryCode(name: string, flag: string | null) {
  const codeFromFlag = flag ? countryCodeFromRegionalFlag(flag) : null;
  if (codeFromFlag) {
    return codeFromFlag;
  }
  const normalized = name.toLocaleLowerCase();
  const countryPatterns: Array<[RegExp, string]> = [
    [/\b(?:nl|nld|netherlands)\b|нидерланд|голланд/, "NL"],
    [/\b(?:de|deu|germany)\b|герман/, "DE"],
    [/\b(?:us|usa|united states|dallas)\b|сша|америк/, "US"],
    [/\b(?:se|swe|sweden)\b|швец/, "SE"],
    [/\b(?:ch|che|switzerland)\b|швейцар/, "CH"],
    [/\b(?:tr|tur|turkey)\b|турц/, "TR"],
    [/\b(?:ru|rus|russia|spb|moscow)\b|росси|москв|спб/, "RU"],
    [/\b(?:fi|fin|finland)\b|финлянд/, "FI"],
    [/\b(?:fr|fra|france)\b|франц/, "FR"],
    [/\b(?:gb|uk|gbr|united kingdom|london)\b|британ|англи/, "GB"],
    [/\b(?:pl|pol|poland)\b|польш/, "PL"],
    [/\b(?:jp|jpn|japan|tokyo)\b|япон/, "JP"],
    [/\b(?:sg|sgp|singapore)\b|сингапур/, "SG"],
    [/\b(?:ca|can|canada)\b|канад/, "CA"],
  ];
  return countryPatterns.find(([pattern]) => pattern.test(normalized))?.[1] ?? null;
}

function countryCodeFromRegionalFlag(flag: string) {
  const chars = Array.from(flag);
  if (chars.length !== 2) {
    return null;
  }
  const code = chars
    .map((char) => {
      const point = char.codePointAt(0);
      return point ? String.fromCharCode(point - 0x1f1e6 + 65) : "";
    })
    .join("");
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

function formatNodeMeta(node: ProxyNodeView) {
  const parts = [node.proxy_type ?? (node.is_group ? "group" : "proxy")];
  if (node.server) {
    parts.push(node.server);
  }
  if (node.alive === false) {
    parts.push("offline");
  }
  return parts.join(" / ");
}

function getTrafficStats(samples: TrafficSample[], state: AgentState) {
  const lastSample = samples[samples.length - 1] ?? {
    at: Date.now(),
    upload: state.metrics.upload_bytes,
    download: state.metrics.download_bytes,
  };
  const previous = samples
    .slice(0, -1)
    .reverse()
    .find((sample) => sample.at < lastSample.at);
  const seconds = previous ? Math.max((lastSample.at - previous.at) / 1000, 1) : 0;
  const baselineJump = previous && previous.upload === 0 && previous.download === 0 && lastSample.upload + lastSample.download > 0;
  const uploadRate = previous && !baselineJump ? Math.max((lastSample.upload - previous.upload) / seconds, 0) : 0;
  const downloadRate = previous && !baselineJump ? Math.max((lastSample.download - previous.download) / seconds, 0) : 0;

  return {
    uploadSpeed: `${formatBytes(uploadRate)}/s`,
    downloadSpeed: `${formatBytes(downloadRate)}/s`,
    uploadTotal: formatBytes(lastSample.upload),
    downloadTotal: formatBytes(lastSample.download),
    total: formatBytes(lastSample.upload + lastSample.download),
  };
}

function proxyGroupMatchesSearch(group: ProxyGroupView, query: string) {
  return proxyGroupText(group).includes(query) || group.nodes.some((node) => proxyNodeMatchesSearch(node, query));
}

function proxyGroupText(group: ProxyGroupView) {
  return [group.name, group.group_type, group.selected ?? ""].join(" ").toLocaleLowerCase();
}

function proxyNodeMatchesSearch(node: ProxyNodeView, query: string) {
  return [node.name, node.proxy_type ?? "", node.server ?? "", node.alive === false ? "down" : node.alive === true ? "alive" : ""]
    .join(" ")
    .toLocaleLowerCase()
    .includes(query);
}

function sortProxyNodes(nodes: ProxyNodeView[], sort: ServerNodeSort, selected: string | null) {
  const indexed = nodes.map((node, index) => ({ node, index }));
  indexed.sort((left, right) => {
    switch (sort) {
      case "name":
        return compareText(left.node.name, right.node.name) || left.index - right.index;
      case "latency":
        return compareLatency(left.node.delay_ms, right.node.delay_ms) || compareText(left.node.name, right.node.name) || left.index - right.index;
      case "alive":
        return compareAlive(left.node.alive, right.node.alive) || compareText(left.node.name, right.node.name) || left.index - right.index;
      case "selected":
        return compareSelected(left.node, right.node, selected) || left.index - right.index;
      default:
        return left.index - right.index;
    }
  });
  return indexed.map((item) => item.node);
}

function compareText(left: string, right: string) {
  return left.localeCompare(right, undefined, { sensitivity: "base", numeric: true });
}

function compareLatency(left: number | null, right: number | null) {
  if (left === right) {
    return 0;
  }
  if (left === null) {
    return 1;
  }
  if (right === null) {
    return -1;
  }
  return left - right;
}

function compareAlive(left: boolean | null, right: boolean | null) {
  const rank = (value: boolean | null) => (value === true ? 0 : value === null ? 1 : 2);
  return rank(left) - rank(right);
}

function compareSelected(left: ProxyNodeView, right: ProxyNodeView, selected: string | null) {
  const isLeftSelected = left.selected || left.name === selected;
  const isRightSelected = right.selected || right.name === selected;
  if (isLeftSelected === isRightSelected) {
    return compareText(left.name, right.name);
  }
  return isLeftSelected ? -1 : 1;
}

function formatRuntimeComponentStatus(components: ComponentUpdate[], readiness: RuntimeReadinessResponse | null) {
  const status = getRuntimeComponentStatus(components, readiness);
  if (status.status === "ready") {
    return "Ready";
  }
  if (status.status === "blocked") {
    return "Needs prepare";
  }
  return components.length ? "Update available" : "Not checked";
}

function parseStartupTimeline(message: string | null): Array<{ name: string; value: number }> {
  if (!message?.includes("Startup timeline:")) {
    return [];
  }

  return [...message.matchAll(/([a-z_]+_ms)=(\d+)/g)].map((match) => ({
    name: match[1],
    value: Number(match[2]),
  }));
}

function formatTimelineKey(name: string) {
  return name
    .replace(/_ms$/, "")
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function conciseError(message: string) {
  const firstSentence = message.split(/[.!?]\s/)[0]?.trim();
  if (!firstSentence) {
    return "Connection failed.";
  }
  return firstSentence.length > 96 ? `${firstSentence.slice(0, 93)}...` : firstSentence;
}

function getQuota(state: AgentState) {
  const { upload_bytes, download_bytes, total_bytes, expire_at } = state.subscription.user_info;
  const used = (upload_bytes ?? 0) + (download_bytes ?? 0);
  const trafficLeft = total_bytes && total_bytes > 0 ? formatBytes(Math.max(total_bytes - used, 0)) : "Unlimited";

  if (!expire_at || expire_at === 0) {
    return {
      trafficLeft,
      daysLeft: "Unlimited",
      expires: "Never",
    };
  }

  const now = Math.floor(Date.now() / 1000);
  const days = Math.max(Math.ceil((expire_at - now) / 86400), 0);
  return {
    trafficLeft,
    daysLeft: String(days),
    expires: new Date(expire_at * 1000).toLocaleDateString(),
  };
}
