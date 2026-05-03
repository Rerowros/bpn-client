import {
  Activity,
  AlertTriangle,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  CirclePause,
  Download,
  ExternalLink,
  Gauge,
  History,
  LifeBuoy,
  ListTree,
  PanelLeftClose,
  PanelLeftOpen,
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
import { AppNotification, NotificationCenter, NotificationTone } from "./ui/NotificationCenter";
import {
  AgentState,
  AppSettings,
  AgentServiceStatus,
  ComponentUpdate,
  ConnectionPath,
  ConnectionsSnapshot,
  PolicySummaryResponse,
  ProxyCatalog,
  ProxyGroupView,
  ProxyNodeView,
  RuntimeDiagnosticsReport,
  SubscriptionProfilesState,
  TrackedConnection,
  ZapretServiceStatus,
  addSubscriptionProfile,
  checkComponentUpdates,
  clearClosedConnections,
  closeAllConnections,
  closeConnection,
  getConnectionsSnapshot,
  getPolicySummary,
  getProxyCatalog,
  getSettings,
  getStatus,
  getSubscriptionProfiles,
  getAgentServiceStatus,
  getZapretServiceStatus,
  installAgentService,
  removeAgentService,
  removeSubscriptionProfile,
  refreshSubscription,
  restartConnection,
  runDiagnostics,
  resetSettings,
  saveSettings,
  selectProxy,
  selectSubscriptionProfile,
  setSubscription,
  startConnection,
  stopConnection,
  updateRuntimeComponents,
} from "./services/agentClient";
import { AppUpdateStatus, checkAppUpdate, installAppUpdate } from "./services/updateClient";

type AppView = "overview" | "connections" | "servers" | "policy" | "settings";
type ConnectionTab = "active" | "closed";
type ConnectionPathFilter = "all" | ConnectionPath;
type SettingsSection = "core" | "tun" | "zapret" | "updates";
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
  },
  dns: {
    mode: "fake-ip",
    preset: "cloudflare_google",
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
  const [connectionsBusy, setConnectionsBusy] = useState(false);
  const [catalog, setCatalog] = useState<ProxyCatalog | null>(null);
  const [lastCatalogError, setLastCatalogError] = useState<string | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [runtimeDiagnostics, setRuntimeDiagnostics] = useState<RuntimeDiagnosticsReport | null>(null);
  const [diagnosticBusy, setDiagnosticBusy] = useState(false);
  const [policySummary, setPolicySummary] = useState<PolicySummaryResponse | null>(null);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [agentService, setAgentService] = useState<AgentServiceStatus | null>(null);
  const [agentServiceBusy, setAgentServiceBusy] = useState(false);
  const [zapretService, setZapretService] = useState<ZapretServiceStatus | null>(null);
  const [zapretServiceBusy, setZapretServiceBusy] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("core");
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [settingsRestartRequired, setSettingsRestartRequired] = useState(false);
  const [lastConnectionsError, setLastConnectionsError] = useState<string | null>(null);

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
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => void runAction(() => getStatus(), false), 5000);
    return () => window.clearInterval(timer);
  }, []);

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
    if (view !== "connections") {
      return;
    }
    void refreshConnections(false);
    const timer = window.setInterval(() => void refreshConnections(false), 2500);
    return () => window.clearInterval(timer);
  }, [view]);

  useEffect(() => {
    if (view === "servers") {
      void refreshCatalog(false);
    }
    if (view === "policy") {
      void refreshPolicySummary(false);
    }
  }, [view]);

  useEffect(() => {
    if (!catalog?.groups.length) {
      setSelectedGroup(null);
      return;
    }
    setSelectedGroup((current) => current ?? catalog.groups[0].name);
  }, [catalog]);

  const hasSubscription =
    state.subscription.is_valid !== false &&
    (state.subscription.node_count > 0 ||
      state.subscription.format !== "unknown" ||
      Boolean(state.subscription.profile_title));
  const isOnboarding = !hasSubscription || state.phase === "onboarding";
  const quota = getQuota(state);
  const supportUrl = state.subscription.support_url;
  const announceUrl = state.subscription.announce_url || state.subscription.profile_web_page_url;
  const isRuntimeTransitioning = state.connection.status === "starting" || state.connection.status === "stopping";
  const isConnected = state.connection.connected && state.connection.status === "running";
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
      pushNotification({ tone: "success", title: "Agent service updated", message: status.message });
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
          refresh: () => void refreshConnections(),
          closeOne: (id) => void handleCloseConnection(id),
          closeAll: () => void handleCloseAllConnections(),
          clearClosed: () => void handleClearClosedConnections(),
          busy: connectionsBusy,
        });
      case "servers":
        return renderServersPage({
          catalog,
          selectedGroup,
          setSelectedGroup,
          refresh: () => void refreshCatalog(),
          select: (group, proxy) => void handleSelectProxy(group, proxy),
          busy: catalogBusy,
        });
      case "policy":
        return renderPolicyPage({
          policySummary,
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
          subscriptionProfiles,
          profileUrl,
          agentService,
          zapretService,
          settingsRestartRequired,
          updateBusy,
          diagnosticBusy,
          profilesBusy,
          agentServiceBusy,
          zapretServiceBusy,
          settingsBusy,
          busy,
          setSettingsSection,
          updateSettings,
          resetSettings: () => void handleResetSettings(),
          applySettingsRestart: () => void handleApplySettingsRestart(),
          refreshSubscription: () => void handleRefreshSubscription(),
          checkUpdates: () => void handleCheckUpdates(),
          installUpdate: () => void handleInstallAppUpdate(),
          updateRuntime: () => void handleRuntimeUpdate(),
          setProfileUrl,
          addSubscriptionProfile: () => void handleAddSubscriptionProfile(),
          selectSubscriptionProfile: (id) => void handleSelectSubscriptionProfile(id),
          removeSubscriptionProfile: (id) => void handleRemoveSubscriptionProfile(id),
          runDiagnostics: () => void handleRunDiagnostics(),
          refreshAgentService: () => void refreshAgentService(),
          installAgentService: () => void handleInstallAgentService(),
          removeAgentService: () => void handleRemoveAgentService(),
          refreshZapretService: () => void refreshZapretService(),
        });
      default:
        return renderOverview();
    }
  }

  function renderOverview() {
    return (
      <div className={isOnboarding ? "workspace setupMode" : "workspace"}>
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
                <span className="inlineError">{state.subscription.validation_error}</span>
              ) : null}
            </form>
          </section>
        ) : (
          <section className="connectionPane">
            {state.subscription.announce ? (
              <div className="announceLine">
                <Bell size={16} aria-hidden="true" />
                <span>{state.subscription.announce}</span>
                {announceUrl ? (
                  <a href={announceUrl} target="_blank" rel="noreferrer" title="Open">
                    <ExternalLink size={14} aria-hidden="true" />
                  </a>
                ) : null}
              </div>
            ) : null}

            <div className="connectCenter">
              <span className="modeText">{formatRouteMode(state.connection.route_mode)}</span>
              <button
                className={isConnected ? "connectButton connected" : isRuntimeTransitioning ? "connectButton pending" : "connectButton"}
                type="button"
                onClick={() => void runAction(isConnected ? stopConnection : startConnection)}
                disabled={busy || isRuntimeTransitioning}
                aria-label={isConnected ? "Disconnect" : "Connect"}
              >
                {isRuntimeTransitioning ? <RefreshCw size={46} /> : isConnected ? <CirclePause size={48} /> : <Power size={48} />}
              </button>
              <strong>{statusLabel}</strong>
            </div>

            <div className="meterGrid">
              <Metric icon={<Upload size={15} />} label="Up" value={formatBytes(state.metrics.upload_bytes)} />
              <Metric icon={<Download size={15} />} label="Down" value={formatBytes(state.metrics.download_bytes)} />
              <Metric icon={<Wifi size={15} />} label="Traffic left" value={quota.trafficLeft} />
              <Metric icon={<Shield size={15} />} label="Expires" value={quota.expires} />
            </div>
          </section>
        )}

        <aside className="inspector">
          <Panel title="Runtime">
            <StatusRow label="Mihomo" value={state.running ? "Owned process" : "Stopped"} good={state.running} />
            <StatusRow
              label="zapret"
              value={state.diagnostics.zapret_healthy ? "Running" : "Standby"}
              good={state.diagnostics.zapret_healthy}
            />
            <p className="diagnosticText">{state.diagnostics.message ?? "No diagnostics yet."}</p>
          </Panel>

          <Panel title="Subscription">
            {hasSubscription ? (
              <>
                <StatusRow label="Nodes" value={String(state.subscription.node_count)} good />
                <StatusRow label="Format" value={formatRouteMode(state.subscription.format)} />
                <StatusRow label="Refresh" value={formatRefreshInterval(state.subscription.update_interval_hours)} />
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
            <StatusRow label="VPN" value="MATCH -> PROXY" good={hasSubscription} />
            <StatusRow label="zapret" value="Discord/YouTube DIRECT" good={state.diagnostics.zapret_healthy} />
            <p className="diagnosticText">Connections page explains how each active flow is routed.</p>
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
        <span className={isConnected ? "railLed on" : "railLed"} />
      </aside>

      <section className="appPane">
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
  refresh,
  closeOne,
  closeAll,
  clearClosed,
  busy,
}: {
  connections: ConnectionsSnapshot | null;
  connectionTab: ConnectionTab;
  setConnectionTab: (tab: ConnectionTab) => void;
  connectionPathFilter: ConnectionPathFilter;
  setConnectionPathFilter: (filter: ConnectionPathFilter) => void;
  refresh: () => void;
  closeOne: (id: string) => void;
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
  const visibleRows = connectionPathFilter === "all" ? rows : rows.filter((connection) => connection.path === connectionPathFilter);

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
        </div>

        <div className="connectionList">
          {rows.length === 0 ? (
            <EmptyList icon={<Activity size={24} />} title="No connections" text="Start the VPN and open an app to see live routes here." />
          ) : visibleRows.length === 0 ? (
            <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching connections" text="Change the route filter to show hidden flows." />
          ) : (
            visibleRows.map((connection) => (
              <ConnectionRow key={`${connection.state}-${connection.id}-${connection.closed_at ?? "open"}`} connection={connection} closeOne={closeOne} />
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
  refresh,
  select,
  busy,
}: {
  catalog: ProxyCatalog | null;
  selectedGroup: string | null;
  setSelectedGroup: (group: string) => void;
  refresh: () => void;
  select: (group: string, proxy: string) => void;
  busy: boolean;
}) {
  const groups = catalog?.groups ?? [];
  const activeGroup = groups.find((group) => group.name === selectedGroup) ?? groups[0] ?? null;

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

        {groups.length === 0 ? (
          <EmptyList icon={<Server size={24} />} title="No server groups" text="Import a valid subscription to view Mihomo groups." />
        ) : (
          <div className="serverGrid">
            <div className="groupList">
              {groups.map((group) => (
                <GroupButton key={group.name} group={group} active={activeGroup?.name === group.name} onClick={() => setSelectedGroup(group.name)} />
              ))}
            </div>
            <div className="nodeList">
              <div className="nodeHeader">
                <div>
                  <strong>{activeGroup?.name}</strong>
                  <span>{activeGroup?.group_type} group</span>
                </div>
                <span>{activeGroup?.selected ? `Selected: ${activeGroup.selected}` : "No runtime selection"}</span>
              </div>
              {activeGroup?.nodes.map((node) => (
                <NodeRow key={node.name} group={activeGroup.name} node={node} busy={busy} select={select} />
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function renderPolicyPage({
  policySummary,
  refresh,
  busy,
}: {
  policySummary: PolicySummaryResponse | null;
  refresh: () => void;
  busy: boolean;
}) {
  const policy = policySummary;
  const notAvailable = !policy || !policy.available;

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
              <div className="policySection">
                <h2>Policy rules <span className="policyCount">{policy.policy_rules.length}</span></h2>
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
                      </tr>
                    </thead>
                    <tbody>
                      {policy.policy_rules.map((rule, index) => (
                        <tr key={index} className={policyPathTone(rule.path)}>
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
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.suppressed_rules.length > 0 ? (
              <div className="policySection">
                <h2>Suppressed rules <span className="policyCount">{policy.suppressed_rules.length}</span></h2>
                <div className="policyTableWrap">
                  <table className="policyTable" id="policy-suppressed-table">
                    <thead>
                      <tr>
                        <th>Original rule</th>
                        <th>Chosen rule</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.suppressed_rules.map((rule, index) => (
                        <tr key={index}>
                          <td className="mono wrap">{rule.original_rule}</td>
                          <td className="mono wrap">{rule.chosen_rule}</td>
                          <td>{rule.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.mihomo_rules.length > 0 ? (
              <div className="policySection">
                <h2>Mihomo rules <span className="policyCount">{policy.mihomo_rules.length}</span></h2>
                <div className="policyRuleList" id="policy-mihomo-rules">
                  {policy.mihomo_rules.map((rule, index) => (
                    <div key={index} className="policyRuleLine">
                      <span className="policyRuleIndex">{index + 1}</span>
                      <code>{rule}</code>
                    </div>
                  ))}
                </div>
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

function policyPathTone(path: string): string {
  if (path.startsWith("VpnProxy")) return "vpn";
  if (path === "ZapretDirect") return "zapret";
  if (path === "Reject") return "reject";
  return "direct";
}

function renderSettingsPage({
  state,
  hasSubscription,
  settings,
  settingsSection,
  appUpdate,
  componentUpdates,
  runtimeDiagnostics,
  subscriptionProfiles,
  profileUrl,
  agentService,
  zapretService,
  settingsRestartRequired,
  updateBusy,
  diagnosticBusy,
  profilesBusy,
  agentServiceBusy,
  zapretServiceBusy,
  settingsBusy,
  busy,
  setSettingsSection,
  updateSettings,
  resetSettings,
  applySettingsRestart,
  refreshSubscription,
  checkUpdates,
  installUpdate,
  updateRuntime,
  setProfileUrl,
  addSubscriptionProfile,
  selectSubscriptionProfile,
  removeSubscriptionProfile,
  runDiagnostics,
  refreshAgentService,
  installAgentService,
  removeAgentService,
  refreshZapretService,
}: {
  state: AgentState;
  hasSubscription: boolean;
  settings: AppSettings;
  settingsSection: SettingsSection;
  appUpdate: AppUpdateStatus;
  componentUpdates: ComponentUpdate[];
  runtimeDiagnostics: RuntimeDiagnosticsReport | null;
  subscriptionProfiles: SubscriptionProfilesState;
  profileUrl: string;
  agentService: AgentServiceStatus | null;
  zapretService: ZapretServiceStatus | null;
  settingsRestartRequired: boolean;
  updateBusy: boolean;
  diagnosticBusy: boolean;
  profilesBusy: boolean;
  agentServiceBusy: boolean;
  zapretServiceBusy: boolean;
  settingsBusy: boolean;
  busy: boolean;
  setSettingsSection: (section: SettingsSection) => void;
  updateSettings: (settings: AppSettings) => void;
  resetSettings: () => void;
  applySettingsRestart: () => void;
  refreshSubscription: () => void;
  checkUpdates: () => void;
  installUpdate: () => void;
  updateRuntime: () => void;
  setProfileUrl: (value: string) => void;
  addSubscriptionProfile: () => void;
  selectSubscriptionProfile: (id: string) => void;
  removeSubscriptionProfile: (id: string) => void;
  runDiagnostics: () => void;
  refreshAgentService: () => void;
  installAgentService: () => void;
  removeAgentService: () => void;
  refreshZapretService: () => void;
}) {
  const updateCore = (patch: Partial<AppSettings["core"]>) =>
    updateSettings({ ...settings, core: { ...settings.core, ...patch } });
  const updateTun = (patch: Partial<AppSettings["tun"]>) =>
    updateSettings({ ...settings, tun: { ...settings.tun, ...patch } });
  const updateDns = (patch: Partial<AppSettings["dns"]>) =>
    updateSettings({ ...settings, dns: { ...settings.dns, ...patch } });
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

  return (
    <div className="workspace pageWorkspace">
      <section className="settingsShell">
        <div className="settingsSide">
          <SettingsTab active={settingsSection === "core"} icon={<SlidersHorizontal size={16} />} label="Core" onClick={() => setSettingsSection("core")} />
          <SettingsTab active={settingsSection === "tun"} icon={<Router size={16} />} label="TUN & DNS" onClick={() => setSettingsSection("tun")} />
          <SettingsTab active={settingsSection === "zapret"} icon={<Zap size={16} />} label="zapret" onClick={() => setSettingsSection("zapret")} />
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

          {settingsSection === "core" ? (
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
                    ? "Умный режим для РФ: YouTube, Discord и игры идут напрямую через zapret, AI, соцсети и VPN-правила идут через выбранные VPN-группы, остальное напрямую."
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

          {settingsSection === "tun" ? (
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
              </Panel>
            </section>
          ) : null}

          {settingsSection === "zapret" ? (
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
                <TextAreaField
                  label="Force VPN"
                  value={listToText(settings.routing_policy.force_vpn_domains)}
                  disabled={settingsBusy}
                  onChange={(value) => updateRoutingPolicy({ force_vpn_domains: textToList(value) })}
                />
                <TextAreaField
                  label="Force Zapret"
                  value={listToText(settings.routing_policy.force_zapret_domains)}
                  disabled={settingsBusy || settings.core.route_mode !== "smart"}
                  onChange={(value) => updateRoutingPolicy({ force_zapret_domains: textToList(value) })}
                />
                <TextAreaField
                  label="Force DIRECT"
                  value={listToText(settings.routing_policy.force_direct_domains)}
                  disabled={settingsBusy}
                  onChange={(value) => updateRoutingPolicy({ force_direct_domains: textToList(value) })}
                />
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

          {settingsSection === "updates" ? (
            <section className="settingsPanels">
              <Panel title="Subscription">
                {hasSubscription ? (
                  <>
                    <StatusRow label="Active" value={state.subscription.profile_title ?? "Subscription"} good />
                    <StatusRow label="Nodes" value={String(state.subscription.node_count)} good />
                    <StatusRow label="Format" value={formatRouteMode(state.subscription.format)} />
                    <StatusRow label="Refresh" value={formatRefreshInterval(state.subscription.update_interval_hours)} />
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
                </div>
                <div className="profileList">
                  {subscriptionProfiles.profiles.length ? (
                    subscriptionProfiles.profiles.map((profile) => (
                      <div key={profile.id} className={profile.active ? "profileRow active" : "profileRow"}>
                        <div>
                          <strong>{profile.name}</strong>
                          <span>{profile.redacted_url ?? formatRouteMode(profile.subscription.format)}</span>
                        </div>
                        <span>{profile.subscription.node_count} nodes</span>
                        <button className="subtleButton" type="button" onClick={() => selectSubscriptionProfile(profile.id)} disabled={profilesBusy || profile.active}>
                          {profile.active ? "Active" : "Select"}
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
  disabled,
  onChange,
}: {
  label: string;
  value: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}) {
  return (
    <label className="selectField">
      <span>{label}</span>
      <input
        type="number"
        min={1}
        max={65535}
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

function ConnectionRow({ connection, closeOne }: { connection: TrackedConnection; closeOne: (id: string) => void }) {
  const isActive = connection.state === "active";
  return (
    <div className="connectionRow">
      <div className="connectionMain">
        <PathBadge path={connection.path} label={connection.path_label} />
        <div>
          <strong>{connection.host || connection.destination}</strong>
          <span>{connection.destination}</span>
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
      <div className="connectionTail">
        <span>{connection.rule ?? "rule unknown"}{connection.rule_payload ? ` / ${connection.rule_payload}` : ""}</span>
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

function GroupButton({ group, active, onClick }: { group: ProxyGroupView; active: boolean; onClick: () => void }) {
  return (
    <button className={active ? "groupButton active" : "groupButton"} type="button" onClick={onClick}>
      <span>{group.name}</span>
      <strong>{group.selected ?? `${group.nodes.length} nodes`}</strong>
    </button>
  );
}

function NodeRow({ group, node, busy, select }: { group: string; node: ProxyNodeView; busy: boolean; select: (group: string, proxy: string) => void }) {
  return (
    <div className={node.selected ? "nodeRow selected" : "nodeRow"}>
      <div>
        <strong>{node.name}</strong>
        <span>{node.proxy_type ?? "proxy"}{node.server ? ` / ${node.server}` : ""}</span>
      </div>
      <div className="nodeMeta">
        <span>{node.delay_ms ? `${node.delay_ms} ms` : "No ping"}</span>
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
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function formatRefreshInterval(hours: number | null) {
  if (!hours) {
    return "Manual";
  }
  return `${hours} h`;
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
