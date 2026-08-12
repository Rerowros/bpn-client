use crate::settings::{
    read_settings_from_path, settings_require_restart, write_settings_to_path, AppSettings,
    ZapretGameFilter, ZapretIpSetFilter, ZapretRunMode, ZapretStrategy,
};
use badvpn_common::{
    classify_subscription_failure, decode_header_value, flowseal_exclude_hostlist,
    flowseal_general_hostlist, flowseal_google_hostlist, flowseal_ipset_exclude,
    generate_mihomo_config_from_subscription_with_options, geodata_asset_exists,
    overlay_mihomo_config_yaml, parse_subscription_userinfo, strip_missing_geodata_rules,
    summarize_subscription_body, zapret_default_hostlist, zapret_default_ipset,
    zapret_user_placeholder_hostlist, AgentCommand, AgentState, AppPhase, CompiledPolicy,
    ConnectRequest, ConnectionStatus, DiagnosticSummary, MihomoConfigOptions, RouteMode,
    RuntimeDiagnosticsSettings, RuntimeGameProfile, RuntimeMode, RuntimeSettings,
    RuntimeZapretSettings, SubscriptionFormat, SubscriptionState, AGENT_LOCAL_ADDR,
    AGENT_PIPE_NAME,
};
use base64::{engine::general_purpose, Engine};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;
use zip::ZipArchive;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const FLOWSEAL_IPSET_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt";
const FLOWSEAL_VERSION_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/version.txt";
const FLOWSEAL_LIST_GENERAL_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/lists/list-general.txt";
const FLOWSEAL_LIST_GOOGLE_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/lists/list-google.txt";
const FLOWSEAL_LIST_EXCLUDE_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/lists/list-exclude.txt";
const FLOWSEAL_IPSET_EXCLUDE_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/lists/ipset-exclude.txt";
const FLOWSEAL_IPSET_MAX_AGE_SECONDS: u64 = 60 * 60 * 24;
const MIHOMO_READY_TIMEOUT: Duration = Duration::from_secs(12);
const MIHOMO_REPO: &str = "MetaCubeX/mihomo";
const FLOWSEAL_ZAPRET_REPO: &str = "Flowseal/zapret-discord-youtube";
const BADVPN_AGENT_SERVICE: &str = "badvpn-agent";
const BADVPN_ZAPRET_SERVICE: &str = "BadVpnZapret";
const SUBSCRIPTION_USER_AGENT: &str = "mihomo/1.19.24 BadVpn/0.1.0";

static STATE: OnceLock<Mutex<AgentState>> = OnceLock::new();
static MIHOMO_PROCESS: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
static ZAPRET_PROCESS: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
static AGENT_PROCESS: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
static RUNTIME_OPERATION: OnceLock<AsyncMutex<()>> = OnceLock::new();
static LAST_ACTIVE_CONNECTIONS: OnceLock<Mutex<Vec<TrackedConnection>>> = OnceLock::new();
static CLOSED_CONNECTIONS: OnceLock<Mutex<Vec<TrackedConnection>>> = OnceLock::new();
static LAST_LIST_REFRESH_ATTEMPT: OnceLock<Mutex<u64>> = OnceLock::new();
static LAST_MIHOMO_HEALTHY_AT: OnceLock<Mutex<u64>> = OnceLock::new();
static LAST_PREVIEW_POLICY: OnceLock<Mutex<Option<CompiledPolicy>>> = OnceLock::new();
static APP_STARTED_AT: OnceLock<u64> = OnceLock::new();

fn state() -> &'static Mutex<AgentState> {
    let _ = app_started_at();
    STATE.get_or_init(|| Mutex::new(AgentState::default()))
}

fn app_started_at() -> u64 {
    *APP_STARTED_AT.get_or_init(current_unix_timestamp)
}

fn mihomo_process() -> &'static Mutex<Option<Child>> {
    MIHOMO_PROCESS.get_or_init(|| Mutex::new(None))
}

fn zapret_process() -> &'static Mutex<Option<Child>> {
    ZAPRET_PROCESS.get_or_init(|| Mutex::new(None))
}

fn agent_process() -> &'static Mutex<Option<Child>> {
    AGENT_PROCESS.get_or_init(|| Mutex::new(None))
}

fn runtime_operation() -> &'static AsyncMutex<()> {
    RUNTIME_OPERATION.get_or_init(|| AsyncMutex::new(()))
}

fn last_active_connections() -> &'static Mutex<Vec<TrackedConnection>> {
    LAST_ACTIVE_CONNECTIONS.get_or_init(|| Mutex::new(Vec::new()))
}

fn closed_connections() -> &'static Mutex<Vec<TrackedConnection>> {
    CLOSED_CONNECTIONS.get_or_init(|| Mutex::new(Vec::new()))
}

fn last_list_refresh_attempt() -> &'static Mutex<u64> {
    LAST_LIST_REFRESH_ATTEMPT.get_or_init(|| Mutex::new(0))
}

fn last_mihomo_healthy_at() -> &'static Mutex<u64> {
    LAST_MIHOMO_HEALTHY_AT.get_or_init(|| Mutex::new(0))
}

fn last_preview_policy() -> &'static Mutex<Option<CompiledPolicy>> {
    LAST_PREVIEW_POLICY.get_or_init(|| Mutex::new(None))
}

fn store_preview_policy(policy: &CompiledPolicy) {
    if let Ok(mut guard) = last_preview_policy().lock() {
        *guard = Some(policy.clone());
    }
}

fn log_event(scope: &str, message: impl AsRef<str>) {
    let message = message.as_ref().replace(['\r', '\n'], " ");
    let line = format!("{} [{scope}] {message}\n", current_unix_timestamp());
    match app_log_path() {
        Ok(path) => {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = file.write_all(line.as_bytes());
            }
        }
        Err(_) => {
            eprintln!("{line}");
        }
    }
}

#[derive(Debug, Deserialize)]
struct AgentWireResponse {
    ok: bool,
    state: Option<AgentState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_summary: Option<badvpn_common::ipc::PolicySummaryResponse>,
    error: Option<String>,
}

#[tauri::command]
pub async fn status() -> Result<AgentState, String> {
    log_event("status", "refresh requested");
    if should_use_agent_runtime() {
        match send_agent_command(AgentCommand::RuntimeStatus, false) {
            Ok(agent_state) => return apply_agent_state(agent_state),
            Err(error) => return apply_agent_unreachable_state(error),
        }
    }
    refresh_runtime_state(false).await
}

#[tauri::command]
pub async fn start() -> Result<AgentState, String> {
    let _guard = runtime_operation().lock().await;
    start_inner().await
}

async fn start_inner() -> Result<AgentState, String> {
    log_event("start", "connect requested");
    hydrate_persisted_state()?;
    let config_path = mihomo_config_path()?;
    let settings = load_app_settings();
    settings.validate()?;
    if should_use_agent_runtime() {
        return start_via_agent(&settings).await;
    }
    let requested_route_mode = settings.effective_route_mode();
    log_event(
        "start",
        format!(
            "settings route={:?} effective={:?} zapret_enabled={} zapret_run_mode={:?} strategy={:?} game_filter={:?} ipset_filter={:?}",
            settings.core.route_mode,
            requested_route_mode,
            settings.zapret.enabled,
            settings.zapret.run_mode,
            settings.zapret.strategy,
            settings.zapret.game_filter,
            settings.zapret.ipset_filter
        ),
    );

    if child_is_running(mihomo_process()).unwrap_or(false) || recorded_mihomo_is_running() {
        if fetch_mihomo_version().await.is_ok() {
            let mut state = state()
                .lock()
                .map_err(|_| "agent state lock is poisoned".to_string())?;
            state.running = true;
            state.phase = AppPhase::Connected;
            state.connection.connected = true;
            state.connection.status = ConnectionStatus::Running;
            state.diagnostics.message = Some("BadVpn-owned Mihomo is already running.".to_string());
            log_event(
                "start",
                "ignored duplicate connect; owned Mihomo is already running",
            );
            return Ok(state.clone());
        }
        log_event(
            "start",
            "owned Mihomo child exists but controller is not ready; stopping stale child before restart",
        );
        stop_child(mihomo_process())?;
        clear_mihomo_pid_file();
    }

    {
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        if matches!(
            state.connection.status,
            ConnectionStatus::Starting | ConnectionStatus::Stopping
        ) {
            log_event(
                "start",
                "ignored duplicate connect while transition is in progress",
            );
            return Ok(state.clone());
        }
        state.phase = AppPhase::Connecting;
        state.connection.status = ConnectionStatus::Starting;
        state.connection.connected = false;
        state.running = false;
        state.diagnostics.message = Some("Starting Mihomo and route services...".to_string());
        state.last_error = None;
    }

    if !config_path.exists() {
        log_event("start", "missing Mihomo config; subscription is required");
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Ready;
        state.connection.status = ConnectionStatus::Error;
        state.last_error = Some("Import a subscription before connecting.".to_string());
        return Ok(state.clone());
    }

    if resolve_mihomo_bin().is_err() || zapret_runtime_assets_ready().is_err() {
        if let Err(error) = install_components(false).await {
            log_event("start", format!("component install failed: {error}"));
            let mut state = state()
                .lock()
                .map_err(|_| "agent state lock is poisoned".to_string())?;
            state.phase = AppPhase::Ready;
            state.connection.status = ConnectionStatus::Error;
            state.diagnostics = DiagnosticSummary {
                mihomo_healthy: false,
                zapret_healthy: false,
                message: Some(error.clone()),
            };
            state.last_error = Some(error);
            return Ok(state.clone());
        }
    }

    let zapret_prepare_status = if requested_route_mode == RouteMode::Smart {
        if settings.updates.auto_flowseal_list_refresh {
            let result = ensure_zapret_runtime_lists().await;
            if let Err(error) = &result {
                log_event("zapret", format!("list preparation failed: {error}"));
            }
            result.err()
        } else {
            let result = write_zapret_lists();
            if let Err(error) = &result {
                log_event("zapret", format!("static list write failed: {error}"));
            }
            result.err()
        }
    } else {
        None
    };

    let mihomo_bin = match resolve_mihomo_bin() {
        Ok(path) => path,
        Err(error) => {
            log_event("start", format!("missing Mihomo binary: {error}"));
            let mut state = state()
                .lock()
                .map_err(|_| "agent state lock is poisoned".to_string())?;
            state.phase = AppPhase::Ready;
            state.connection.status = ConnectionStatus::Error;
            state.diagnostics = DiagnosticSummary {
                mihomo_healthy: false,
                zapret_healthy: false,
                message: Some(error.clone()),
            };
            state.last_error = Some(error);
            return Ok(state.clone());
        }
    };

    let (mut zapret_status, route_mode) = if requested_route_mode == RouteMode::Smart {
        match start_zapret_process(&settings) {
            Ok(status) => (status, RouteMode::Smart),
            Err(error) => {
                log_event(
                    "zapret",
                    format!("pre-start failed: {error}; using VPN fallback before Mihomo start"),
                );
                (
                    format!("{error}; using VPN fallback before enabling DIRECT rules"),
                    RouteMode::VpnOnly,
                )
            }
        }
    } else {
        stop_child(zapret_process())?;
        (
            "VPN Only active; zapret is not started for this route mode.".to_string(),
            RouteMode::VpnOnly,
        )
    };

    ensure_mihomo_config_routing(&config_path, &settings, route_mode)?;
    log_event(
        "mihomo",
        format!(
            "config routing patched at {} for route={route_mode:?}",
            config_path.display()
        ),
    );

    stop_recorded_mihomo_pid()?;
    clear_mihomo_pid_file();

    if let Some(message) = occupied_mihomo_ports_hint() {
        log_event(
            "start",
            format!("blocked by occupied Mihomo ports: {message}"),
        );
        if settings.zapret.run_mode == ZapretRunMode::Process {
            let _ = stop_child(zapret_process());
        }
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Ready;
        state.connection.status = ConnectionStatus::Error;
        state.diagnostics = DiagnosticSummary {
            mihomo_healthy: false,
            zapret_healthy: false,
            message: Some(format!(
                "{message} BadVpn also could not reload the existing Mihomo controller."
            )),
        };
        state.last_error = Some(message);
        return Ok(state.clone());
    }

    start_mihomo_process(&mihomo_bin, &config_path)?;
    if let Err(error) = wait_for_mihomo_ready(MIHOMO_READY_TIMEOUT).await {
        log_event("mihomo", format!("controller readiness failed: {error}"));
        let _ = stop_child(mihomo_process());
        clear_mihomo_pid_file();
        if settings.zapret.run_mode == ZapretRunMode::Process {
            let _ = stop_child(zapret_process());
        }
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Ready;
        state.connection.status = ConnectionStatus::Error;
        state.connection.connected = false;
        state.running = false;
        state.diagnostics = DiagnosticSummary {
            mihomo_healthy: false,
            zapret_healthy: false,
            message: Some(error.clone()),
        };
        state.last_error = Some(error);
        return Ok(state.clone());
    }
    if let Some(warning) = zapret_prepare_status {
        zapret_status = format!("{zapret_status}; {warning}");
    }

    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;

    state.installed = false;
    state.running = true;
    state.phase = AppPhase::Connected;
    state.connection.connected = true;
    state.connection.status = ConnectionStatus::Running;
    state.connection.route_mode = route_mode;
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: true,
        zapret_healthy: route_mode == RouteMode::Smart
            && zapret_status.starts_with("zapret running"),
        message: Some(zapret_status),
    };
    state.last_error = None;
    log_event(
        "start",
        format!(
            "connected route={:?} zapret_healthy={} message={}",
            state.connection.route_mode,
            state.diagnostics.zapret_healthy,
            state.diagnostics.message.clone().unwrap_or_default()
        ),
    );
    Ok(state.clone())
}

#[tauri::command]
pub async fn stop() -> Result<AgentState, String> {
    let _guard = runtime_operation().lock().await;
    stop_inner()
}

fn stop_inner() -> Result<AgentState, String> {
    log_event("stop", "disconnect requested");
    if should_use_agent_runtime() {
        match send_agent_command(AgentCommand::Stop, false) {
            Ok(agent_state) => return apply_agent_state(agent_state),
            Err(error) => log_event("agent", format!("stop via agent skipped/failed: {error}")),
        }
    }
    {
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Disconnecting;
        state.connection.status = ConnectionStatus::Stopping;
    }
    stop_child(mihomo_process())?;
    stop_recorded_mihomo_pid()?;
    clear_mihomo_pid_file();
    stop_child(zapret_process())?;

    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;

    state.running = false;
    state.phase = if state.subscription.url.is_some() {
        AppPhase::Ready
    } else {
        AppPhase::Onboarding
    };
    state.connection.connected = false;
    state.connection.status = ConnectionStatus::Idle;
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: false,
        zapret_healthy: false,
        message: Some("Stopped Mihomo and zapret processes owned by BadVpn.".to_string()),
    };
    state.last_error = None;
    Ok(state.clone())
}

#[tauri::command]
pub async fn restart() -> Result<AgentState, String> {
    let _guard = runtime_operation().lock().await;
    if should_use_agent_runtime() {
        let _ = send_agent_command(AgentCommand::Stop, false)
            .map_err(|error| log_event("agent", format!("restart stop failed/skipped: {error}")));
        return start_inner().await;
    }
    stop_inner()?;
    start_inner().await
}

async fn start_via_agent(settings: &AppSettings) -> Result<AgentState, String> {
    let request = build_agent_connect_request(settings).await?;
    ensure_agent_runtime_components(settings).await?;
    let agent_state = send_agent_command(
        AgentCommand::Connect {
            request: Box::new(request),
        },
        true,
    )?;
    apply_agent_state(agent_state)
}

async fn build_agent_connect_request(settings: &AppSettings) -> Result<ConnectRequest, String> {
    let subscription = active_persisted_subscription_profile()
        .or_else(|| read_persisted_subscription_state())
        .or_else(|| {
            state()
                .lock()
                .ok()
                .and_then(|state| Some(state.subscription.clone()))
        })
        .filter(subscription_is_present)
        .ok_or_else(|| "Import a subscription before connecting.".to_string())?;
    let imported = if let Some(url) = subscription.url.as_deref() {
        match fetch_active_subscription_profile(url).await {
            Ok(imported) => imported,
            Err(error) => {
                let log_reason = subscription_fetch_log_reason(&error);
                if let Some(body) = active_persisted_subscription_profile_body() {
                    log_event(
                        "subscription",
                        format!(
                            "using cached subscription profile for connect because live fetch failed: {log_reason}"
                        ),
                    );
                    ImportedSubscription {
                        subscription: subscription.clone(),
                        body,
                    }
                } else if let Some(body) = existing_mihomo_config_profile_body() {
                    log_event(
                        "subscription",
                        format!(
                            "using existing Mihomo config for connect because live fetch failed: {log_reason}"
                        ),
                    );
                    ImportedSubscription {
                        subscription: subscription.clone(),
                        body,
                    }
                } else {
                    return Err(format!(
                        "Failed to fetch subscription and no cached profile body or local Mihomo config is available: {error}"
                    ));
                }
            }
        }
    } else if let Some(body) = active_persisted_subscription_profile_body() {
        ImportedSubscription {
            subscription: subscription.clone(),
            body,
        }
    } else if let Some(body) = existing_mihomo_config_profile_body() {
        ImportedSubscription {
            subscription: subscription.clone(),
            body,
        }
    } else {
        return Err(
            "Active local profile body is not available. Re-import the local profile.".to_string(),
        );
    };
    persist_subscription_state_with_body(&imported.subscription, Some(&imported.body))?;

    let route_mode = settings.effective_route_mode();
    let mut mihomo = mihomo_options_for_runtime_route(settings, route_mode);
    mihomo.selected_proxies = read_proxy_selections().unwrap_or_default();
    let runtime_mode = RuntimeMode::from(mihomo.route_mode);

    Ok(ConnectRequest {
        profile_body: imported.body,
        subscription: imported.subscription,
        selected_proxies: mihomo.selected_proxies.clone(),
        route_mode: runtime_mode,
        settings: RuntimeSettings {
            mihomo,
            zapret: RuntimeZapretSettings {
                enabled: settings.zapret.enabled,
                strategy: format_zapret_strategy(settings.zapret.strategy).to_string(),
                game_filter: format_game_filter(settings.zapret.game_filter).to_string(),
                game_bypass_mode: format_game_bypass_mode(settings.zapret.game_bypass_mode)
                    .to_string(),
                game_filter_mode: format_game_filter_mode(settings.zapret.game_filter_mode)
                    .to_string(),
                active_game_profiles: Vec::new(),
                learned_game_profiles: settings
                    .zapret
                    .learned_game_profiles
                    .iter()
                    .map(runtime_game_profile_from_settings)
                    .collect(),
                ipset_filter: format_ipset_filter(settings.zapret.ipset_filter).to_string(),
                auto_profile_fallback: settings.zapret.auto_profile_fallback,
                fallback_to_vpn_on_failed_probe: settings.zapret.fallback_to_vpn_on_failed_probe,
            },
            diagnostics: RuntimeDiagnosticsSettings {
                runtime_checks_after_connect: settings.diagnostics.runtime_checks_after_connect,
                discord_youtube_probes: settings.diagnostics.discord_youtube_probes,
            },
        },
    })
}

fn subscription_fetch_log_reason(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("http ")
        || lower.contains("provider rejected")
        || lower.contains("server returned")
    {
        "provider rejected the refresh"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "request timed out"
    } else if lower.contains("connect") {
        "connection failed"
    } else if lower.contains("decode") || lower.contains("format") {
        "invalid response format"
    } else {
        "refresh failed"
    }
}

fn apply_agent_state(agent_state: AgentState) -> Result<AgentState, String> {
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    let previous_subscription = state.subscription.clone();
    let mut next_state = agent_state;
    next_state.subscription =
        merged_subscription_for_ui(next_state.subscription, previous_subscription);
    if !next_state.running
        && matches!(next_state.phase, AppPhase::Init | AppPhase::Onboarding)
        && subscription_is_present(&next_state.subscription)
    {
        next_state.phase = AppPhase::Ready;
    }
    *state = next_state;
    Ok(state.clone())
}

fn apply_agent_unreachable_state(error: String) -> Result<AgentState, String> {
    let service = read_badvpn_agent_service_status();
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    let message = if service.installed {
        format!("badvpn-agent IPC failed: {error}")
    } else {
        "badvpn-agent is not installed; install or repair the service before connecting."
            .to_string()
    };
    state.installed = service.installed;
    state.running = false;
    state.connection.connected = false;
    state.connection.status = if service.installed {
        ConnectionStatus::Error
    } else {
        ConnectionStatus::Idle
    };
    state.phase = if service.installed {
        AppPhase::Error
    } else if subscription_is_present(&state.subscription) {
        AppPhase::Ready
    } else {
        AppPhase::Onboarding
    };
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: false,
        zapret_healthy: false,
        message: Some(message.clone()),
    };
    state.last_error = service.installed.then_some(message);
    Ok(state.clone())
}

fn should_use_agent_runtime() -> bool {
    // Release builds are service-first only. Legacy GUI-owned Mihomo/winws spawn
    // remains available in debug builds behind BADVPN_LEGACY_RUNTIME=1.
    #[cfg(not(debug_assertions))]
    {
        true
    }
    #[cfg(debug_assertions)]
    {
        std::env::var("BADVPN_LEGACY_RUNTIME").ok().as_deref() != Some("1")
    }
}

fn send_agent_command(command: AgentCommand, spawn_if_missing: bool) -> Result<AgentState, String> {
    if spawn_if_missing {
        ensure_agent_server()?;
    }
    match send_agent_pipe_command(&command) {
        Ok(state) => return Ok(state),
        Err(pipe_error) => {
            if std::env::var("BADVPN_AGENT_TCP_FALLBACK").ok().as_deref() != Some("1") {
                log_event(
                    "agent",
                    format!("named pipe IPC failed and TCP fallback is disabled: {pipe_error}"),
                );
                return Err(pipe_error);
            }
            log_event(
                "agent",
                format!("named pipe IPC failed; trying TCP fallback: {pipe_error}"),
            );
        }
    }
    send_agent_tcp_command(&command)
}

fn send_agent_tcp_command(command: &AgentCommand) -> Result<AgentState, String> {
    let mut stream = TcpStream::connect(AGENT_LOCAL_ADDR)
        .map_err(|error| format!("BadVpn agent is not reachable at {AGENT_LOCAL_ADDR}: {error}"))?;
    serde_json::to_writer(&mut stream, command)
        .map_err(|error| format!("Failed to serialize agent command: {error}"))?;
    stream
        .write_all(b"\n")
        .map_err(|error| format!("Failed to send agent command: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("Failed to flush agent command: {error}"))?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| format!("Failed to read agent response: {error}"))?;
    let response = serde_json::from_str::<AgentWireResponse>(&line)
        .map_err(|error| format!("Failed to parse agent response: {error}"))?;
    if response.ok {
        response
            .state
            .ok_or_else(|| "Agent returned an empty successful response.".to_string())
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Agent command failed.".to_string()))
    }
}

fn send_agent_tcp_command_raw(command: &AgentCommand) -> Result<AgentWireResponse, String> {
    let mut stream = TcpStream::connect(AGENT_LOCAL_ADDR)
        .map_err(|error| format!("BadVpn agent is not reachable at {AGENT_LOCAL_ADDR}: {error}"))?;
    serde_json::to_writer(&mut stream, command)
        .map_err(|error| format!("Failed to serialize agent command: {error}"))?;
    stream
        .write_all(b"\n")
        .map_err(|error| format!("Failed to send agent command: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("Failed to flush agent command: {error}"))?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| format!("Failed to read agent response: {error}"))?;
    serde_json::from_str::<AgentWireResponse>(&line)
        .map_err(|error| format!("Failed to parse agent response: {error}"))
}

#[cfg(windows)]
fn send_agent_pipe_command(command: &AgentCommand) -> Result<AgentState, String> {
    let mut data = serde_json::to_vec(command)
        .map_err(|error| format!("Failed to serialize agent command: {error}"))?;
    data.push(b'\n');
    let handle = open_agent_pipe(Duration::from_secs(4))?;
    let result = (|| {
        write_pipe_all(handle, &data)?;
        let line = read_pipe_line(handle)?;
        let response = serde_json::from_str::<AgentWireResponse>(&line)
            .map_err(|error| format!("Failed to parse agent response: {error}"))?;
        if response.ok {
            response
                .state
                .ok_or_else(|| "Agent returned an empty successful response.".to_string())
        } else {
            Err(response
                .error
                .unwrap_or_else(|| "Agent command failed.".to_string()))
        }
    })();
    unsafe {
        CloseHandle(handle);
    }
    result
}

#[cfg(windows)]
fn send_agent_pipe_command_raw(command: &AgentCommand) -> Result<AgentWireResponse, String> {
    let mut data = serde_json::to_vec(command)
        .map_err(|error| format!("Failed to serialize agent command: {error}"))?;
    data.push(b'\n');
    let handle = open_agent_pipe(Duration::from_secs(4))?;
    let result = (|| {
        write_pipe_all(handle, &data)?;
        let line = read_pipe_line(handle)?;
        serde_json::from_str::<AgentWireResponse>(&line)
            .map_err(|error| format!("Failed to parse agent response: {error}"))
    })();
    unsafe {
        CloseHandle(handle);
    }
    result
}

#[cfg(not(windows))]
fn send_agent_pipe_command(_command: &AgentCommand) -> Result<AgentState, String> {
    Err("BadVpn named pipe IPC is only available on Windows.".to_string())
}

#[cfg(not(windows))]
fn send_agent_pipe_command_raw(_command: &AgentCommand) -> Result<AgentWireResponse, String> {
    Err("BadVpn named pipe IPC is only available on Windows.".to_string())
}

#[cfg(windows)]
fn open_agent_pipe(timeout: Duration) -> Result<windows_sys::Win32::Foundation::HANDLE, String> {
    let started = SystemTime::now();
    let pipe_name = wide_null(AGENT_PIPE_NAME);
    loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(handle);
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_PIPE_BUSY {
            unsafe {
                let _ = WaitNamedPipeW(pipe_name.as_ptr(), 250);
            }
        } else if started.elapsed().map_or(true, |elapsed| elapsed >= timeout) {
            return Err(format!(
                "BadVpn agent named pipe is not reachable at {AGENT_PIPE_NAME}: {}",
                std::io::Error::last_os_error()
            ));
        } else {
            std::thread::sleep(Duration::from_millis(120));
        }
    }
}

#[cfg(windows)]
fn write_pipe_all(
    handle: windows_sys::Win32::Foundation::HANDLE,
    mut data: &[u8],
) -> Result<(), String> {
    while !data.is_empty() {
        let written = overlapped_pipe_io(
            handle,
            Duration::from_secs(30),
            "Timed out writing BadVpn agent named pipe request.",
            |overlapped, transferred| unsafe {
                WriteFile(
                    handle,
                    data.as_ptr(),
                    data.len().min(u32::MAX as usize) as u32,
                    transferred,
                    overlapped,
                )
            },
        )?;
        if written == 0 {
            return Err("BadVpn agent named pipe accepted zero request bytes.".to_string());
        }
        data = &data[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_pipe_line(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<String, String> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Timed out waiting for BadVpn agent named pipe response.".to_string());
        }
        let read = match overlapped_pipe_io(
            handle,
            remaining,
            "Timed out waiting for BadVpn agent named pipe response.",
            |overlapped, transferred| unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    transferred,
                    overlapped,
                )
            },
        ) {
            Ok(read) => read,
            Err(error) if error.contains("broken pipe") && !data.is_empty() => break,
            Err(error) => return Err(error),
        };
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read as usize]);
        if data.contains(&b'\n') {
            break;
        }
        if data.len() > 1024 * 1024 {
            return Err("Agent response exceeded maximum IPC frame size.".to_string());
        }
    }
    String::from_utf8(data)
        .map(|line| line.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|error| format!("Agent response was not valid UTF-8: {error}"))
}

#[cfg(windows)]
fn overlapped_pipe_io(
    handle: windows_sys::Win32::Foundation::HANDLE,
    timeout: Duration,
    timeout_message: &str,
    issue: impl FnOnce(*mut OVERLAPPED, *mut u32) -> i32,
) -> Result<u32, String> {
    let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(format!(
            "Failed to create named pipe I/O event: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let mut transferred = 0_u32;
        if issue(&mut overlapped, &mut transferred) != 0 {
            return Ok(transferred);
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            if error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA {
                return Err("BadVpn agent named pipe was closed (broken pipe).".to_string());
            }
            return Err(format!(
                "Failed to perform BadVpn agent named pipe I/O: {}",
                std::io::Error::from_raw_os_error(error as i32)
            ));
        }

        let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        match unsafe { WaitForSingleObject(event, timeout_ms) } {
            WAIT_OBJECT_0 => {
                if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0 {
                    let error = unsafe { GetLastError() };
                    if error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA {
                        return Err("BadVpn agent named pipe was closed (broken pipe).".to_string());
                    }
                    return Err(format!(
                        "Failed to complete BadVpn agent named pipe I/O: {}",
                        std::io::Error::from_raw_os_error(error as i32)
                    ));
                }
                Ok(transferred)
            }
            WAIT_TIMEOUT => {
                // Wait for cancellation completion before the OVERLAPPED/event/buffer leave scope.
                unsafe {
                    let _ = CancelIoEx(handle, &overlapped);
                    let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, 1);
                }
                Err(timeout_message.to_string())
            }
            wait_error => {
                unsafe {
                    let _ = CancelIoEx(handle, &overlapped);
                    let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, 1);
                }
                Err(format!(
                    "Named pipe I/O wait failed with status {wait_error}."
                ))
            }
        }
    })();
    unsafe {
        CloseHandle(event);
    }
    result
}

#[cfg(windows)]
fn agent_ipc_ready() -> bool {
    match open_agent_pipe(Duration::from_millis(250)) {
        Ok(handle) => {
            unsafe {
                CloseHandle(handle);
            }
            true
        }
        Err(_) if std::env::var("BADVPN_AGENT_TCP_FALLBACK").ok().as_deref() == Some("1") => {
            TcpStream::connect(AGENT_LOCAL_ADDR).is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn agent_ipc_ready() -> bool {
    TcpStream::connect(AGENT_LOCAL_ADDR).is_ok()
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ensure_agent_server() -> Result<(), String> {
    if agent_ipc_ready() {
        return Ok(());
    }

    let service_status = read_badvpn_agent_service_status();
    log_event(
        "agent",
        format!(
            "IPC not ready; service installed={} running={} state={:?} message={}",
            service_status.installed,
            service_status.running,
            service_status.state,
            service_status.message
        ),
    );
    if service_status.installed {
        if !service_status.running {
            start_badvpn_agent_service_normal()?;
        }
        return wait_for_agent_server();
    }

    if std::env::var("BADVPN_ALLOW_USER_AGENT").ok().as_deref() != Some("1") {
        return Err(format!(
            "{} Install or repair the BadVpn agent service from Settings > Updates & Diagnostics.",
            service_status.message
        ));
    }

    {
        let mut child = agent_process()
            .lock()
            .map_err(|_| "agent process lock is poisoned".to_string())?;
        if let Some(running) = child.as_mut() {
            if running.try_wait().ok().flatten().is_none() {
                drop(child);
                return wait_for_agent_server();
            }
        }

        let agent_bin = resolve_agent_bin()?;
        let mut command = Command::new(&agent_bin);
        command
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_background_process(&mut command);
        *child = Some(command.spawn().map_err(|error| {
            format!(
                "Failed to start BadVpn agent server {}: {error}",
                agent_bin.display()
            )
        })?);
    }

    wait_for_agent_server()
}

fn wait_for_agent_server() -> Result<(), String> {
    let started = SystemTime::now();
    loop {
        if agent_ipc_ready() {
            return Ok(());
        }
        if started
            .elapsed()
            .map_or(true, |elapsed| elapsed > Duration::from_secs(4))
        {
            let endpoint =
                if std::env::var("BADVPN_AGENT_TCP_FALLBACK").ok().as_deref() == Some("1") {
                    format!("{AGENT_PIPE_NAME} or {AGENT_LOCAL_ADDR}")
                } else {
                    AGENT_PIPE_NAME.to_string()
                };
            log_event(
                "agent",
                format!("agent IPC readiness timeout at {endpoint}"),
            );
            return Err(format!(
                "BadVpn agent IPC did not become ready at {endpoint}."
            ));
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

fn resolve_agent_bin() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BADVPN_AGENT_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let exe_names: Vec<&str> = if cfg!(windows) {
        vec!["badvpn-agent-staged.exe", "badvpn-agent.exe"]
    } else {
        vec!["badvpn-agent"]
    };
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            candidates.extend(exe_names.iter().map(|name| dir.join(name)));
            candidates.extend(agent_resource_bin_candidates(dir, &exe_names));
            // tauri:dev keeps resources under src-tauri/resources, not next to the debug exe.
            if let Some(src_tauri) = dir
                .ancestors()
                .find(|path| path.file_name().and_then(|name| name.to_str()) == Some("src-tauri"))
            {
                candidates.extend(
                    exe_names
                        .iter()
                        .map(|name| src_tauri.join("resources").join("agent").join(name)),
                );
            }
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        for exe_name in &exe_names {
            candidates.push(current_dir.join("target").join("debug").join(exe_name));
            candidates.push(current_dir.join("target").join("release").join(exe_name));
            candidates.push(
                current_dir
                    .join("apps")
                    .join("badvpn-client")
                    .join("src-tauri")
                    .join("resources")
                    .join("agent")
                    .join(exe_name),
            );
            candidates.push(
                current_dir
                    .join("src-tauri")
                    .join("resources")
                    .join("agent")
                    .join(exe_name),
            );
            candidates.push(
                current_dir
                    .join("apps")
                    .join("badvpn-client")
                    .join("src-tauri")
                    .join("target-runtime")
                    .join("release")
                    .join(exe_name),
            );
        }
        // Walk up to workspace root when cwd is apps/badvpn-client.
        for ancestor in current_dir.ancestors().take(5) {
            for exe_name in &exe_names {
                candidates.push(ancestor.join("target").join("debug").join(exe_name));
                candidates.push(ancestor.join("target").join("release").join(exe_name));
                candidates.push(
                    ancestor
                        .join("apps")
                        .join("badvpn-client")
                        .join("src-tauri")
                        .join("resources")
                        .join("agent")
                        .join(exe_name),
                );
            }
        }
    }
    if let Ok(data) = data_dir() {
        for exe_name in &exe_names {
            candidates.push(data.join("components").join("agent").join(exe_name));
        }
    }
    if let Some(path) = data_dir()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        for exe_name in &exe_names {
            candidates.push(
                path.join("BadVpn")
                    .join("components")
                    .join("agent")
                    .join(exe_name),
            );
        }
    }

    candidates
        .into_iter()
        .filter(|path| path.exists())
        .max_by_key(|path| {
            path.metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
        })
        .ok_or_else(|| {
            format!(
                "BadVpn agent binary was not found. Build it with `cargo build -p badvpn-agent`, stage `badvpn-agent-staged.exe`, or set BADVPN_AGENT_BIN."
            )
        })
}

fn agent_resource_bin_candidates(resource_parent: &Path, exe_names: &[&str]) -> Vec<PathBuf> {
    exe_names
        .iter()
        .flat_map(|exe_name| {
            [
                resource_parent
                    .join("resources")
                    .join("agent")
                    .join(exe_name),
                resource_parent
                    .join("resources")
                    .join("resources")
                    .join("agent")
                    .join(exe_name),
            ]
        })
        .collect()
}

#[cfg(test)]
mod agent_resource_tests {
    use super::*;

    #[test]
    fn agent_resource_candidates_include_tauri_preserved_directory_layout() {
        let candidates = agent_resource_bin_candidates(
            Path::new("C:/Program Files/BadVpn"),
            &["badvpn-agent-staged.exe"],
        );

        assert_eq!(
            candidates,
            vec![
                PathBuf::from("C:/Program Files/BadVpn/resources/agent/badvpn-agent-staged.exe"),
                PathBuf::from(
                    "C:/Program Files/BadVpn/resources/resources/agent/badvpn-agent-staged.exe"
                ),
            ]
        );
    }
}

#[tauri::command]
pub async fn set_subscription(url: String) -> Result<AgentState, String> {
    log_event("subscription", "import requested");
    let trimmed = url.trim();
    if trimmed.is_empty() {
        log_event("subscription", "import rejected: empty URL");
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Onboarding;
        state.subscription = SubscriptionState {
            url: None,
            is_valid: Some(false),
            validation_error: Some("Subscription URL is required.".to_string()),
            ..SubscriptionState::default()
        };
        state.last_error = Some("Subscription URL is required.".to_string());
        return Ok(state.clone());
    }

    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        log_event("subscription", "import rejected: invalid URL scheme");
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.phase = AppPhase::Onboarding;
        state.subscription = SubscriptionState {
            url: Some(trimmed.to_string()),
            is_valid: Some(false),
            validation_error: Some(
                "Subscription URL must start with http:// or https://.".to_string(),
            ),
            ..SubscriptionState::default()
        };
        state.last_error =
            Some("Subscription URL must start with http:// or https://.".to_string());
        return Ok(state.clone());
    }

    let imported = fetch_subscription(trimmed).await;
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;

    let imported = match imported {
        Ok(imported) => {
            if let Err(error) = write_mihomo_config(&imported.body) {
                log_event("subscription", format!("config generation failed: {error}"));
                state.phase = AppPhase::Onboarding;
                state.subscription = SubscriptionState {
                    url: Some(trimmed.to_string()),
                    is_valid: Some(false),
                    validation_error: Some(error.clone()),
                    ..SubscriptionState::default()
                };
                state.last_error = Some(error);
                return Ok(state.clone());
            }
            imported
        }
        Err(error) => {
            log_event("subscription", format!("fetch/import failed: {error}"));
            state.phase = AppPhase::Onboarding;
            state.subscription = SubscriptionState {
                url: Some(trimmed.to_string()),
                is_valid: Some(false),
                validation_error: Some(error.clone()),
                ..SubscriptionState::default()
            };
            state.last_error = Some(error);
            return Ok(state.clone());
        }
    };

    state.phase = AppPhase::Ready;
    state.subscription = imported.subscription;
    let _ = persist_subscription_state_with_body(&state.subscription, Some(&imported.body));
    state.last_error = None;
    log_event(
        "subscription",
        format!(
            "imported successfully; nodes={} format={:?}",
            state.subscription.node_count, state.subscription.format
        ),
    );
    Ok(state.clone())
}

#[tauri::command]
pub async fn refresh_subscription() -> Result<AgentState, String> {
    log_event("subscription", "refresh requested");
    hydrate_persisted_state()?;
    let url = {
        let state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.subscription.url.clone()
    };

    let Some(url) = url else {
        log_event("subscription", "refresh rejected: no subscription");
        let mut state = state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?;
        state.subscription.is_valid = Some(false);
        state.subscription.validation_error =
            Some("Add a subscription before refreshing.".to_string());
        state.last_error = Some("Add a subscription before refreshing.".to_string());
        return Ok(state.clone());
    };

    let imported = fetch_active_subscription_profile(&url).await;
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;

    match imported {
        Ok(imported) => {
            if let Err(error) = write_mihomo_config(&imported.body) {
                log_event(
                    "subscription",
                    format!("refresh config generation failed: {error}"),
                );
                let _ = mark_active_subscription_profile_refresh_failure(&error).map_err(|store_error| {
                    log_event(
                        "subscription-profile",
                        format!(
                            "failed to persist active profile refresh validation failure: {store_error}"
                        ),
                    )
                });
                state.subscription.is_valid = Some(false);
                state.subscription.validation_error = Some(error.clone());
                state.last_error = Some(error);
                return Ok(state.clone());
            }
            state.subscription = imported.subscription;
            let _ = persist_subscription_state_with_body(&state.subscription, Some(&imported.body));
            let _ = mark_active_subscription_profile_refresh_success(
                &state.subscription,
                &imported.body,
            )
            .map_err(|error| {
                log_event(
                    "subscription-profile",
                    format!("failed to persist active profile refresh success: {error}"),
                )
            });
            state.last_error = None;
        }
        Err(error) => {
            log_event("subscription", format!("refresh failed: {error}"));
            let _ =
                mark_active_subscription_profile_refresh_failure(&error).map_err(|store_error| {
                    log_event(
                        "subscription-profile",
                        format!("failed to persist active profile refresh failure: {store_error}"),
                    )
                });
            state.subscription.is_valid = Some(false);
            state.subscription.validation_error = Some(error.clone());
            state.last_error = Some(error);
            return Ok(state.clone());
        }
    }

    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: state.running,
        zapret_healthy: false,
        message: Some("Subscription metadata refreshed from provider.".to_string()),
    };
    log_event(
        "subscription",
        format!(
            "refresh succeeded; nodes={} format={:?}",
            state.subscription.node_count, state.subscription.format
        ),
    );
    Ok(state.clone())
}

#[tauri::command]
pub fn subscription_profiles() -> Result<SubscriptionProfilesState, String> {
    Ok(build_subscription_profiles_state()?)
}

#[tauri::command]
pub async fn add_subscription_profile(
    url: String,
    name: Option<String>,
) -> Result<SubscriptionProfilesApplyResult, String> {
    log_event("subscription-profile", "add requested");
    let trimmed = validate_subscription_url(&url)?;
    let imported =
        fetch_subscription_with_options(trimmed, &PersistedSubscriptionFetchOptions::default())
            .await?;
    write_mihomo_config(&imported.body)?;
    let reload_message =
        maybe_reload_mihomo_after_subscription_change("subscription profile add").await;

    let mut store = read_persisted_subscription_profiles()?;
    let now = current_unix_timestamp();
    let existing_index = store.profiles.iter().position(|profile| {
        profile
            .subscription
            .url
            .as_deref()
            .map(|stored| stored.eq_ignore_ascii_case(trimmed))
            .unwrap_or(false)
    });
    let display_name = subscription_profile_display_name(
        name.as_deref(),
        &imported.subscription,
        store.profiles.len() + 1,
    );
    let active_id = if let Some(index) = existing_index {
        let profile = &mut store.profiles[index];
        profile.name = display_name;
        profile.subscription = imported.subscription.clone();
        profile.protected_url = Some(protect_secret(trimmed)?);
        profile.protected_body = Some(protect_secret(&imported.body)?);
        profile.last_successful_refresh_at = Some(now);
        profile.last_failed_refresh_at = None;
        profile.last_refresh_error = None;
        profile.next_refresh_at = next_profile_refresh_at(&profile.subscription, now);
        profile.updated_at = now;
        profile.id.clone()
    } else {
        let id = subscription_profile_id(trimmed, now);
        store.profiles.push(PersistedSubscriptionProfile {
            id: id.clone(),
            name: display_name,
            description: None,
            subscription: imported.subscription.clone(),
            protected_url: Some(protect_secret(trimmed)?),
            protected_body: Some(protect_secret(&imported.body)?),
            last_successful_refresh_at: Some(now),
            last_failed_refresh_at: None,
            last_refresh_error: None,
            next_refresh_at: next_profile_refresh_at(&imported.subscription, now),
            fetch_options: PersistedSubscriptionFetchOptions::default(),
            created_at: now,
            updated_at: now,
        });
        id
    };
    store.active_id = Some(active_id.clone());
    write_persisted_subscription_profiles(&store)?;
    persist_subscription_state_with_body(&imported.subscription, Some(&imported.body))?;

    let state = apply_active_subscription_state(
        imported.subscription,
        Some("Subscription profile added.".to_string()),
    )?;
    log_event(
        "subscription-profile",
        format!(
            "added/selected profile; profiles={} active_id={active_id}",
            store.profiles.len()
        ),
    );
    let message =
        reload_message.unwrap_or_else(|| "Subscription profile added and selected.".to_string());
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message,
    })
}

#[tauri::command]
pub async fn select_subscription_profile(
    id: String,
) -> Result<SubscriptionProfilesApplyResult, String> {
    log_event("subscription-profile", "select requested");
    let mut store = read_persisted_subscription_profiles()?;
    let index = store
        .profiles
        .iter()
        .position(|profile| profile.id == id)
        .ok_or_else(|| "Subscription profile was not found.".to_string())?;
    let url = store.profiles[index]
        .subscription
        .url
        .clone()
        .ok_or_else(|| "Subscription profile URL is not available.".to_string())?;
    let fetch_options = store.profiles[index].fetch_options.clone();
    let imported = fetch_subscription_with_options(&url, &fetch_options).await?;
    write_mihomo_config(&imported.body)?;
    let reload_message =
        maybe_reload_mihomo_after_subscription_change("subscription profile select").await;
    store.profiles[index].subscription = imported.subscription.clone();
    store.profiles[index].protected_body = Some(protect_secret(&imported.body)?);
    store.profiles[index].updated_at = current_unix_timestamp();
    store.active_id = Some(id.clone());
    write_persisted_subscription_profiles(&store)?;
    persist_subscription_state_with_body(&imported.subscription, Some(&imported.body))?;

    let state = apply_active_subscription_state(
        imported.subscription,
        Some("Subscription profile selected.".to_string()),
    )?;
    log_event("subscription-profile", format!("selected profile id={id}"));
    let message = reload_message.unwrap_or_else(|| "Subscription profile selected.".to_string());
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message,
    })
}

#[tauri::command]
pub async fn remove_subscription_profile(
    id: String,
) -> Result<SubscriptionProfilesApplyResult, String> {
    log_event("subscription-profile", "remove requested");
    let mut store = read_persisted_subscription_profiles()?;
    write_subscription_profiles_backup(&store, "before-remove")?;
    let active_removed = store.active_id.as_deref() == Some(id.as_str());
    let before = store.profiles.len();
    store.profiles.retain(|profile| profile.id != id);
    if store.profiles.len() == before {
        return Err("Subscription profile was not found.".to_string());
    }

    let mut message = "Subscription profile removed.".to_string();
    let next_state = if active_removed {
        if let Some(next_profile) = store.profiles.first().cloned() {
            let url = next_profile
                .subscription
                .url
                .clone()
                .ok_or_else(|| "Next subscription profile URL is not available.".to_string())?;
            let fetch_options = next_profile.fetch_options.clone();
            let imported = fetch_subscription_with_options(&url, &fetch_options).await?;
            write_mihomo_config(&imported.body)?;
            let reload_message =
                maybe_reload_mihomo_after_subscription_change("subscription profile remove").await;
            if let Some(profile) = store
                .profiles
                .iter_mut()
                .find(|profile| profile.id == next_profile.id)
            {
                profile.subscription = imported.subscription.clone();
                profile.protected_body = Some(protect_secret(&imported.body)?);
                profile.updated_at = current_unix_timestamp();
            }
            store.active_id = Some(next_profile.id.clone());
            persist_subscription_state_with_body(&imported.subscription, Some(&imported.body))?;
            message = reload_message.unwrap_or_else(|| {
                "Subscription profile removed. Another profile was selected.".to_string()
            });
            apply_active_subscription_state(
                imported.subscription,
                Some("Another subscription profile was selected.".to_string()),
            )?
        } else {
            store.active_id = None;
            clear_legacy_subscription_state()?;
            apply_no_subscription_state(
                "Subscription profile removed. Add a subscription to connect.",
            )?
        }
    } else {
        state()
            .lock()
            .map_err(|_| "agent state lock is poisoned".to_string())?
            .clone()
    };
    write_persisted_subscription_profiles(&store)?;
    log_event(
        "subscription-profile",
        format!(
            "removed profile; profiles={} active_removed={active_removed}",
            store.profiles.len()
        ),
    );
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state: next_state,
        message,
    })
}

#[tauri::command]
pub fn update_subscription_profile_metadata(
    id: String,
    description: Option<String>,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let mut store = read_persisted_subscription_profiles()?;
    let profile = store
        .profiles
        .iter_mut()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "Subscription profile was not found.".to_string())?;
    profile.description = normalize_subscription_profile_description(description)?;
    profile.updated_at = current_unix_timestamp();
    write_persisted_subscription_profiles(&store)?;
    let state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?
        .clone();
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message: "Subscription profile notes saved.".to_string(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentUpdateReport {
    pub components: Vec<ComponentUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSubscriptionState {
    subscription: SubscriptionState,
    #[serde(default)]
    protected_url: Option<String>,
    #[serde(default)]
    protected_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedSubscriptionProfiles {
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    profiles: Vec<PersistedSubscriptionProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSubscriptionProfile {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    subscription: SubscriptionState,
    #[serde(default)]
    protected_url: Option<String>,
    #[serde(default)]
    protected_body: Option<String>,
    #[serde(default)]
    last_successful_refresh_at: Option<u64>,
    #[serde(default)]
    last_failed_refresh_at: Option<u64>,
    #[serde(default)]
    last_refresh_error: Option<String>,
    #[serde(default)]
    next_refresh_at: Option<u64>,
    #[serde(default)]
    fetch_options: PersistedSubscriptionFetchOptions,
    created_at: u64,
    updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFetchProxyMode {
    Direct,
    System,
    Custom,
}

impl Default for SubscriptionFetchProxyMode {
    fn default() -> Self {
        Self::System
    }
}

impl SubscriptionFetchProxyMode {
    fn from_wire(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "system" | "system_proxy" => Ok(Self::System),
            "custom" | "custom_proxy" => Ok(Self::Custom),
            _ => Err("Fetch proxy mode must be direct, system, or custom.".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct PersistedSubscriptionFetchOptions {
    timeout_seconds: u64,
    proxy_mode: SubscriptionFetchProxyMode,
    protected_custom_proxy_url: Option<String>,
    user_agent: Option<String>,
}

impl Default for PersistedSubscriptionFetchOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: 20,
            proxy_mode: SubscriptionFetchProxyMode::System,
            protected_custom_proxy_url: None,
            user_agent: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionFetchOptionsView {
    pub timeout_seconds: u64,
    pub proxy_mode: SubscriptionFetchProxyMode,
    pub custom_proxy_redacted: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionProfilesState {
    pub active_id: Option<String>,
    pub profiles: Vec<SubscriptionProfileView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionProfileView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
    pub redacted_url: Option<String>,
    pub subscription: SubscriptionState,
    pub last_successful_refresh_at: Option<u64>,
    pub last_failed_refresh_at: Option<u64>,
    pub last_refresh_error: Option<String>,
    pub next_refresh_at: Option<u64>,
    pub fetch_options: SubscriptionFetchOptionsView,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionProfilesApplyResult {
    pub profiles: SubscriptionProfilesState,
    pub state: AgentState,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProfilePreview {
    pub display_name: String,
    pub source_file_name: Option<String>,
    pub format: SubscriptionFormat,
    pub node_count: usize,
    pub decoded_size_bytes: usize,
    pub import_ready: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionsSnapshot {
    pub active: Vec<TrackedConnection>,
    pub closed: Vec<TrackedConnection>,
    pub upload_total: u64,
    pub download_total: u64,
    pub refreshed_at: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrackedConnection {
    pub id: String,
    pub state: String,
    pub host: String,
    pub destination: String,
    pub network: String,
    pub connection_type: String,
    pub process: Option<String>,
    pub process_path: Option<String>,
    pub rule: Option<String>,
    pub rule_payload: Option<String>,
    pub rule_source: Option<String>,
    pub chains: Vec<String>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub started_at: Option<String>,
    pub closed_at: Option<u64>,
    pub path: ConnectionPath,
    pub path_label: String,
    pub path_note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPath {
    Vpn,
    Zapret,
    Direct,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyCatalog {
    pub groups: Vec<ProxyGroupView>,
    pub running: bool,
    pub refreshed_at: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroupView {
    pub name: String,
    pub group_type: String,
    pub selected: Option<String>,
    pub nodes: Vec<ProxyNodeView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyNodeView {
    pub name: String,
    pub proxy_type: Option<String>,
    pub server: Option<String>,
    pub delay_ms: Option<u64>,
    pub alive: Option<bool>,
    pub is_group: bool,
    pub selected: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct MihomoConnectionsResponse {
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default)]
    connections: Vec<MihomoConnection>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawMihomoConnectionsResponse {
    #[serde(default, rename = "downloadTotal")]
    download_total: serde_json::Value,
    #[serde(default, rename = "uploadTotal")]
    upload_total: serde_json::Value,
    #[serde(default, deserialize_with = "deserialize_nullable_json_vec")]
    connections: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct MihomoConnection {
    #[serde(default, deserialize_with = "deserialize_lossy_string")]
    id: String,
    #[serde(default)]
    metadata: MihomoMetadata,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    #[serde(default)]
    start: Option<String>,
    #[serde(default, deserialize_with = "deserialize_lossy_string_vec")]
    chains: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_lossy_option_string")]
    rule: Option<String>,
    #[serde(
        default,
        rename = "rulePayload",
        deserialize_with = "deserialize_lossy_option_string"
    )]
    rule_payload: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MihomoMetadata {
    #[serde(default, deserialize_with = "deserialize_lossy_string")]
    network: String,
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_lossy_string"
    )]
    connection_type: String,
    #[serde(default, deserialize_with = "deserialize_lossy_string")]
    host: String,
    #[serde(
        default,
        rename = "destinationIP",
        deserialize_with = "deserialize_lossy_string"
    )]
    destination_ip: String,
    #[serde(default, rename = "destinationPort")]
    destination_port: serde_json::Value,
    #[serde(default, deserialize_with = "deserialize_lossy_option_string")]
    process: Option<String>,
    #[serde(
        default,
        rename = "processPath",
        alias = "process_path",
        deserialize_with = "deserialize_lossy_option_string"
    )]
    process_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MihomoProxiesResponse {
    #[serde(default)]
    proxies: std::collections::BTreeMap<String, MihomoProxyState>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MihomoProxyState {
    #[serde(default, rename = "type")]
    proxy_type: Option<String>,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    delay: Option<u64>,
    #[serde(default)]
    history: Vec<MihomoProxyHistory>,
    #[serde(default, rename = "all")]
    members: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct MihomoProxyHistory {
    #[serde(default)]
    delay: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppReleaseUpdate {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub notes: Option<String>,
    pub release_url: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TauriLatestJson {
    version: String,
    notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentUpdate {
    pub name: String,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
    pub update_available: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZapretProfileState {
    pub selected: String,
    pub options: Vec<ZapretProfileOption>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZapretProfileOption {
    pub id: String,
    pub label: String,
    pub description: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZapretServiceStatus {
    pub service_name: String,
    pub installed: bool,
    pub running: bool,
    pub state: Option<String>,
    pub config_hash: Option<String>,
    pub expected_hash: Option<String>,
    pub repair_required: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentServiceStatus {
    pub service_name: String,
    pub installed: bool,
    pub running: bool,
    pub state: Option<String>,
    pub ipc_ready: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeReadinessResponse {
    pub agent: AgentServiceStatus,
    pub mihomo_ready: bool,
    pub zapret_ready: bool,
    pub needs_zapret: bool,
    pub components_ready: bool,
    pub ready: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeDiagnosticsReport {
    pub checked_at: u64,
    pub mihomo_healthy: bool,
    pub zapret_healthy: bool,
    pub summary: String,
    pub checks: Vec<RuntimeDiagnosticCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeDiagnosticCheck {
    pub id: String,
    pub label: String,
    pub status: RuntimeCheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCheckStatus {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeUpdateResult {
    pub changed: bool,
    pub messages: Vec<String>,
    pub state: AgentState,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsApplyResult {
    pub settings: AppSettings,
    pub restart_required: bool,
    pub state: AgentState,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct MihomoVersionResponse {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[tauri::command]
pub async fn check_app_release_update() -> Result<AppReleaseUpdate, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let release_url = "https://github.com/Rerowros/bpn-client/releases/latest/download/latest.json";
    let client = reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    let result = client
        .get(release_url)
        .send()
        .await
        .map_err(|error| format!("Failed to check BadVpn app release: {error}"));

    let response = match result {
        Ok(response) => response,
        Err(error) => {
            return Ok(AppReleaseUpdate {
                current_version,
                latest_version: None,
                update_available: false,
                notes: None,
                release_url: release_url.to_string(),
                error: Some(error),
            })
        }
    };

    if response.status().as_u16() == 404 {
        return Ok(AppReleaseUpdate {
            current_version,
            latest_version: None,
            update_available: false,
            notes: None,
            release_url: release_url.to_string(),
            error: Some("No BadVpn GitHub Release latest.json published yet.".to_string()),
        });
    }

    let latest = response
        .error_for_status()
        .map_err(|error| format!("GitHub returned an error: {error}"))?
        .json::<TauriLatestJson>()
        .await
        .map_err(|error| format!("Failed to parse BadVpn latest.json: {error}"))?;
    let update_available = latest.version != current_version;

    Ok(AppReleaseUpdate {
        current_version,
        latest_version: Some(latest.version),
        update_available,
        notes: latest.notes,
        release_url: release_url.to_string(),
        error: None,
    })
}

#[tauri::command]
pub async fn check_component_updates() -> Result<ComponentUpdateReport, String> {
    let client = reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    let components = vec![
        check_github_component(
            &client,
            "mihomo",
            &local_mihomo_version().unwrap_or_else(|error| format!("missing ({error})")),
            MIHOMO_REPO,
        )
        .await,
        check_github_component(
            &client,
            "zapret",
            &local_zapret_version().unwrap_or_else(|error| format!("missing ({error})")),
            FLOWSEAL_ZAPRET_REPO,
        )
        .await,
        check_flowseal_lists_component(&client).await,
    ];

    Ok(ComponentUpdateReport { components })
}

#[tauri::command]
pub fn runtime_readiness() -> Result<RuntimeReadinessResponse, String> {
    let settings = load_app_settings();
    let needs_zapret =
        settings.effective_route_mode() == RouteMode::Smart && settings.zapret.enabled;
    let agent = read_badvpn_agent_service_status();
    let service_runtime = agent.installed;
    let mihomo_ready = if service_runtime {
        programdata_mihomo_ready()
    } else {
        user_mihomo_ready() || programdata_mihomo_ready()
    };
    let zapret_ready = if !needs_zapret {
        true
    } else if service_runtime {
        programdata_zapret_runtime_assets_ready().is_ok()
    } else {
        zapret_runtime_assets_ready().is_ok() || programdata_zapret_runtime_assets_ready().is_ok()
    };
    let components_ready = mihomo_ready && zapret_ready;
    let ready = agent.installed && agent.ipc_ready && components_ready;
    let user_components_ready = user_runtime_components_ready(needs_zapret);
    let message = if ready {
        "Ready to connect.".to_string()
    } else if !agent.installed {
        "Install badvpn-agent before connecting.".to_string()
    } else if !agent.ipc_ready {
        "badvpn-agent is installed but not reachable yet.".to_string()
    } else if user_components_ready && !components_ready {
        "Runtime components are present in the user cache but not staged to ProgramData for badvpn-agent; prepare or repair runtime components.".to_string()
    } else if !mihomo_ready {
        "Mihomo runtime is missing; prepare runtime components.".to_string()
    } else if !zapret_ready {
        "zapret runtime assets are missing for Smart mode; prepare runtime components.".to_string()
    } else {
        "Runtime setup needs attention.".to_string()
    };

    Ok(RuntimeReadinessResponse {
        agent,
        mihomo_ready,
        zapret_ready,
        needs_zapret,
        components_ready,
        ready,
        message,
    })
}

#[tauri::command]
pub fn get_settings() -> Result<AppSettings, String> {
    Ok(load_app_settings())
}

#[tauri::command]
pub fn save_settings(settings: AppSettings) -> Result<SettingsApplyResult, String> {
    apply_settings(settings)
}

#[tauri::command]
pub fn reset_settings() -> Result<SettingsApplyResult, String> {
    apply_settings(AppSettings::default())
}

#[tauri::command]
pub fn agent_service_status() -> Result<AgentServiceStatus, String> {
    Ok(read_badvpn_agent_service_status())
}

#[tauri::command]
pub fn install_agent_service() -> Result<AgentServiceStatus, String> {
    install_badvpn_agent_service()
}

#[tauri::command]
pub fn remove_agent_service() -> Result<AgentServiceStatus, String> {
    remove_badvpn_agent_service()
}

#[tauri::command]
pub fn zapret_profile_state() -> Result<ZapretProfileState, String> {
    Ok(build_zapret_profile_state(configured_zapret_profile()))
}

#[tauri::command]
pub fn zapret_service_status() -> Result<ZapretServiceStatus, String> {
    Ok(read_badvpn_zapret_service_status())
}

#[tauri::command]
pub fn set_zapret_profile(profile: String) -> Result<ZapretProfileState, String> {
    let profile = parse_zapret_profile_id(&profile)
        .ok_or_else(|| "Unknown zapret Flowseal profile.".to_string())?;
    let mut settings = load_app_settings();
    settings.zapret.strategy = profile.strategy();
    write_settings_to_path(&settings_file_path()?, &settings)?;
    persist_zapret_profile(profile)?;
    Ok(build_zapret_profile_state(profile))
}

#[tauri::command]
pub async fn run_diagnostics() -> Result<RuntimeDiagnosticsReport, String> {
    log_event("diagnostics", "manual diagnostics requested");
    let settings = load_app_settings();
    let run_network_tests = settings.diagnostics.discord_youtube_probes;
    let mut report = collect_runtime_diagnostics(run_network_tests).await;
    let fallback_message = match maybe_apply_vpn_fallback_after_zapret_failure(
        &settings,
        &report,
        "diagnostics",
    )
    .await
    {
        Ok(message) => message,
        Err(error) => {
            log_event("routing", format!("VPN fallback apply failed: {error}"));
            None
        }
    };
    if fallback_message.is_some() {
        report = collect_runtime_diagnostics(false).await;
    }
    let restore_message =
        match maybe_restore_smart_hybrid_after_zapret_recovery(&settings, &report, "diagnostics")
            .await
        {
            Ok(message) => message,
            Err(error) => {
                log_event("routing", format!("Smart restore failed: {error}"));
                None
            }
        };
    if restore_message.is_some() {
        report = collect_runtime_diagnostics(false).await;
    }
    let runtime_route_mode =
        detect_mihomo_config_route_mode().unwrap_or_else(|| settings.effective_route_mode());
    let active_fallback_message = active_vpn_fallback_message(&settings, runtime_route_mode);
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    state.connection.route_mode = runtime_route_mode;
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: report.mihomo_healthy,
        zapret_healthy: report.zapret_healthy,
        message: Some(
            fallback_message
                .or(restore_message)
                .or(active_fallback_message)
                .map(|message| format!("{message} {}", report.summary.clone()))
                .unwrap_or_else(|| report.summary.clone()),
        ),
    };
    state.running = report.mihomo_healthy;
    state.connection.connected = report.mihomo_healthy;
    state.connection.status = if report.mihomo_healthy {
        ConnectionStatus::Running
    } else {
        ConnectionStatus::Idle
    };
    state.phase = if report.mihomo_healthy {
        AppPhase::Connected
    } else if subscription_is_present(&state.subscription) {
        AppPhase::Ready
    } else {
        AppPhase::Onboarding
    };
    Ok(report)
}

async fn maybe_apply_vpn_fallback_after_zapret_failure(
    settings: &AppSettings,
    report: &RuntimeDiagnosticsReport,
    context: &str,
) -> Result<Option<String>, String> {
    if should_use_agent_runtime() {
        log_event(
            "routing",
            format!("skipped UI VPN fallback because service-first runtime owns routing; context={context}"),
        );
        return Ok(None);
    }

    if !settings.zapret.fallback_to_vpn_on_failed_probe
        || !settings.zapret.enabled
        || !report.mihomo_healthy
        || report.zapret_healthy
        || !has_structural_zapret_failure(report)
    {
        return Ok(None);
    }

    let runtime_route_mode =
        detect_mihomo_config_route_mode().unwrap_or_else(|| settings.effective_route_mode());
    if runtime_route_mode != RouteMode::Smart {
        return Ok(None);
    }

    let config_path = mihomo_config_path()?;
    ensure_mihomo_config_routing(&config_path, settings, RouteMode::VpnOnly)?;
    reload_mihomo_config_via_api(&config_path).await?;
    let _ = close_all_connections().await;

    let failed_checks = report
        .checks
        .iter()
        .filter(|check| check.status != RuntimeCheckStatus::Ok)
        .map(|check| format!("{}: {}", check.label, check.message))
        .collect::<Vec<_>>()
        .join(" | ");
    let message =
        "zapret is unhealthy; switched current Mihomo config to VPN Only fallback.".to_string();
    log_event(
        "routing",
        format!("{message} context={context} failed_checks={failed_checks}"),
    );
    Ok(Some(message))
}

async fn maybe_restore_smart_hybrid_after_zapret_recovery(
    settings: &AppSettings,
    report: &RuntimeDiagnosticsReport,
    context: &str,
) -> Result<Option<String>, String> {
    if should_use_agent_runtime() {
        log_event(
            "routing",
            format!("skipped UI Smart restore because service-first runtime owns routing; context={context}"),
        );
        return Ok(None);
    }

    if !settings.zapret.enabled
        || settings.effective_route_mode() != RouteMode::Smart
        || !report.mihomo_healthy
        || !report.zapret_healthy
    {
        return Ok(None);
    }

    let runtime_route_mode =
        detect_mihomo_config_route_mode().unwrap_or_else(|| settings.effective_route_mode());
    if runtime_route_mode != RouteMode::VpnOnly {
        return Ok(None);
    }

    let config_path = mihomo_config_path()?;
    ensure_mihomo_config_routing(&config_path, settings, RouteMode::Smart)?;
    reload_mihomo_config_via_api(&config_path).await?;
    let _ = close_all_connections().await;
    let message = "Smart routing restored after zapret recovered.".to_string();
    log_event("routing", format!("{message} context={context}"));
    Ok(Some(message))
}

fn has_structural_zapret_failure(report: &RuntimeDiagnosticsReport) -> bool {
    report.checks.iter().any(|check| {
        matches!(
            check.id.as_str(),
            "zapret_process" | "zapret_assets" | "flowseal_lists"
        ) && check.status == RuntimeCheckStatus::Error
    })
}

fn active_vpn_fallback_message(
    settings: &AppSettings,
    runtime_route_mode: RouteMode,
) -> Option<String> {
    (runtime_route_mode == RouteMode::VpnOnly
        && settings.effective_route_mode() == RouteMode::Smart
        && settings.zapret.enabled
        && settings.zapret.fallback_to_vpn_on_failed_probe)
        .then(|| "VPN Only fallback is active because Smart zapret is not ready.".to_string())
}

#[tauri::command]
pub async fn update_runtime_components() -> Result<RuntimeUpdateResult, String> {
    log_event("components", "runtime component update requested");
    let was_running = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?
        .running;
    if was_running {
        stop().await?;
    }

    let mut messages = Vec::new();
    match install_components(true).await {
        Ok(()) => {
            log_event("components", "Mihomo and zapret binaries refreshed");
            messages.push("Mihomo and zapret binaries refreshed from GitHub releases.".to_string())
        }
        Err(error) => {
            log_event("components", format!("binary refresh failed: {error}"));
            messages.push(format!("Component update failed: {error}"))
        }
    }
    match ensure_zapret_runtime_lists_force().await {
        Ok(()) => {
            log_event("components", "Flowseal lists refreshed");
            messages.push("Flowseal lists refreshed.".to_string())
        }
        Err(error) => {
            log_event(
                "components",
                format!("Flowseal list refresh failed: {error}"),
            );
            messages.push(format!("Flowseal list update failed: {error}"))
        }
    }

    if read_badvpn_agent_service_status().installed {
        match stage_runtime_assets_to_programdata() {
            Ok(()) => {
                log_event("components", "runtime assets staged to ProgramData");
                messages.push("Runtime assets staged for the BadVpn agent service.".to_string());
            }
            Err(error) => {
                log_event("components", format!("ProgramData staging failed: {error}"));
                messages.push(format!("ProgramData staging failed: {error}"));
            }
        }
    }

    let state = if was_running {
        start().await?
    } else {
        refresh_runtime_state(false).await?
    };
    let changed = messages.iter().any(|message| !message.contains("failed"));
    Ok(RuntimeUpdateResult {
        changed,
        messages,
        state,
    })
}

#[tauri::command]
pub async fn connections_snapshot() -> Result<ConnectionsSnapshot, String> {
    let refreshed_at = current_unix_timestamp();

    match fetch_mihomo_connections().await {
        Ok(response) => {
            let active = response
                .connections
                .into_iter()
                .map(tracked_connection_from_mihomo)
                .collect::<Vec<_>>();
            update_connection_history(&active, refreshed_at)?;
            let closed = closed_connections()
                .lock()
                .map_err(|_| "closed connections lock is poisoned".to_string())?
                .clone();

            Ok(ConnectionsSnapshot {
                active,
                closed,
                upload_total: response.upload_total,
                download_total: response.download_total,
                refreshed_at,
                error: None,
            })
        }
        Err(error) => {
            let closed = closed_connections()
                .lock()
                .map_err(|_| "closed connections lock is poisoned".to_string())?
                .clone();
            Ok(ConnectionsSnapshot {
                active: Vec::new(),
                closed,
                upload_total: 0,
                download_total: 0,
                refreshed_at,
                error: Some(error),
            })
        }
    }
}

#[tauri::command]
pub async fn close_connection(id: String) -> Result<ConnectionsSnapshot, String> {
    let client = mihomo_http_client()?;
    let url = format!(
        "{}/connections/{}",
        mihomo_controller_base()?,
        path_encode(&id)
    );
    let response = add_mihomo_auth(client.delete(url))
        .send()
        .await
        .map_err(|error| format!("Failed to close connection: {error}"))?;
    response
        .error_for_status()
        .map_err(|error| format!("Mihomo rejected close connection request: {error}"))?;
    connections_snapshot().await
}

#[tauri::command]
pub async fn close_all_connections() -> Result<ConnectionsSnapshot, String> {
    let client = mihomo_http_client()?;
    let url = format!("{}/connections", mihomo_controller_base()?);
    let response = add_mihomo_auth(client.delete(url))
        .send()
        .await
        .map_err(|error| format!("Failed to close connections: {error}"))?;
    response
        .error_for_status()
        .map_err(|error| format!("Mihomo rejected close-all request: {error}"))?;
    connections_snapshot().await
}

#[tauri::command]
pub fn clear_closed_connections() -> Result<ConnectionsSnapshot, String> {
    closed_connections()
        .lock()
        .map_err(|_| "closed connections lock is poisoned".to_string())?
        .clear();

    Ok(ConnectionsSnapshot {
        active: last_active_connections()
            .lock()
            .map_err(|_| "active connections lock is poisoned".to_string())?
            .clone(),
        closed: Vec::new(),
        upload_total: 0,
        download_total: 0,
        refreshed_at: current_unix_timestamp(),
        error: None,
    })
}

#[tauri::command]
pub async fn proxy_catalog() -> Result<ProxyCatalog, String> {
    let refreshed_at = current_unix_timestamp();
    let running = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?
        .running;

    let mut groups = match local_proxy_catalog() {
        Ok(groups) => groups,
        Err(error) => {
            return Ok(ProxyCatalog {
                groups: Vec::new(),
                running,
                refreshed_at,
                error: Some(error),
            })
        }
    };

    let mut error = None;
    match fetch_mihomo_proxies().await {
        Ok(api) => merge_proxy_runtime_state(&mut groups, &api),
        Err(fetch_error) if running => error = Some(fetch_error),
        Err(_) => {}
    }

    Ok(ProxyCatalog {
        groups,
        running,
        refreshed_at,
        error,
    })
}

#[tauri::command]
pub async fn select_proxy(group: String, proxy: String) -> Result<ProxyCatalog, String> {
    let group = group.trim();
    let proxy = proxy.trim();
    if group.is_empty() || proxy.is_empty() {
        return Err("Proxy group and proxy name are required.".to_string());
    }

    if should_use_agent_runtime() {
        let previous_selections = read_proxy_selections()?;
        let mut updated_selections = previous_selections.clone();
        updated_selections.insert(group.to_string(), proxy.to_string());
        persist_proxy_selections(&updated_selections)?;
        if let Err(error) = send_agent_command(
            AgentCommand::SelectProxy {
                group: group.to_string(),
                proxy: proxy.to_string(),
            },
            false,
        ) {
            return match persist_proxy_selections(&previous_selections) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(format!(
                    "{error} The saved proxy selection also could not be restored: {rollback_error}"
                )),
            };
        }
        return proxy_catalog().await;
    }

    let api = fetch_mihomo_proxies().await?;
    validate_proxy_selection(&api, group, proxy)?;
    let client = mihomo_http_client()?;
    let url = format!(
        "{}/proxies/{}",
        mihomo_controller_base()?,
        path_encode(group)
    );
    let response = add_mihomo_auth(client.put(url).json(&json!({ "name": proxy })))
        .send()
        .await
        .map_err(|error| format!("Failed to select proxy: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(proxy_selection_http_error(status, &detail));
    }
    persist_proxy_selection(group, proxy)?;
    proxy_catalog().await
}

#[tauri::command]
pub async fn policy_summary() -> Result<badvpn_common::ipc::PolicySummaryResponse, String> {
    if should_use_agent_runtime() {
        if let Ok(response) = send_agent_pipe_command_raw(&AgentCommand::PolicySummary) {
            if response.ok {
                if let Some(summary) = response.policy_summary {
                    return Ok(summary);
                }
            }
        } else if std::env::var("BADVPN_AGENT_TCP_FALLBACK").ok().as_deref() == Some("1") {
            if let Ok(response) = send_agent_tcp_command_raw(&AgentCommand::PolicySummary) {
                if response.ok {
                    if let Some(summary) = response.policy_summary {
                        return Ok(summary);
                    }
                }
            }
        }
    }

    let program_data =
        std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let path = std::path::PathBuf::from(program_data)
        .join("BadVpn")
        .join("runtime")
        .join("mihomo")
        .join("policy-summary.json");

    if let Ok(json) = std::fs::read_to_string(&path) {
        if let Ok(summary) =
            serde_json::from_str::<badvpn_common::ipc::PolicySummaryResponse>(&json)
        {
            return Ok(summary);
        }
    }

    let policy = last_preview_policy()
        .lock()
        .map_err(|_| "policy lock is poisoned".to_string())?
        .clone();

    if let Some(policy) = policy {
        let mut summary: badvpn_common::ipc::PolicySummaryResponse = (&policy).into();
        summary.source = "import_preview".to_string();
        return Ok(summary);
    }

    Ok(badvpn_common::ipc::PolicySummaryResponse::empty())
}

#[tauri::command]
pub async fn operator_snapshot() -> Result<OperatorSnapshot, String> {
    let policy = policy_summary().await.unwrap_or_else(|_| {
        let mut empty = badvpn_common::ipc::PolicySummaryResponse::empty();
        empty.state = "unavailable".to_string();
        empty
    });
    Ok(OperatorSnapshot {
        generated_at: current_unix_timestamp(),
        providers: operator_provider_catalog().unwrap_or_else(|error| ProviderCatalog {
            rule_providers: Vec::new(),
            proxy_providers: Vec::new(),
            update_status: format!("Provider read failed: {error}"),
            provider_editing: "Provider editing is read-only in this implementation slice."
                .to_string(),
        }),
        resources: operator_resource_catalog()?,
        logs: runtime_log_snapshot(240),
        config: runtime_config_snapshot()?,
        health: zapret_health_definitions(&policy),
        game_profiles: game_profiles_catalog(&load_app_settings()),
        backups: backup_history_snapshot()?,
    })
}

#[tauri::command]
pub fn pick_executable_path() -> Result<Option<String>, String> {
    #[cfg(not(windows))]
    {
        Ok(None)
    }

    #[cfg(windows)]
    {
        let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Filter = 'Windows executable (*.exe)|*.exe'
$dialog.Multiselect = $false
$dialog.CheckFileExists = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  Write-Output $dialog.FileName
}
"#;
        let mut command = Command::new("powershell");
        command.args(["-NoProfile", "-Sta", "-Command", script]);
        hide_process_window(&mut command);
        let output = command
            .output()
            .map_err(|error| format!("Failed to open executable picker: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Executable picker failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if selected.is_empty() {
            Ok(None)
        } else {
            Ok(Some(selected))
        }
    }
}

#[tauri::command]
pub async fn run_zapret_health_checks(
    custom_domain: Option<String>,
) -> Result<ZapretHealthReport, String> {
    let policy = policy_summary().await.unwrap_or_else(|_| {
        let mut empty = badvpn_common::ipc::PolicySummaryResponse::empty();
        empty.state = "unavailable".to_string();
        empty
    });
    let settings = load_app_settings();
    let mut checks = zapret_health_definitions(&policy).checks;
    if let Some(domain) = custom_domain
        .as_deref()
        .map(normalize_check_domain)
        .filter(|value| !value.is_empty())
    {
        checks.push(ZapretHealthCheck {
            id: "custom".to_string(),
            label: "Custom domain".to_string(),
            domain,
            route_path: "unknown".to_string(),
            dns_result: "pending".to_string(),
            probe_result: "pending".to_string(),
            zapret_list: "pending".to_string(),
            recovery_action: "Compare the route path with the intended local override.".to_string(),
            status: "warning".to_string(),
        });
    }

    let hostlist = read_hostlist_values().unwrap_or_default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("BadVpn/0.1.0 diagnostics")
        .build()
        .map_err(|error| format!("Failed to create diagnostics HTTP client: {error}"))?;

    for check in &mut checks {
        check.route_path = route_path_for_domain(&policy, &check.domain);
        check.zapret_list = if hostlist_contains_domain(&hostlist, &check.domain) {
            "present".to_string()
        } else if check.route_path == "zapret" {
            "missing".to_string()
        } else {
            "not-required".to_string()
        };
        check.dns_result = dns_answer_class(&check.domain).await;
        check.probe_result = safe_https_probe(&client, &check.domain).await;
        check.status = if check.route_path == "zapret"
            && settings.core.route_mode == RouteMode::Smart
            && check.zapret_list == "missing"
        {
            "warning".to_string()
        } else if check.probe_result.starts_with("ok") || check.probe_result == "skipped" {
            "ok".to_string()
        } else {
            "warning".to_string()
        };
    }

    Ok(ZapretHealthReport {
        checked_at: current_unix_timestamp(),
        checks,
    })
}

#[tauri::command]
pub async fn repair_windows_network() -> Result<AgentState, String> {
    log_event(
        "operator",
        "Windows firewall/route recovery requested through badvpn-agent",
    );
    if !should_use_agent_runtime() {
        return Err(
            "Windows network recovery requires badvpn-agent runtime ownership.".to_string(),
        );
    }
    let agent_state = send_agent_command(AgentCommand::RepairWindowsNetwork, true)?;
    apply_agent_state(agent_state)
}

#[tauri::command]
pub async fn update_operator_resource(id: String) -> Result<ResourceActionResult, String> {
    let id = id.trim();
    if id == "runtime-components" {
        let result = update_runtime_components().await?;
        return Ok(ResourceActionResult {
            changed: result.changed,
            message: result.messages.join(" "),
            resources: operator_resource_catalog()?,
        });
    }
    let def = operator_resource_defs()
        .into_iter()
        .find(|resource| resource.id == id)
        .ok_or_else(|| "Unknown resource.".to_string())?;
    if def.url.is_none() {
        return Err("This resource is visible but does not have a safe updater yet.".to_string());
    }
    update_text_resource(&def).await?;
    Ok(ResourceActionResult {
        changed: true,
        message: format!("{} updated with staged verification and backup.", def.label),
        resources: operator_resource_catalog()?,
    })
}

#[tauri::command]
pub async fn update_all_operator_resources() -> Result<ResourceActionResult, String> {
    let mut changed = false;
    let mut messages = Vec::new();
    for def in operator_resource_defs()
        .into_iter()
        .filter(|resource| resource.url.is_some())
    {
        match update_text_resource(&def).await {
            Ok(()) => {
                changed = true;
                messages.push(format!("{} updated", def.label));
            }
            Err(error) => messages.push(format!("{} failed: {error}", def.label)),
        }
    }
    Ok(ResourceActionResult {
        changed,
        message: messages.join("; "),
        resources: operator_resource_catalog()?,
    })
}

#[tauri::command]
pub fn rollback_operator_resource(id: String) -> Result<ResourceActionResult, String> {
    let def = operator_resource_defs()
        .into_iter()
        .find(|resource| resource.id == id.trim())
        .ok_or_else(|| "Unknown resource.".to_string())?;
    let backup = newest_resource_backup(&def.path)
        .ok_or_else(|| "No rollback backup is available for this resource.".to_string())?;
    fs::copy(&backup, &def.path).map_err(|error| {
        format!(
            "Failed to restore resource {} from {}: {error}",
            def.label,
            backup.display()
        )
    })?;
    Ok(ResourceActionResult {
        changed: true,
        message: format!("{} restored from backup.", def.label),
        resources: operator_resource_catalog()?,
    })
}

#[tauri::command]
pub async fn import_local_profile_from_text(
    name: String,
    body: String,
) -> Result<SubscriptionProfilesApplyResult, String> {
    import_profile_body(name.trim(), None, &body).await
}

#[tauri::command]
pub fn preview_local_profile_from_text(
    name: String,
    body: String,
) -> Result<LocalProfilePreview, String> {
    preview_profile_body(name.trim(), None, &body)
}

#[tauri::command]
pub async fn import_local_profile_from_path(
    path: String,
    name: Option<String>,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let path = PathBuf::from(path.trim());
    let body = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read local profile {}: {error}", path.display()))?;
    let display_name = local_profile_display_name(name.as_deref(), &path);
    import_profile_body(&display_name, Some(&path), &body).await
}

#[tauri::command]
pub fn preview_local_profile_from_path(
    path: String,
    name: Option<String>,
) -> Result<LocalProfilePreview, String> {
    let path = PathBuf::from(path.trim());
    let body = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read local profile {}: {error}", path.display()))?;
    let display_name = local_profile_display_name(name.as_deref(), &path);
    preview_profile_body(&display_name, Some(&path), &body)
}

#[tauri::command]
pub async fn import_profile_deep_link(
    link: String,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let parsed = url::Url::parse(link.trim())
        .map_err(|error| format!("Invalid bpn:// import link: {error}"))?;
    if parsed.scheme() != "bpn" {
        return Err("Deep link must use the bpn:// scheme.".to_string());
    }
    let pairs = parsed
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    if let Some(url) = pairs.get("url") {
        let trimmed = validate_subscription_url(url)?;
        let imported =
            fetch_subscription_with_options(trimmed, &PersistedSubscriptionFetchOptions::default())
                .await?;
        write_mihomo_config(&imported.body)?;
        let reload_message =
            maybe_reload_mihomo_after_subscription_change("subscription deep-link import").await;
        let mut store = read_persisted_subscription_profiles()?;
        let now = current_unix_timestamp();
        let existing_index = store.profiles.iter().position(|profile| {
            profile
                .subscription
                .url
                .as_deref()
                .map(|stored| stored.eq_ignore_ascii_case(trimmed))
                .unwrap_or(false)
        });
        let display_name = subscription_profile_display_name(
            pairs.get("name").map(String::as_str),
            &imported.subscription,
            store.profiles.len() + 1,
        );
        let active_id = if let Some(index) = existing_index {
            let profile = &mut store.profiles[index];
            profile.name = display_name;
            profile.subscription = imported.subscription.clone();
            profile.protected_url = Some(protect_secret(trimmed)?);
            profile.protected_body = Some(protect_secret(&imported.body)?);
            profile.last_successful_refresh_at = Some(now);
            profile.last_failed_refresh_at = None;
            profile.last_refresh_error = None;
            profile.next_refresh_at = next_profile_refresh_at(&profile.subscription, now);
            profile.updated_at = now;
            profile.id.clone()
        } else {
            let id = subscription_profile_id(trimmed, now);
            store.profiles.push(PersistedSubscriptionProfile {
                id: id.clone(),
                name: display_name,
                description: None,
                subscription: imported.subscription.clone(),
                protected_url: Some(protect_secret(trimmed)?),
                protected_body: Some(protect_secret(&imported.body)?),
                last_successful_refresh_at: Some(now),
                last_failed_refresh_at: None,
                last_refresh_error: None,
                next_refresh_at: next_profile_refresh_at(&imported.subscription, now),
                fetch_options: PersistedSubscriptionFetchOptions::default(),
                created_at: now,
                updated_at: now,
            });
            id
        };
        store.active_id = Some(active_id);
        write_persisted_subscription_profiles(&store)?;
        persist_subscription_state_with_body(&imported.subscription, Some(&imported.body))?;
        let state = apply_active_subscription_state(
            imported.subscription,
            Some("Subscription imported from bpn:// link.".to_string()),
        )?;
        return Ok(SubscriptionProfilesApplyResult {
            profiles: build_subscription_profiles_state()?,
            state,
            message: reload_message
                .unwrap_or_else(|| "Deep link subscription imported and selected.".to_string()),
        });
    }
    if let Some(data) = pairs.get("data") {
        let decoded = general_purpose::STANDARD
            .decode(data)
            .map_err(|error| format!("Invalid deep link profile payload: {error}"))?;
        let body = String::from_utf8(decoded)
            .map_err(|error| format!("Deep link profile payload is not UTF-8: {error}"))?;
        return import_profile_body(
            pairs
                .get("name")
                .map(String::as_str)
                .unwrap_or("Deep link profile"),
            None,
            &body,
        )
        .await;
    }
    Err("bpn:// import link must include url= or data=.".to_string())
}

#[tauri::command]
pub async fn refresh_all_subscription_profiles() -> Result<SubscriptionProfilesApplyResult, String>
{
    refresh_subscription_profiles(false).await
}

#[tauri::command]
pub async fn refresh_due_subscription_profiles() -> Result<SubscriptionProfilesApplyResult, String>
{
    refresh_subscription_profiles(true).await
}

async fn refresh_subscription_profiles(
    only_due: bool,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let mut store = read_persisted_subscription_profiles()?;
    let mut refreshed = 0_usize;
    let mut failed = 0_usize;
    let mut skipped = 0_usize;
    let now = current_unix_timestamp();
    for profile in &mut store.profiles {
        if only_due && !subscription_profile_is_due_for_refresh(profile, now) {
            skipped += 1;
            continue;
        }
        let Some(url) = profile.subscription.url.clone() else {
            skipped += 1;
            continue;
        };
        match fetch_subscription_with_options(&url, &profile.fetch_options).await {
            Ok(imported) => {
                profile.subscription = imported.subscription;
                profile.protected_url = Some(protect_secret(&url)?);
                profile.protected_body = Some(protect_secret(&imported.body)?);
                profile.last_successful_refresh_at = Some(current_unix_timestamp());
                profile.last_failed_refresh_at = None;
                profile.last_refresh_error = None;
                profile.next_refresh_at = next_profile_refresh_at(
                    &profile.subscription,
                    profile
                        .last_successful_refresh_at
                        .unwrap_or_else(current_unix_timestamp),
                );
                profile.updated_at = current_unix_timestamp();
                refreshed += 1;
            }
            Err(error) => {
                log_event(
                    "subscription-profile",
                    format!(
                        "refresh-all preserved cached profile id={} after failure: {error}",
                        profile.id
                    ),
                );
                profile.last_failed_refresh_at = Some(current_unix_timestamp());
                profile.last_refresh_error = Some(redact_sensitive_text(&error));
                failed += 1;
            }
        }
    }
    write_persisted_subscription_profiles(&store)?;
    if let Some(active_id) = store.active_id.as_deref() {
        if let Some(active) = store
            .profiles
            .iter()
            .find(|profile| profile.id == active_id)
        {
            persist_subscription_state_with_body(
                &active.subscription,
                active
                    .protected_body
                    .as_deref()
                    .and_then(|value| unprotect_secret(value).ok())
                    .as_deref(),
            )?;
        }
    }
    let state = status().await?;
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message: if only_due {
            format!("{refreshed} due profile(s) refreshed; {failed} preserved from cache; {skipped} skipped.")
        } else {
            format!(
                "{refreshed} profile(s) refreshed; {failed} preserved from cache; {skipped} local profile(s) skipped."
            )
        },
    })
}

fn subscription_profile_is_due_for_refresh(
    profile: &PersistedSubscriptionProfile,
    now: u64,
) -> bool {
    match profile.next_refresh_at {
        Some(due_at) => due_at <= now,
        None => profile.last_successful_refresh_at.is_none(),
    }
}

#[tauri::command]
pub fn update_subscription_profile_fetch_options(
    id: String,
    timeout_seconds: u64,
    proxy_mode: String,
    custom_proxy_url: Option<String>,
    user_agent: Option<String>,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let mut store = read_persisted_subscription_profiles()?;
    let mode = SubscriptionFetchProxyMode::from_wire(&proxy_mode)?;
    let timeout_seconds = timeout_seconds.clamp(5, 120);
    let profile = store
        .profiles
        .iter_mut()
        .find(|profile| profile.id == id)
        .ok_or_else(|| "Subscription profile was not found.".to_string())?;
    let protected_custom_proxy_url = if mode == SubscriptionFetchProxyMode::Custom {
        if let Some(proxy_url) = custom_proxy_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            validate_custom_fetch_proxy_url(proxy_url)?;
            Some(protect_secret(proxy_url)?)
        } else {
            Some(
                profile
                    .fetch_options
                    .protected_custom_proxy_url
                    .clone()
                    .ok_or_else(|| {
                        "Custom fetch proxy URL is required for custom mode.".to_string()
                    })?,
            )
        }
    } else {
        None
    };
    profile.fetch_options = PersistedSubscriptionFetchOptions {
        timeout_seconds,
        proxy_mode: mode,
        protected_custom_proxy_url,
        user_agent: normalize_subscription_fetch_user_agent(
            user_agent,
            profile.fetch_options.user_agent.as_deref(),
        )?,
    };
    profile.updated_at = current_unix_timestamp();
    write_persisted_subscription_profiles(&store)?;
    let state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?
        .clone();
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message: "Subscription fetch options saved.".to_string(),
    })
}

#[tauri::command]
pub fn export_backup_bundle() -> Result<BackupActionResult, String> {
    let snapshot = BackupBundle {
        schema: 1,
        generated_at: current_unix_timestamp(),
        settings: load_app_settings(),
        subscription_profiles: subscription_profiles_backup_snapshot()?,
        proxy_selections: read_proxy_selections().unwrap_or_default(),
    };
    let dir = data_dir()?.join("backups");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create backup directory: {error}"))?;
    let path = dir.join(format!("badvpn-backup-{}.json", snapshot.generated_at));
    let content = serde_json::to_string_pretty(&snapshot)
        .map_err(|error| format!("Failed to serialize backup: {error}"))?;
    fs::write(&path, content)
        .map_err(|error| format!("Failed to write backup {}: {error}", path.display()))?;
    Ok(BackupActionResult {
        message: format!("Backup exported to {}.", redact_path(&path)),
        path: Some(path.to_string_lossy().to_string()),
        history: backup_history_snapshot()?,
    })
}

#[tauri::command]
pub fn restore_backup_bundle_from_path(path: String) -> Result<BackupActionResult, String> {
    let path = PathBuf::from(path.trim());
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read backup {}: {error}", path.display()))?;
    let backup = serde_json::from_str::<BackupBundle>(&content)
        .map_err(|error| format!("Backup schema validation failed: {error}"))?;
    if backup.schema != 1 {
        return Err("Unsupported backup schema.".to_string());
    }
    write_settings_to_path(&settings_file_path()?, &backup.settings)?;
    write_persisted_subscription_profiles(&backup.subscription_profiles)?;
    let restored_active = backup
        .subscription_profiles
        .active_id
        .as_deref()
        .and_then(|active_id| {
            backup
                .subscription_profiles
                .profiles
                .iter()
                .find(|profile| profile.id == active_id)
        });
    if let Some(active) = restored_active {
        persist_subscription_state_with_body(
            &active.subscription,
            active
                .protected_body
                .as_deref()
                .and_then(|value| unprotect_secret(value).ok())
                .as_deref(),
        )?;
    } else {
        clear_legacy_subscription_state()?;
    }
    persist_proxy_selections(&backup.proxy_selections)?;
    Ok(BackupActionResult {
        message: "Backup settings and subscription profiles restored. Reconnect to apply runtime settings.".to_string(),
        path: Some(path.to_string_lossy().to_string()),
        history: backup_history_snapshot()?,
    })
}

#[tauri::command]
pub fn export_support_bundle() -> Result<BackupActionResult, String> {
    let dir = data_dir()?.join("support-bundles");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create support bundle directory: {error}"))?;
    let path = dir.join(format!("badvpn-support-{}.txt", current_unix_timestamp()));
    let snapshot = operator_snapshot_blocking()?;
    let body = redacted_support_bundle_text(&snapshot);
    fs::write(&path, body)
        .map_err(|error| format!("Failed to write support bundle {}: {error}", path.display()))?;
    Ok(BackupActionResult {
        message: format!("Support bundle exported to {}.", redact_path(&path)),
        path: Some(path.to_string_lossy().to_string()),
        history: backup_history_snapshot()?,
    })
}

#[tauri::command]
pub fn open_operator_directory(kind: String) -> Result<String, String> {
    let path = match kind.trim() {
        "app_data" => data_dir()?,
        "runtime" => programdata_dir()?,
        "logs" => data_dir()?.join("logs"),
        "backups" => data_dir()?.join("backups"),
        _ => return Err("Unknown directory kind.".to_string()),
    };
    fs::create_dir_all(&path)
        .map_err(|error| format!("Failed to create directory {}: {error}", path.display()))?;
    #[cfg(windows)]
    {
        let mut command = Command::new("explorer");
        command.arg(&path);
        hide_process_window(&mut command);
        let _ = command
            .spawn()
            .map_err(|error| format!("Failed to open directory {}: {error}", path.display()))?;
    }
    Ok(path.to_string_lossy().to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorSnapshot {
    pub generated_at: u64,
    pub providers: ProviderCatalog,
    pub resources: ResourceCatalog,
    pub logs: RuntimeLogSnapshot,
    pub config: RuntimeConfigSnapshot,
    pub health: ZapretHealthReport,
    pub game_profiles: GameProfilesCatalog,
    pub backups: BackupHistory,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderCatalog {
    pub rule_providers: Vec<ProviderView>,
    pub proxy_providers: Vec<ProviderView>,
    pub update_status: String,
    pub provider_editing: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderView {
    pub name: String,
    pub provider_type: String,
    pub behavior: String,
    pub path: Option<String>,
    pub url_redacted: Option<String>,
    pub interval_seconds: Option<u64>,
    pub vehicle: Option<String>,
    pub health_check: Option<String>,
    pub consumed_by_bpn: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceCatalog {
    pub resources: Vec<OperatorResource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorResource {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub path: String,
    pub installed: bool,
    pub version: Option<String>,
    pub last_modified: Option<u64>,
    pub source: String,
    pub update_supported: bool,
    pub rollback_available: bool,
    pub verification_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceActionResult {
    pub changed: bool,
    pub message: String,
    pub resources: ResourceCatalog,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeLogSnapshot {
    pub sources: Vec<RuntimeLogSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeLogSource {
    pub id: String,
    pub label: String,
    pub path: String,
    pub lines: Vec<RuntimeLogLine>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeLogLine {
    pub source: String,
    pub level: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeConfigSnapshot {
    pub source_profile: RedactedTextArtifact,
    pub runtime_yaml: RedactedTextArtifact,
    pub diff: RedactedTextArtifact,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedTextArtifact {
    pub label: String,
    pub path: Option<String>,
    pub text: String,
    pub line_count: usize,
    pub redacted: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZapretHealthReport {
    pub checked_at: u64,
    pub checks: Vec<ZapretHealthCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZapretHealthCheck {
    pub id: String,
    pub label: String,
    pub domain: String,
    pub route_path: String,
    pub dns_result: String,
    pub probe_result: String,
    pub zapret_list: String,
    pub recovery_action: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GameProfilesCatalog {
    pub known: Vec<RuntimeGameProfile>,
    pub detected: Vec<RuntimeGameProfile>,
    pub learned: Vec<RuntimeGameProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupBundle {
    schema: u16,
    generated_at: u64,
    settings: AppSettings,
    subscription_profiles: PersistedSubscriptionProfiles,
    proxy_selections: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupHistory {
    pub backups: Vec<BackupFileView>,
    pub support_bundles: Vec<BackupFileView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupFileView {
    pub name: String,
    pub path: String,
    pub modified_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupActionResult {
    pub message: String,
    pub path: Option<String>,
    pub history: BackupHistory,
}

#[derive(Debug, Clone)]
struct OperatorResourceDef {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    path: PathBuf,
    source: &'static str,
    url: Option<&'static str>,
    min_lines: usize,
}

fn operator_snapshot_blocking() -> Result<OperatorSnapshot, String> {
    let policy = last_preview_policy()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .map(|policy| {
            let mut summary: badvpn_common::ipc::PolicySummaryResponse = (&policy).into();
            summary.source = "import_preview".to_string();
            summary
        })
        .unwrap_or_else(badvpn_common::ipc::PolicySummaryResponse::empty);
    Ok(OperatorSnapshot {
        generated_at: current_unix_timestamp(),
        providers: operator_provider_catalog().unwrap_or_else(|error| ProviderCatalog {
            rule_providers: Vec::new(),
            proxy_providers: Vec::new(),
            update_status: format!("Provider read failed: {error}"),
            provider_editing: "Provider editing is read-only in this implementation slice."
                .to_string(),
        }),
        resources: operator_resource_catalog()?,
        logs: runtime_log_snapshot(240),
        config: runtime_config_snapshot()?,
        health: zapret_health_definitions(&policy),
        game_profiles: game_profiles_catalog(&load_app_settings()),
        backups: backup_history_snapshot()?,
    })
}

fn operator_provider_catalog() -> Result<ProviderCatalog, String> {
    let path = active_mihomo_config_path()?;
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read runtime config: {error}"))?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content)
        .map_err(|error| format!("Failed to parse runtime config: {error}"))?;
    let rule_providers = provider_map_to_views(&yaml, "rule-providers");
    let proxy_providers = provider_map_to_views(&yaml, "proxy-providers");
    Ok(ProviderCatalog {
        update_status: if rule_providers.is_empty() && proxy_providers.is_empty() {
            "No rule-providers or proxy-providers are present in the generated runtime config."
                .to_string()
        } else {
            "Providers are shown read-only; manual provider update waits for validated rollback."
                .to_string()
        },
        provider_editing:
            "Direct provider content editing is disabled in this implementation slice.".to_string(),
        rule_providers,
        proxy_providers,
    })
}

fn provider_map_to_views(yaml: &YamlValue, key: &str) -> Vec<ProviderView> {
    yaml.get(key)
        .and_then(YamlValue::as_mapping)
        .map(|map| {
            map.iter()
                .filter_map(|(name, value)| {
                    let name = name.as_str()?.to_string();
                    let url = value.get("url").and_then(YamlValue::as_str).map(redact_url);
                    let path = value
                        .get("path")
                        .and_then(YamlValue::as_str)
                        .map(redact_path_string);
                    let provider_type = value
                        .get("type")
                        .and_then(YamlValue::as_str)
                        .unwrap_or("http")
                        .to_string();
                    let behavior = value
                        .get("behavior")
                        .and_then(YamlValue::as_str)
                        .unwrap_or("domain")
                        .to_string();
                    let vehicle = value
                        .get("format")
                        .and_then(YamlValue::as_str)
                        .or_else(|| value.get("vehicle").and_then(YamlValue::as_str))
                        .map(ToOwned::to_owned);
                    let interval_seconds = value.get("interval").and_then(YamlValue::as_u64);
                    let health_check = value.get("health-check").map(|health| {
                        redact_sensitive_text(&serde_yaml::to_string(health).unwrap_or_default())
                    });
                    let lower_name = name.to_ascii_lowercase();
                    let consumed_by_bpn = ["badvpn", "zapret", "discord", "youtube", "google"]
                        .iter()
                        .any(|needle| lower_name.contains(needle));
                    Some(ProviderView {
                        name,
                        provider_type,
                        behavior,
                        path,
                        url_redacted: url,
                        interval_seconds,
                        vehicle,
                        health_check,
                        consumed_by_bpn,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn operator_resource_catalog() -> Result<ResourceCatalog, String> {
    let mut resources = Vec::new();
    for def in operator_resource_defs() {
        let installed = def.path.exists();
        let metadata = fs::metadata(&def.path).ok();
        let last_modified = metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        let version = if def.id == "flowseal-version" {
            fs::read_to_string(&def.path)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        } else if def.id == "runtime-components" {
            Some(format!(
                "mihomo={}, zapret={}",
                local_component_version("mihomo").unwrap_or_else(|| "missing".to_string()),
                local_component_version("zapret").unwrap_or_else(|| "missing".to_string())
            ))
        } else {
            metadata
                .as_ref()
                .map(|metadata| format!("{} bytes", metadata.len()))
        };
        let verification_status = if installed {
            let body = fs::read(&def.path).unwrap_or_default();
            resource_digest_status(&def.path, &body)
        } else if def.url.is_some() {
            "missing; update can stage a checked copy".to_string()
        } else {
            "not installed".to_string()
        };
        resources.push(OperatorResource {
            id: def.id.to_string(),
            label: def.label.to_string(),
            kind: def.kind.to_string(),
            path: redact_path(&def.path),
            installed,
            version,
            last_modified,
            source: def.source.to_string(),
            update_supported: def.url.is_some() || def.id == "runtime-components",
            rollback_available: newest_resource_backup(&def.path).is_some(),
            verification_status,
        });
    }
    Ok(ResourceCatalog { resources })
}

fn operator_resource_defs() -> Vec<OperatorResourceDef> {
    let lists = zapret_lists_dir().unwrap_or_else(|_| PathBuf::from("zapret/lists"));
    let data = data_dir().unwrap_or_else(|_| PathBuf::from("BadVpn"));
    vec![
        OperatorResourceDef {
            id: "runtime-components",
            label: "Mihomo + zapret binaries",
            kind: "runtime",
            path: data.join("components"),
            source: "BPN component/runtime updater",
            url: None,
            min_lines: 0,
        },
        OperatorResourceDef {
            id: "flowseal-version",
            label: "Flowseal version",
            kind: "zapret_list",
            path: lists.join("flowseal-version.txt"),
            source: FLOWSEAL_VERSION_URL,
            url: Some(FLOWSEAL_VERSION_URL),
            min_lines: 1,
        },
        OperatorResourceDef {
            id: "flowseal-general",
            label: "Flowseal general hostlist",
            kind: "zapret_list",
            path: lists.join("list-general.txt"),
            source: FLOWSEAL_LIST_GENERAL_URL,
            url: Some(FLOWSEAL_LIST_GENERAL_URL),
            min_lines: 20,
        },
        OperatorResourceDef {
            id: "flowseal-google",
            label: "Flowseal Google hostlist",
            kind: "zapret_list",
            path: lists.join("list-google.txt"),
            source: FLOWSEAL_LIST_GOOGLE_URL,
            url: Some(FLOWSEAL_LIST_GOOGLE_URL),
            min_lines: 5,
        },
        OperatorResourceDef {
            id: "flowseal-exclude",
            label: "Flowseal exclude hostlist",
            kind: "zapret_list",
            path: lists.join("list-exclude.txt"),
            source: FLOWSEAL_LIST_EXCLUDE_URL,
            url: Some(FLOWSEAL_LIST_EXCLUDE_URL),
            min_lines: 1,
        },
        OperatorResourceDef {
            id: "flowseal-ipset",
            label: "Flowseal ipset",
            kind: "zapret_ipset",
            path: lists.join("ipset-service.txt"),
            source: FLOWSEAL_IPSET_URL,
            url: Some(FLOWSEAL_IPSET_URL),
            min_lines: 5,
        },
        OperatorResourceDef {
            id: "flowseal-ipset-exclude",
            label: "Flowseal ipset exclude",
            kind: "zapret_ipset",
            path: lists.join("ipset-exclude.txt"),
            source: FLOWSEAL_IPSET_EXCLUDE_URL,
            url: Some(FLOWSEAL_IPSET_EXCLUDE_URL),
            min_lines: 1,
        },
        OperatorResourceDef {
            id: "geosite",
            label: "geosite database",
            kind: "geodata",
            path: data.join("components").join("mihomo").join("geosite.dat"),
            source: "Mihomo geodata path",
            url: None,
            min_lines: 0,
        },
        OperatorResourceDef {
            id: "geoip",
            label: "geoip database",
            kind: "geodata",
            path: data.join("components").join("mihomo").join("geoip.dat"),
            source: "Mihomo geodata path",
            url: None,
            min_lines: 0,
        },
        OperatorResourceDef {
            id: "mmdb",
            label: "Country MMDB",
            kind: "geodata",
            path: data.join("components").join("mihomo").join("Country.mmdb"),
            source: "Mihomo MMDB path",
            url: None,
            min_lines: 0,
        },
        OperatorResourceDef {
            id: "asn",
            label: "ASN database",
            kind: "geodata",
            path: data
                .join("components")
                .join("mihomo")
                .join("GeoLite2-ASN.mmdb"),
            source: "Optional ASN database path",
            url: None,
            min_lines: 0,
        },
        OperatorResourceDef {
            id: "bpn-curated",
            label: "BPN curated rules",
            kind: "bpn_rules",
            path: data.join("rules").join("bpn-curated.yaml"),
            source: "BPN managed rules",
            url: None,
            min_lines: 0,
        },
    ]
}

async fn update_text_resource(def: &OperatorResourceDef) -> Result<(), String> {
    let url = def
        .url
        .ok_or_else(|| "Resource has no updater URL.".to_string())?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("BadVpn/0.1.0 resource-manager")
        .build()
        .map_err(|error| format!("Failed to create resource HTTP client: {error}"))?;
    let body = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("Failed to download {}: {error}", def.label))?
        .error_for_status()
        .map_err(|error| {
            format!(
                "Resource endpoint returned an error for {}: {error}",
                def.label
            )
        })?
        .text()
        .await
        .map_err(|error| format!("Failed to read {}: {error}", def.label))?;
    activate_text_resource_body(def, &body)
}

fn activate_text_resource_body(def: &OperatorResourceDef, body: &str) -> Result<(), String> {
    let line_count = body.lines().filter(|line| !line.trim().is_empty()).count();
    if line_count < def.min_lines {
        return Err(format!(
            "{} failed structural verification: expected at least {} non-empty lines, got {line_count}.",
            def.label, def.min_lines
        ));
    }
    if let Some(parent) = def.path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create resource directory: {error}"))?;
    }
    let staged = def.path.with_extension("next");
    fs::write(&staged, &body).map_err(|error| format!("Failed to stage {}: {error}", def.label))?;
    let staged_body = fs::read_to_string(&staged)
        .map_err(|error| format!("Failed to verify staged {}: {error}", def.label))?;
    let digest = stable_config_hash(&staged_body);
    if digest != stable_config_hash(&body) {
        let _ = fs::remove_file(&staged);
        return Err(format!("{} staged digest mismatch.", def.label));
    }
    if def.path.exists() {
        let backup = def.path.with_file_name(format!(
            "{}.backup.{}",
            def.path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(def.id),
            current_unix_timestamp()
        ));
        fs::copy(&def.path, &backup).map_err(|error| {
            format!(
                "Failed to preserve previous resource {}: {error}",
                def.path.display()
            )
        })?;
    }
    fs::copy(&staged, &def.path)
        .map_err(|error| format!("Failed to activate {}: {error}", def.label))?;
    let active_body = fs::read_to_string(&def.path)
        .map_err(|error| format!("Failed to verify activated {}: {error}", def.label))?;
    if stable_config_hash(&active_body) != digest {
        let _ = fs::remove_file(&staged);
        return Err(format!("{} activated digest mismatch.", def.label));
    }
    let _ = fs::remove_file(&staged);
    fs::write(def.path.with_extension("hash"), digest)
        .map_err(|error| format!("Failed to write resource digest: {error}"))?;
    Ok(())
}

fn resource_digest_status(path: &Path, body: &[u8]) -> String {
    let digest = stable_bytes_hash(body);
    let recorded = fs::read_to_string(path.with_extension("hash"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match recorded {
        Some(recorded) if recorded == digest => format!("digest verified: {digest}"),
        Some(recorded) => format!("digest mismatch: current={digest} recorded={recorded}"),
        None => format!("content-hash={digest}; no activation digest recorded"),
    }
}

fn newest_resource_backup(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    let file = path.file_name()?.to_string_lossy().to_string();
    let mut backups = fs::read_dir(parent)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with(&format!("{file}.backup.")))
        })
        .collect::<Vec<_>>();
    backups.sort();
    backups.pop()
}

fn runtime_log_snapshot(max_lines: usize) -> RuntimeLogSnapshot {
    let sources = vec![
        ("app", "BPN Client", app_log_path()),
        (
            "agent",
            "badvpn-agent",
            Ok(programdata_dir()
                .unwrap_or_else(|_| PathBuf::from("BadVpn"))
                .join("logs")
                .join("badvpn-agent.log")),
        ),
        (
            "mihomo",
            "Mihomo",
            Ok(data_dir()
                .unwrap_or_else(|_| PathBuf::from("BadVpn"))
                .join("logs")
                .join("mihomo.log")),
        ),
        (
            "zapret",
            "zapret/winws",
            Ok(data_dir()
                .unwrap_or_else(|_| PathBuf::from("BadVpn"))
                .join("logs")
                .join("zapret.log")),
        ),
    ];
    RuntimeLogSnapshot {
        sources: sources
            .into_iter()
            .map(|(id, label, path)| match path {
                Ok(path) => RuntimeLogSource {
                    id: id.to_string(),
                    label: label.to_string(),
                    path: redact_path(&path),
                    lines: read_redacted_log_lines(id, &path, max_lines).unwrap_or_default(),
                    error: if path.exists() {
                        None
                    } else {
                        Some("Log file is not present yet.".to_string())
                    },
                },
                Err(error) => RuntimeLogSource {
                    id: id.to_string(),
                    label: label.to_string(),
                    path: String::new(),
                    lines: Vec::new(),
                    error: Some(error),
                },
            })
            .collect(),
    }
}

fn read_redacted_log_lines(
    source: &str,
    path: &Path,
    max_lines: usize,
) -> Result<Vec<RuntimeLogLine>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read log {}: {error}", path.display()))?;
    let mut lines = content
        .lines()
        .rev()
        .take(max_lines)
        .map(|line| {
            let text = redact_sensitive_text(line);
            RuntimeLogLine {
                source: source.to_string(),
                level: classify_log_level(&text),
                text,
            }
        })
        .collect::<Vec<_>>();
    lines.reverse();
    Ok(lines)
}

fn classify_log_level(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if lower.contains(" error") || lower.contains("[error]") || lower.contains("failed") {
        "error".to_string()
    } else if lower.contains(" warn") || lower.contains("[warn]") || lower.contains("warning") {
        "warning".to_string()
    } else if lower.contains(" debug") || lower.contains("[debug]") {
        "debug".to_string()
    } else {
        "info".to_string()
    }
}

fn runtime_config_snapshot() -> Result<RuntimeConfigSnapshot, String> {
    let source_body =
        active_persisted_subscription_profile_body().or_else(existing_mihomo_config_profile_body);
    let source_profile = text_artifact(
        "Source subscription profile",
        None,
        source_body.as_deref(),
        source_body
            .is_none()
            .then_some("No cached source profile body is available."),
    );
    let runtime_path = active_mihomo_config_path().ok();
    let runtime_body = runtime_path
        .as_ref()
        .and_then(|path| fs::read_to_string(path).ok());
    let runtime_yaml = text_artifact(
        "Generated runtime YAML",
        runtime_path.as_deref(),
        runtime_body.as_deref(),
        runtime_body
            .is_none()
            .then_some("Generated runtime YAML is not present yet."),
    );
    let diff_text = match (source_body.as_deref(), runtime_body.as_deref()) {
        (Some(source), Some(runtime)) => simple_redacted_diff(source, runtime),
        _ => "Diff is available after both source and runtime YAML exist.".to_string(),
    };
    Ok(RuntimeConfigSnapshot {
        source_profile,
        runtime_yaml,
        diff: RedactedTextArtifact {
            label: "Source -> runtime diff".to_string(),
            path: None,
            line_count: diff_text.lines().count(),
            text: diff_text,
            redacted: true,
            error: None,
        },
        read_only: true,
    })
}

fn text_artifact(
    label: &str,
    path: Option<&Path>,
    text: Option<&str>,
    error: Option<&str>,
) -> RedactedTextArtifact {
    let redacted = text.map(redact_sensitive_text).unwrap_or_default();
    RedactedTextArtifact {
        label: label.to_string(),
        path: path.map(redact_path),
        line_count: redacted.lines().count(),
        text: redacted,
        redacted: true,
        error: error.map(ToOwned::to_owned),
    }
}

fn simple_redacted_diff(source: &str, runtime: &str) -> String {
    let source = redact_sensitive_text(source);
    let runtime = redact_sensitive_text(runtime);
    let source_lines = source.lines().collect::<BTreeSet<_>>();
    let runtime_lines = runtime.lines().collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    out.push("# BPN overlay changes".to_string());
    for line in runtime_lines.difference(&source_lines).take(300) {
        if line.trim().is_empty() {
            continue;
        }
        out.push(format!("+ {line}"));
    }
    out.push("# Provider/source lines not present in runtime".to_string());
    for line in source_lines.difference(&runtime_lines).take(120) {
        if line.trim().is_empty() {
            continue;
        }
        out.push(format!("- {line}"));
    }
    if out.len() <= 2 {
        out.push("No line-level differences detected after redaction.".to_string());
    }
    out.join("\n")
}

fn zapret_health_definitions(
    policy: &badvpn_common::ipc::PolicySummaryResponse,
) -> ZapretHealthReport {
    let mut checks = vec![
        health_definition("youtube", "YouTube", "youtube.com"),
        health_definition("discord", "Discord voice/CDN", "discord.com"),
        health_definition("openai", "ChatGPT/OpenAI", "chatgpt.com"),
        health_definition("claude", "Claude", "claude.ai"),
        health_definition("gemini", "Gemini", "gemini.google.com"),
    ];
    for check in &mut checks {
        check.route_path = route_path_for_domain(policy, &check.domain);
        check.zapret_list = "not-checked".to_string();
        check.dns_result = "not-run".to_string();
        check.probe_result = "not-run".to_string();
    }
    ZapretHealthReport {
        checked_at: current_unix_timestamp(),
        checks,
    }
}

fn health_definition(id: &str, label: &str, domain: &str) -> ZapretHealthCheck {
    ZapretHealthCheck {
        id: id.to_string(),
        label: label.to_string(),
        domain: domain.to_string(),
        route_path: "unknown".to_string(),
        dns_result: "not-run".to_string(),
        probe_result: "not-run".to_string(),
        zapret_list: "not-run".to_string(),
        recovery_action: "Run diagnostics, refresh Flowseal lists, then reconnect Smart mode."
            .to_string(),
        status: "idle".to_string(),
    }
}

fn route_path_for_domain(
    policy: &badvpn_common::ipc::PolicySummaryResponse,
    domain: &str,
) -> String {
    let needle = domain.to_ascii_lowercase();
    policy
        .policy_rules
        .iter()
        .find(|rule| {
            let value = rule.target_value.to_ascii_lowercase();
            needle == value || needle.ends_with(&format!(".{value}"))
        })
        .map(|rule| {
            if rule.path.contains("ZapretDirect") {
                "zapret"
            } else if rule.path.contains("VpnProxy") {
                "vpn"
            } else if rule.path.contains("DirectSafe") {
                "direct"
            } else if rule.path.contains("Reject") {
                "blocked"
            } else {
                "unknown"
            }
            .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_hostlist_values() -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for file in [
        zapret_lists_dir()?.join("list-general.txt"),
        zapret_lists_dir()?.join("list-google.txt"),
        zapret_lists_dir()?.join("zapret_hostlist.txt"),
    ] {
        if let Ok(content) = fs::read_to_string(file) {
            values.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(|line| line.trim_start_matches("+.").to_ascii_lowercase()),
            );
        }
    }
    Ok(values)
}

fn hostlist_contains_domain(values: &[String], domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    values
        .iter()
        .any(|value| domain == *value || domain.ends_with(&format!(".{value}")))
}

async fn dns_answer_class(domain: &str) -> String {
    match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((domain, 443)),
    )
    .await
    {
        Ok(Ok(iter)) => {
            let addrs = iter.collect::<Vec<_>>();
            let v4 = addrs.iter().any(|addr| addr.ip().is_ipv4());
            let v6 = addrs.iter().any(|addr| addr.ip().is_ipv6());
            match (v4, v6) {
                (true, true) => "A+AAAA".to_string(),
                (true, false) => "A".to_string(),
                (false, true) => "AAAA".to_string(),
                _ => "empty".to_string(),
            }
        }
        Ok(Err(error)) => format!("dns-error: {error}"),
        Err(_) => "dns-timeout".to_string(),
    }
}

async fn safe_https_probe(client: &reqwest::Client, domain: &str) -> String {
    let url = format!("https://{domain}/");
    match tokio::time::timeout(Duration::from_secs(5), client.head(url).send()).await {
        Ok(Ok(response)) => format!("ok-http-{}", response.status().as_u16()),
        Ok(Err(error)) if error.is_timeout() => "timeout".to_string(),
        Ok(Err(error)) if error.is_connect() => "connect-error".to_string(),
        Ok(Err(error)) => format!("http-error: {error}"),
        Err(_) => "timeout".to_string(),
    }
}

fn normalize_check_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_start_matches("*.")
        .to_ascii_lowercase()
}

fn game_profiles_catalog(settings: &AppSettings) -> GameProfilesCatalog {
    let known = known_game_profiles();
    let running = running_process_names();
    let detected = known
        .iter()
        .filter(|profile| {
            profile
                .process_names
                .iter()
                .any(|process| running.contains(&process.to_ascii_lowercase()))
        })
        .cloned()
        .map(|mut profile| {
            profile.detected = true;
            profile
        })
        .collect();
    GameProfilesCatalog {
        known,
        detected,
        learned: settings
            .zapret
            .learned_game_profiles
            .iter()
            .map(runtime_game_profile_from_settings)
            .collect(),
    }
}

fn known_game_profiles() -> Vec<RuntimeGameProfile> {
    vec![
        RuntimeGameProfile {
            id: "discord_rtc".to_string(),
            title: "Discord voice".to_string(),
            process_names: vec!["Discord.exe".to_string()],
            domains: vec!["discord.com".to_string(), "discord.gg".to_string()],
            udp_ports: vec!["50000-50100".to_string()],
            filter_mode: "udp_first".to_string(),
            risk_level: "low".to_string(),
            ..RuntimeGameProfile::default()
        },
        RuntimeGameProfile {
            id: "steam".to_string(),
            title: "Steam games".to_string(),
            process_names: vec!["steam.exe".to_string(), "steamwebhelper.exe".to_string()],
            domains: vec![
                "steamcontent.com".to_string(),
                "steamstatic.com".to_string(),
            ],
            udp_ports: vec!["27000-27100".to_string()],
            filter_mode: "udp_first".to_string(),
            risk_level: "normal".to_string(),
            ..RuntimeGameProfile::default()
        },
        RuntimeGameProfile {
            id: "epic".to_string(),
            title: "Epic Games".to_string(),
            process_names: vec!["EpicGamesLauncher.exe".to_string()],
            domains: vec!["epicgames.com".to_string()],
            udp_ports: vec!["50000-50100".to_string()],
            filter_mode: "tcp_udp".to_string(),
            risk_level: "normal".to_string(),
            ..RuntimeGameProfile::default()
        },
    ]
}

fn running_process_names() -> BTreeSet<String> {
    #[cfg(not(windows))]
    {
        BTreeSet::new()
    }

    #[cfg(windows)]
    {
        let mut command = Command::new("powershell");
        command.args([
            "-NoProfile",
            "-Command",
            "Get-Process | Select-Object -ExpandProperty ProcessName",
        ]);
        hide_process_window(&mut command);
        command
            .output()
            .ok()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .flat_map(|line| [format!("{line}.exe"), line.to_string()])
                    .map(|line| line.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    }
}

async fn import_profile_body(
    name: &str,
    source_path: Option<&Path>,
    body: &str,
) -> Result<SubscriptionProfilesApplyResult, String> {
    let summary = summarize_subscription_body(body);
    if summary.node_count == 0 {
        return Err("Imported local profile does not contain supported proxy nodes.".to_string());
    }
    write_mihomo_config(body)?;
    let now = current_unix_timestamp();
    let subscription = SubscriptionState {
        url: None,
        is_valid: Some(true),
        validation_error: None,
        last_refreshed_at: Some(now.to_string()),
        profile_title: Some(if name.trim().is_empty() {
            "Local profile".to_string()
        } else {
            name.trim().to_string()
        }),
        announce: source_path.map(|path| {
            format!(
                "Imported from local file {}; raw path is not stored in profile metadata.",
                path.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("profile")
            )
        }),
        announce_url: None,
        support_url: None,
        profile_web_page_url: None,
        update_interval_hours: None,
        user_info: Default::default(),
        node_count: summary.node_count,
        format: summary.format,
    };
    let id = format!(
        "local-{}",
        stable_config_hash(&format!("{now}:{name}:{body}"))
    );
    let mut store = read_persisted_subscription_profiles()?;
    if let Some(existing) = store.profiles.iter_mut().find(|profile| profile.id == id) {
        existing.name = subscription
            .profile_title
            .clone()
            .unwrap_or_else(|| "Local profile".to_string());
        existing.subscription = subscription.clone();
        existing.protected_body = Some(protect_secret(body)?);
        existing.last_successful_refresh_at = Some(now);
        existing.last_failed_refresh_at = None;
        existing.last_refresh_error = None;
        existing.next_refresh_at = next_profile_refresh_at(&subscription, now);
        existing.updated_at = now;
    } else {
        store.profiles.push(PersistedSubscriptionProfile {
            id: id.clone(),
            name: subscription
                .profile_title
                .clone()
                .unwrap_or_else(|| "Local profile".to_string()),
            description: None,
            subscription: subscription.clone(),
            protected_url: None,
            protected_body: Some(protect_secret(body)?),
            last_successful_refresh_at: Some(now),
            last_failed_refresh_at: None,
            last_refresh_error: None,
            next_refresh_at: next_profile_refresh_at(&subscription, now),
            fetch_options: PersistedSubscriptionFetchOptions::default(),
            created_at: now,
            updated_at: now,
        });
    }
    store.active_id = Some(id);
    write_persisted_subscription_profiles(&store)?;
    persist_subscription_state_with_body(&subscription, Some(body))?;
    let state = apply_active_subscription_state(
        subscription,
        Some("Local profile imported and validated.".to_string()),
    )?;
    Ok(SubscriptionProfilesApplyResult {
        profiles: build_subscription_profiles_state()?,
        state,
        message: "Local profile imported and selected.".to_string(),
    })
}

fn preview_profile_body(
    name: &str,
    source_path: Option<&Path>,
    body: &str,
) -> Result<LocalProfilePreview, String> {
    let summary = summarize_subscription_body(body);
    let display_name = if name.trim().is_empty() {
        "Local profile".to_string()
    } else {
        name.trim().to_string()
    };
    Ok(LocalProfilePreview {
        display_name,
        source_file_name: source_path
            .and_then(|path| path.file_name())
            .and_then(|value| value.to_str())
            .map(ToOwned::to_owned),
        format: summary.format,
        node_count: summary.node_count,
        decoded_size_bytes: summary.decoded_size_bytes,
        import_ready: summary.node_count > 0,
        warning: if summary.node_count == 0 {
            Some("Profile preview found no supported proxy nodes.".to_string())
        } else {
            None
        },
    })
}

fn local_profile_display_name(name: Option<&str>, path: &Path) -> String {
    name.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "Local profile".to_string())
}

fn backup_history_snapshot() -> Result<BackupHistory, String> {
    Ok(BackupHistory {
        backups: list_backup_files(&data_dir()?.join("backups"), "badvpn-backup")?,
        support_bundles: list_backup_files(&data_dir()?.join("support-bundles"), "badvpn-support")?,
    })
}

fn list_backup_files(dir: &Path, prefix: &str) -> Result<Vec<BackupFileView>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = fs::read_dir(dir)
        .map_err(|error| format!("Failed to read backup directory {}: {error}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .map(|path| {
            let modified_at = fs::metadata(&path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            BackupFileView {
                name: path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("backup")
                    .to_string(),
                path: path.to_string_lossy().to_string(),
                modified_at,
            }
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    files.truncate(20);
    Ok(files)
}

fn redacted_support_bundle_text(snapshot: &OperatorSnapshot) -> String {
    let policy = last_preview_policy()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .map(|policy| {
            let summary: badvpn_common::ipc::PolicySummaryResponse = (&policy).into();
            format!(
                "available={} rules={} suppressed={} zapret_domains={} warnings={}",
                summary.available,
                summary.rule_count,
                summary.suppressed_count,
                summary.zapret_domain_count,
                summary.warnings_count
            )
        })
        .unwrap_or_else(|| {
            "available=false rules=0 suppressed=0 zapret_domains=0 warnings=0".to_string()
        });
    let runtime = runtime_readiness()
        .map(|readiness| {
            format!(
                "ready={} components_ready={} mihomo_ready={} zapret_ready={} needs_zapret={} message={}",
                readiness.ready,
                readiness.components_ready,
                readiness.mihomo_ready,
                readiness.zapret_ready,
                readiness.needs_zapret,
                readiness.message
            )
        })
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    let agent_service = read_badvpn_agent_service_status();
    let zapret_service = read_badvpn_zapret_service_status();
    let app_data_path = data_dir()
        .map(|path| redact_path(&path))
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    let runtime_path = programdata_dir()
        .map(|path| redact_path(&path))
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    let log_path = app_log_path()
        .map(|path| redact_path(&path))
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    let app_uptime_seconds = current_unix_timestamp().saturating_sub(app_started_at());
    let override_summary = local_override_support_summary(&load_app_settings());
    let resources = snapshot
        .resources
        .resources
        .iter()
        .map(|resource| {
            format!(
                "{} installed={} version={}",
                resource.id,
                resource.installed,
                resource.version.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let log_lines = snapshot
        .logs
        .sources
        .iter()
        .flat_map(|source| {
            source
                .lines
                .iter()
                .rev()
                .take(30)
                .map(move |line| format!("[{}:{}] {}", source.id, line.level, line.text))
        })
        .collect::<Vec<_>>()
        .join("\n");
    redact_sensitive_text(&format!(
        "BadVpn support bundle\n\
generated_at={}\n\
privacy=redacted\n\
system=os:{} arch:{} family:{}\n\
app_uptime_seconds={app_uptime_seconds}\n\
service_status=agent installed={} running={} ipc_ready={} state={:?}; zapret installed={} running={} state={:?}\n\
admin_elevation=ui-not-elevated-by-design\n\
paths=app_data={app_data_path}; runtime={runtime_path}; logs={log_path}\n\
resources={resources}\n\
policy={policy}\n\
runtime_readiness={runtime}\n\
overrides={override_summary}\n\
providers=rules:{} proxy:{}\n\
runtime_config_lines={}\n\
source_profile_lines={}\n\
health_checks={}\n\n\
logs:\n{log_lines}\n",
        snapshot.generated_at,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY,
        agent_service.installed,
        agent_service.running,
        agent_service.ipc_ready,
        agent_service.state,
        zapret_service.installed,
        zapret_service.running,
        zapret_service.state,
        snapshot.providers.rule_providers.len(),
        snapshot.providers.proxy_providers.len(),
        snapshot.config.runtime_yaml.line_count,
        snapshot.config.source_profile.line_count,
        snapshot.health.checks.len(),
    ))
}

fn local_override_support_summary(settings: &AppSettings) -> String {
    let typed_total = settings.routing_policy.local_overrides.rules.len();
    let typed_enabled = settings
        .routing_policy
        .local_overrides
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .count();
    format!(
        "enabled={} typed={typed_enabled}/{typed_total} legacy_vpn_domains={} legacy_zapret_domains={} legacy_direct_processes={}",
        settings.routing_policy.local_overrides_enabled,
        settings.routing_policy.force_vpn_domains.len(),
        settings.routing_policy.force_zapret_domains.len(),
        settings.routing_policy.force_direct_processes.len()
    )
}

fn redact_sensitive_text(input: &str) -> String {
    let mut lines = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim_start();
        let (list_prefix, key_source) = trimmed
            .strip_prefix("- ")
            .map(|value| ("- ", value.trim_start()))
            .unwrap_or(("", trimmed));
        let lower = key_source.to_ascii_lowercase();
        let sensitive_key = [
            "secret:",
            "authorization:",
            "proxy-authorization:",
            "password:",
            "passwd:",
            "token:",
            "access-token:",
            "refresh-token:",
            "subscription:",
        ]
        .iter()
        .any(|key| lower.starts_with(key));
        if sensitive_key {
            let indent_len = line.len().saturating_sub(trimmed.len());
            let indent = &line[..indent_len];
            let key = key_source.split(':').next().unwrap_or("secret");
            lines.push(format!("{indent}{list_prefix}{key}: <redacted>"));
        } else {
            lines.push(redact_urls_in_line(line));
        }
    }
    lines.join("\n")
}

fn redact_urls_in_line(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        let Some(index) = sensitive_uri_index(rest) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..index]);
        let tail = &rest[index..];
        let end = tail
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | ']' | '}')
            })
            .unwrap_or(tail.len());
        let (url, next) = tail.split_at(end);
        out.push_str(&redact_url(url));
        rest = next;
    }
    out
}

fn sensitive_uri_index(value: &str) -> Option<usize> {
    const SCHEMES: [&str; 7] = [
        "http://",
        "https://",
        "vmess://",
        "vless://",
        "trojan://",
        "ss://",
        "ssr://",
    ];
    SCHEMES.iter().filter_map(|scheme| value.find(scheme)).min()
}

fn redact_path(path: &Path) -> String {
    redact_path_string(&path.to_string_lossy())
}

fn redact_path_string(path: &str) -> String {
    let mut out = path.to_string();
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        if !home.trim().is_empty() {
            out = out.replace(&home, "%USERPROFILE%");
        }
    }
    out
}

async fn refresh_runtime_state(run_network_tests: bool) -> Result<AgentState, String> {
    hydrate_persisted_state()?;
    let settings = load_app_settings();
    let now = current_unix_timestamp();
    let run_network_tests = run_network_tests && settings.diagnostics.discord_youtube_probes;
    if settings.updates.auto_flowseal_list_refresh
        && should_attempt_auto_list_refresh(
            settings.updates.safe_resource_auto_update_interval_hours,
        )
    {
        let _ = ensure_zapret_runtime_lists().await;
    }
    let mut report = collect_runtime_diagnostics(run_network_tests).await;
    let fallback_message =
        match maybe_apply_vpn_fallback_after_zapret_failure(&settings, &report, "status").await {
            Ok(message) => message,
            Err(error) => {
                log_event("routing", format!("VPN fallback apply failed: {error}"));
                None
            }
        };
    if fallback_message.is_some() {
        report = collect_runtime_diagnostics(false).await;
    }
    let restore_message = match maybe_restore_smart_hybrid_after_zapret_recovery(
        &settings, &report, "status",
    )
    .await
    {
        Ok(message) => message,
        Err(error) => {
            log_event("routing", format!("Smart restore failed: {error}"));
            None
        }
    };
    if restore_message.is_some() {
        report = collect_runtime_diagnostics(false).await;
    }
    let metrics = if report.mihomo_healthy {
        fetch_mihomo_connections().await.ok()
    } else {
        None
    };
    let runtime_route_mode =
        detect_mihomo_config_route_mode().unwrap_or_else(|| settings.effective_route_mode());
    let active_fallback_message = active_vpn_fallback_message(&settings, runtime_route_mode);
    let own_mihomo_running =
        child_is_running(mihomo_process()).unwrap_or(false) || recorded_mihomo_is_running();
    if report.mihomo_healthy {
        if let Ok(mut last) = last_mihomo_healthy_at().lock() {
            *last = now;
        }
    }
    let recently_healthy = last_mihomo_healthy_at()
        .lock()
        .map(|last| now.saturating_sub(*last) <= 10)
        .unwrap_or(false);
    let mut current = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    let transition_in_progress = matches!(
        current.connection.status,
        ConnectionStatus::Starting | ConnectionStatus::Stopping
    );
    let keep_runtime_visible = !report.mihomo_healthy
        && own_mihomo_running
        && (recently_healthy || transition_in_progress);
    let effective_mihomo_healthy = report.mihomo_healthy || keep_runtime_visible;

    current.running = effective_mihomo_healthy;
    current.connection.connected = effective_mihomo_healthy && !transition_in_progress;
    current.connection.status = if report.mihomo_healthy {
        ConnectionStatus::Running
    } else if own_mihomo_running {
        ConnectionStatus::Starting
    } else {
        ConnectionStatus::Idle
    };
    current.connection.route_mode = runtime_route_mode;
    current.phase = if report.mihomo_healthy {
        AppPhase::Connected
    } else if own_mihomo_running {
        AppPhase::Connecting
    } else if subscription_is_present(&current.subscription) {
        AppPhase::Ready
    } else {
        AppPhase::Onboarding
    };
    current.diagnostics = DiagnosticSummary {
        mihomo_healthy: effective_mihomo_healthy,
        zapret_healthy: report.zapret_healthy,
        message: Some(append_external_hint_if_needed(
            fallback_message
                .or(restore_message)
                .or(active_fallback_message)
                .map(|message| format!("{message} {}", report.summary))
                .unwrap_or_else(|| {
                    if keep_runtime_visible {
                        format!(
                            "Mihomo process is still running; waiting for the local controller to respond. {}",
                            report.summary
                        )
                    } else {
                        report.summary
                    }
                }),
            effective_mihomo_healthy,
        )),
    };

    if let Some(connections) = metrics {
        current.metrics.upload_bytes = connections.upload_total;
        current.metrics.download_bytes = connections.download_total;
    } else {
        current.metrics.upload_bytes = 0;
        current.metrics.download_bytes = 0;
    }

    Ok(current.clone())
}

fn should_attempt_auto_list_refresh(interval_hours: u64) -> bool {
    let now = current_unix_timestamp();
    let Ok(mut last) = last_list_refresh_attempt().lock() else {
        return false;
    };
    let interval_seconds = interval_hours.clamp(1, 168).saturating_mul(60 * 60);
    if now.saturating_sub(*last) >= interval_seconds {
        *last = now;
        true
    } else {
        false
    }
}

async fn collect_runtime_diagnostics(run_network_tests: bool) -> RuntimeDiagnosticsReport {
    let mut checks = Vec::new();
    let service_first_runtime = should_use_agent_runtime();
    let runtime_route_mode = detect_mihomo_config_route_mode()
        .unwrap_or_else(|| load_app_settings().effective_route_mode());
    let agent_service = read_badvpn_agent_service_status();
    let agent_state = send_agent_command(AgentCommand::RuntimeStatus, false).ok();

    checks.push(RuntimeDiagnosticCheck {
        id: "badvpn_agent_service".to_string(),
        label: "BadVpn agent service".to_string(),
        status: if agent_service.running && agent_service.ipc_ready {
            RuntimeCheckStatus::Ok
        } else if agent_service.installed {
            RuntimeCheckStatus::Warning
        } else {
            RuntimeCheckStatus::Error
        },
        message: agent_service.message,
    });

    let config_ok = push_result_check(
        &mut checks,
        "mihomo_config",
        "Mihomo config",
        check_mihomo_config_routes(runtime_route_mode),
    );
    let mihomo_process_ok =
        child_is_running(mihomo_process()).unwrap_or(false) || recorded_mihomo_is_running();
    let mihomo_api = fetch_mihomo_version().await;
    let mihomo_api_ok = mihomo_api.is_ok();
    let agent_mihomo_ok = agent_state
        .as_ref()
        .map(|state| state.diagnostics.mihomo_healthy)
        .unwrap_or(false);
    checks.push(RuntimeDiagnosticCheck {
        id: "mihomo_process".to_string(),
        label: "Mihomo process".to_string(),
        status: if agent_mihomo_ok || (!service_first_runtime && mihomo_process_ok) {
            RuntimeCheckStatus::Ok
        } else if mihomo_api_ok {
            RuntimeCheckStatus::Warning
        } else {
            RuntimeCheckStatus::Error
        },
        message: if agent_mihomo_ok {
            "badvpn-agent reports Mihomo as running.".to_string()
        } else if !service_first_runtime && mihomo_process_ok {
            "BadVpn-owned Mihomo process is running.".to_string()
        } else if service_first_runtime && mihomo_api_ok {
            "External Mihomo/Clash controller is reachable, but badvpn-agent does not own a running Mihomo process.".to_string()
        } else if mihomo_api_ok {
            "Mihomo API responds, but this UI process does not own the child process.".to_string()
        } else {
            "Mihomo is not running or the local controller is unreachable.".to_string()
        },
    });
    match mihomo_api {
        Ok(version) => checks.push(RuntimeDiagnosticCheck {
            id: "mihomo_api".to_string(),
            label: "Mihomo API".to_string(),
            status: RuntimeCheckStatus::Ok,
            message: format!(
                "Local controller is reachable{}.",
                version
                    .version
                    .map(|version| format!("; version {version}"))
                    .unwrap_or_default()
            ),
        }),
        Err(error) => checks.push(RuntimeDiagnosticCheck {
            id: "mihomo_api".to_string(),
            label: "Mihomo API".to_string(),
            status: RuntimeCheckStatus::Error,
            message: error,
        }),
    }
    push_result_check(
        &mut checks,
        "mihomo_proxies",
        "Proxy groups",
        fetch_mihomo_proxies().await.map(|proxies| {
            format!(
                "{} Mihomo proxy/group entries are visible.",
                proxies.proxies.len()
            )
        }),
    );

    let zapret_owned = child_is_running(zapret_process()).unwrap_or(false);
    let agent_zapret_ok = agent_state
        .as_ref()
        .map(|state| state.diagnostics.zapret_healthy)
        .unwrap_or(false);
    let zapret_service = read_badvpn_zapret_service_status();
    let zapret_service_current = zapret_service.running && !zapret_service.repair_required;
    let zapret_service_usable = zapret_service.running;
    let external_winws = has_windows_process(&["winws.exe"]);
    let zapret_process_ok = if service_first_runtime {
        agent_zapret_ok || external_winws
    } else {
        agent_zapret_ok || zapret_owned || zapret_service_usable || external_winws
    };
    checks.push(RuntimeDiagnosticCheck {
        id: "zapret_process".to_string(),
        label: "zapret/winws process".to_string(),
        status: if agent_zapret_ok || (!service_first_runtime && (zapret_owned || zapret_service_current)) {
            RuntimeCheckStatus::Ok
        } else if zapret_service.running && zapret_service.repair_required {
            RuntimeCheckStatus::Warning
        } else if zapret_process_ok {
            RuntimeCheckStatus::Warning
        } else {
            RuntimeCheckStatus::Error
        },
        message: if agent_zapret_ok {
            "badvpn-agent reports winws/zapret as running.".to_string()
        } else if !service_first_runtime && zapret_owned {
            "BadVpn-owned winws process is running.".to_string()
        } else if !service_first_runtime && zapret_service_current {
            format!("{} is running as a Windows service.", BADVPN_ZAPRET_SERVICE)
        } else if zapret_service.running && zapret_service.repair_required {
            "BadVpn zapret service is running, but its arguments are stale. Install / Repair service before Smart.".to_string()
        } else if service_first_runtime && external_winws {
            "External winws.exe exists, but badvpn-agent does not own it.".to_string()
        } else if zapret_process_ok {
            "A winws.exe process exists, but this UI process does not own it.".to_string()
        } else {
            "winws.exe is not running.".to_string()
        },
    });
    checks.push(RuntimeDiagnosticCheck {
        id: "badvpn_zapret_service".to_string(),
        label: "Legacy BadVpnZapret service".to_string(),
        status: if zapret_service.installed || zapret_service.running {
            RuntimeCheckStatus::Warning
        } else {
            RuntimeCheckStatus::Ok
        },
        message: if zapret_service.running {
            format!(
                "{} It is legacy-only now; badvpn-agent will stop it before Smart starts.",
                zapret_service.message
            )
        } else {
            format!(
                "{} Service-first runtime does not require it.",
                zapret_service.message
            )
        },
    });
    push_result_check(
        &mut checks,
        "zapret_assets",
        "zapret assets",
        zapret_runtime_assets_ready()
            .map(|_| "winws, WinDivert, cygwin, and fake packets exist.".to_string()),
    );
    push_result_check(
        &mut checks,
        "flowseal_lists",
        "Flowseal lists",
        check_flowseal_lists(),
    );
    checks.push(check_windows_service(
        "bfe",
        "Base Filtering Engine",
        &["BFE"],
    ));
    checks.push(check_windows_service(
        "windivert",
        "WinDivert driver",
        &["WinDivert", "WinDivert14"],
    ));
    checks.extend(check_known_conflicts());
    if let Ok(connections) = fetch_mihomo_connections().await {
        let game_connections = connections
            .connections
            .iter()
            .filter(|connection| {
                is_game_connection(
                    connection.metadata.process.as_deref(),
                    connection.rule.as_deref(),
                    connection.rule_payload.as_deref(),
                )
            })
            .collect::<Vec<_>>();
        if game_connections.is_empty() {
            checks.push(RuntimeDiagnosticCheck {
                id: "game_bypass_routes".to_string(),
                label: "Game Bypass routes".to_string(),
                status: RuntimeCheckStatus::Warning,
                message: "No active game process flows are visible in Mihomo yet. Start a game and refresh diagnostics.".to_string(),
            });
        } else {
            let vpn_count = game_connections
                .iter()
                .filter(|connection| {
                    !connection
                        .chains
                        .iter()
                        .any(|chain| chain.eq_ignore_ascii_case("DIRECT"))
                })
                .count();
            let names = game_connections
                .iter()
                .filter_map(|connection| connection.metadata.process.as_deref())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(RuntimeDiagnosticCheck {
                id: "game_bypass_routes".to_string(),
                label: "Game Bypass routes".to_string(),
                status: if vpn_count == 0 {
                    RuntimeCheckStatus::Ok
                } else {
                    RuntimeCheckStatus::Warning
                },
                message: if vpn_count == 0 {
                    format!(
                        "Game flows are matched as DIRECT for zapret processing: {}.",
                        if names.is_empty() {
                            "process rule"
                        } else {
                            names.as_str()
                        }
                    )
                } else {
                    format!("{vpn_count} game flow(s) are still using the VPN chain; check PROCESS-NAME rules and restart the game after reconnect.")
                },
            });
        }
    }

    if run_network_tests {
        checks.push(
            check_https_endpoint(
                "discord_probe",
                "Discord HTTPS",
                "https://discord.com/api/v9/experiments",
            )
            .await,
        );
        checks.push(
            check_https_endpoint(
                "youtube_probe",
                "YouTube HTTPS",
                "https://www.youtube.com/generate_204",
            )
            .await,
        );
    }

    let mihomo_healthy = if service_first_runtime {
        config_ok && agent_mihomo_ok
    } else {
        config_ok && (mihomo_api_ok || mihomo_process_ok)
    };
    let zapret_controlled_ok = if service_first_runtime {
        agent_zapret_ok
    } else {
        agent_zapret_ok || zapret_owned || zapret_service_usable
    };
    let zapret_healthy = zapret_controlled_ok
        && checks
            .iter()
            .any(|check| check.id == "flowseal_lists" && check.status != RuntimeCheckStatus::Error)
        && checks
            .iter()
            .any(|check| check.id == "zapret_assets" && check.status != RuntimeCheckStatus::Error);
    let error_count = checks
        .iter()
        .filter(|check| check.status == RuntimeCheckStatus::Error)
        .count();
    let warning_count = checks
        .iter()
        .filter(|check| check.status == RuntimeCheckStatus::Warning)
        .count();
    let summary = if error_count == 0 && warning_count == 0 {
        "Mihomo and zapret runtime checks passed.".to_string()
    } else {
        format!("{error_count} errors and {warning_count} warnings in runtime checks.")
    };
    let failed_details = checks
        .iter()
        .filter(|check| check.status != RuntimeCheckStatus::Ok)
        .map(|check| format!("{}={:?}: {}", check.id, check.status, check.message))
        .collect::<Vec<_>>()
        .join(" | ");
    log_event(
        "diagnostics",
        format!(
            "route={runtime_route_mode:?} mihomo_healthy={mihomo_healthy} zapret_healthy={zapret_healthy} summary={summary} details={failed_details}"
        ),
    );

    RuntimeDiagnosticsReport {
        checked_at: current_unix_timestamp(),
        mihomo_healthy,
        zapret_healthy,
        summary,
        checks,
    }
}

fn push_result_check(
    checks: &mut Vec<RuntimeDiagnosticCheck>,
    id: &str,
    label: &str,
    result: Result<String, String>,
) -> bool {
    match result {
        Ok(message) => {
            checks.push(RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Ok,
                message,
            });
            true
        }
        Err(message) => {
            checks.push(RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Error,
                message,
            });
            false
        }
    }
}

fn append_external_hint_if_needed(summary: String, mihomo_healthy: bool) -> String {
    if mihomo_healthy {
        return summary;
    }
    match external_runtime_hint() {
        Some(hint) => format!("{summary} {hint}"),
        None => summary,
    }
}

async fn fetch_mihomo_version() -> Result<MihomoVersionResponse, String> {
    let client = mihomo_http_client()?;
    let url = format!("{}/version", mihomo_controller_base()?);
    add_mihomo_auth(client.get(url))
        .send()
        .await
        .map_err(|error| format!("Failed to read Mihomo version: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Mihomo version endpoint returned an error: {error}"))?
        .json::<MihomoVersionResponse>()
        .await
        .map_err(|error| format!("Failed to parse Mihomo version: {error}"))
}

async fn wait_for_mihomo_ready(timeout: Duration) -> Result<MihomoVersionResponse, String> {
    let started = SystemTime::now();
    loop {
        let last_error = match fetch_mihomo_version().await {
            Ok(version) => return Ok(version),
            Err(error) => error,
        };
        if started.elapsed().map_or(true, |elapsed| elapsed >= timeout) {
            return Err(format!(
                "Mihomo started, but local controller did not become ready: {last_error}"
            ));
        }
        sleep(Duration::from_millis(350)).await;
    }
}

async fn reload_mihomo_config_via_api(config_path: &Path) -> Result<(), String> {
    let client = mihomo_http_client()?;
    let url = format!("{}/configs?force=true", mihomo_controller_base()?);
    add_mihomo_auth(client.put(url).json(&json!({
        "path": config_path.to_string_lossy().to_string(),
        "payload": "",
    })))
    .send()
    .await
    .map_err(|error| format!("Failed to request Mihomo config reload: {error}"))?
    .error_for_status()
    .map_err(|error| format!("Mihomo config reload endpoint returned an error: {error}"))?;
    let _ = wait_for_mihomo_ready(Duration::from_secs(4)).await?;
    Ok(())
}

async fn fetch_mihomo_connections() -> Result<MihomoConnectionsResponse, String> {
    let mut last_error = None;
    for attempt in 1..=2 {
        match fetch_mihomo_connections_once().await {
            Ok(response) => return Ok(response),
            Err(error) => {
                log_event(
                    "mihomo-connections",
                    format!("attempt {attempt} failed: {error}"),
                );
                last_error = Some(error);
                sleep(Duration::from_millis(150)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "Failed to read Mihomo connections.".to_string()))
}

async fn fetch_mihomo_connections_once() -> Result<MihomoConnectionsResponse, String> {
    let client = mihomo_http_client()?;
    let url = format!("{}/connections", mihomo_controller_base()?);
    let bytes = add_mihomo_auth(client.get(url))
        .send()
        .await
        .map_err(|error| format!("Failed to read Mihomo connections: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Mihomo connections endpoint returned an error: {error}"))?
        .bytes()
        .await
        .map_err(|error| format!("Failed to decode Mihomo connections body: {error}"))?;
    let raw = serde_json::from_slice::<RawMihomoConnectionsResponse>(&bytes)
        .map_err(|error| format!("Failed to parse Mihomo connections JSON: {error}"))?;
    let mut dropped = 0usize;
    let connections = raw
        .connections
        .into_iter()
        .filter_map(
            |value| match serde_json::from_value::<MihomoConnection>(value) {
                Ok(connection) => Some(connection),
                Err(error) => {
                    dropped += 1;
                    log_event(
                        "mihomo-connections",
                        format!("dropped malformed connection entry: {error}"),
                    );
                    None
                }
            },
        )
        .collect::<Vec<_>>();
    if dropped > 0 {
        log_event(
            "mihomo-connections",
            format!("dropped {dropped} malformed connection entries"),
        );
    }
    Ok(MihomoConnectionsResponse {
        download_total: json_value_to_u64(&raw.download_total),
        upload_total: json_value_to_u64(&raw.upload_total),
        connections,
    })
}

async fn fetch_mihomo_proxies() -> Result<MihomoProxiesResponse, String> {
    let client = mihomo_http_client()?;
    let url = format!("{}/proxies", mihomo_controller_base()?);
    add_mihomo_auth(client.get(url))
        .send()
        .await
        .map_err(|error| format!("Failed to read Mihomo proxies: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Mihomo proxies endpoint returned an error: {error}"))?
        .json::<MihomoProxiesResponse>()
        .await
        .map_err(|error| format!("Failed to parse Mihomo proxies: {error}"))
}

fn tracked_connection_from_mihomo(connection: MihomoConnection) -> TrackedConnection {
    let port = json_value_to_string(&connection.metadata.destination_port);
    let host = if connection.metadata.host.trim().is_empty() {
        connection.metadata.destination_ip.clone()
    } else {
        connection.metadata.host.clone()
    };
    let destination = if port.is_empty() {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path = classify_connection_path(
        &host,
        &port,
        &connection.metadata.network,
        connection.metadata.process.as_deref(),
        connection.rule.as_deref(),
        connection.rule_payload.as_deref(),
        &connection.chains,
    );
    let (path_label, path_note) = connection_path_copy(path);

    TrackedConnection {
        id: connection.id,
        state: "active".to_string(),
        host,
        destination,
        network: uppercase_or_unknown(&connection.metadata.network),
        connection_type: uppercase_or_unknown(&connection.metadata.connection_type),
        process: connection.metadata.process,
        process_path: connection.metadata.process_path,
        rule_source: infer_connection_rule_source(
            connection.rule.as_deref(),
            connection.rule_payload.as_deref(),
        ),
        rule: connection.rule,
        rule_payload: connection.rule_payload,
        chains: connection.chains,
        upload_bytes: connection.upload,
        download_bytes: connection.download,
        started_at: connection.start,
        closed_at: None,
        path,
        path_label,
        path_note,
    }
}

fn infer_connection_rule_source(rule: Option<&str>, rule_payload: Option<&str>) -> Option<String> {
    let text = format!(
        "{} {}",
        rule.unwrap_or_default(),
        rule_payload.unwrap_or_default()
    )
    .to_ascii_lowercase();
    if text.contains("process") || text.contains("dst-port") {
        Some("local override or app/game rule".to_string())
    } else if text.contains("rule-set") {
        Some("provider rule-set".to_string())
    } else if text.contains("geosite") || text.contains("geoip") {
        Some("provider/geodata rule".to_string())
    } else if text.contains("domain") || text.contains("ip-cidr") {
        Some("domain/CIDR policy rule".to_string())
    } else {
        None
    }
}

fn update_connection_history(active: &[TrackedConnection], now: u64) -> Result<(), String> {
    let active_ids = active
        .iter()
        .map(|connection| connection.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut last = last_active_connections()
        .lock()
        .map_err(|_| "active connections lock is poisoned".to_string())?;
    let mut closed = closed_connections()
        .lock()
        .map_err(|_| "closed connections lock is poisoned".to_string())?;

    for connection in last.iter() {
        if !active_ids.contains(connection.id.as_str()) {
            let mut closed_connection = connection.clone();
            closed_connection.state = "closed".to_string();
            closed_connection.closed_at = Some(now);
            closed.push(closed_connection);
        }
    }

    closed.sort_by(|left, right| right.closed_at.cmp(&left.closed_at));
    closed.truncate(200);
    *last = active.to_vec();
    Ok(())
}

fn classify_connection_path(
    host: &str,
    port: &str,
    network: &str,
    process: Option<&str>,
    rule: Option<&str>,
    rule_payload: Option<&str>,
    chains: &[String],
) -> ConnectionPath {
    if chains.iter().any(|chain| {
        chain.eq_ignore_ascii_case("REJECT") || chain.eq_ignore_ascii_case("REJECT-DROP")
    }) {
        return ConnectionPath::Blocked;
    }

    if (is_zapret_target(host, port, network) || is_game_connection(process, rule, rule_payload))
        && chains
            .iter()
            .any(|chain| chain.eq_ignore_ascii_case("DIRECT"))
    {
        return ConnectionPath::Zapret;
    }

    if chains
        .iter()
        .any(|chain| chain.eq_ignore_ascii_case("DIRECT"))
    {
        return ConnectionPath::Direct;
    }

    if chains.is_empty() {
        ConnectionPath::Unknown
    } else {
        ConnectionPath::Vpn
    }
}

fn is_game_connection(
    process: Option<&str>,
    rule: Option<&str>,
    rule_payload: Option<&str>,
) -> bool {
    if rule
        .map(|rule| rule.eq_ignore_ascii_case("PROCESS-NAME"))
        .unwrap_or(false)
    {
        return true;
    }
    process
        .or(rule_payload)
        .map(is_known_game_process)
        .unwrap_or(false)
}

fn is_known_game_process(value: &str) -> bool {
    let process = value
        .trim()
        .trim_matches('"')
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    matches!(
        process.as_str(),
        "fortniteclient-win64-shipping"
            | "fortnitelauncher"
            | "epicgameslauncher"
            | "robloxplayerbeta"
            | "discord"
            | "discordcanary"
            | "discordptb"
            | "repo"
            | "repo-win64-shipping"
    ) || process.ends_with("-win64-shipping")
}

fn is_zapret_target(host: &str, port: &str, network: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if zapret_default_hostlist()
        .iter()
        .any(|domain| normalized == *domain || normalized.ends_with(&format!(".{domain}")))
    {
        return true;
    }

    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let is_udp = network.eq_ignore_ascii_case("udp");
    is_udp && ((19294..=19344).contains(&port) || (50000..=50100).contains(&port))
}

fn connection_path_copy(path: ConnectionPath) -> (String, String) {
    match path {
        ConnectionPath::Vpn => (
            "VPN".to_string(),
            "Mihomo proxy chain; traffic leaves through selected VPN node.".to_string(),
        ),
        ConnectionPath::Zapret => (
            "zapret".to_string(),
            "DIRECT in Mihomo plus Flowseal/winws DPI bypass for Discord, YouTube, and game targets.".to_string(),
        ),
        ConnectionPath::Direct => (
            "DIRECT".to_string(),
            "Direct route without proxy; not in the zapret target list.".to_string(),
        ),
        ConnectionPath::Blocked => (
            "Blocked".to_string(),
            "Rejected by Mihomo rule chain.".to_string(),
        ),
        ConnectionPath::Unknown => (
            "Unknown".to_string(),
            "Mihomo did not return enough routing metadata yet.".to_string(),
        ),
    }
}

fn check_mihomo_config_routes(runtime_route_mode: RouteMode) -> Result<String, String> {
    let settings = load_app_settings();
    let expected_route_mode = if runtime_route_mode == RouteMode::VpnOnly {
        RouteMode::VpnOnly
    } else {
        settings.effective_route_mode()
    };
    let path = mihomo_config_path()?;
    if !path.exists() {
        return Err("Import a subscription before running Mihomo checks.".to_string());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read Mihomo config: {error}"))?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content)
        .map_err(|error| format!("Failed to parse Mihomo config: {error}"))?;
    let rules = yaml
        .get("rules")
        .and_then(YamlValue::as_sequence)
        .ok_or_else(|| "Mihomo config has no rules section.".to_string())?;
    let rule_strings = rules
        .iter()
        .filter_map(YamlValue::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let direct_required = if expected_route_mode == RouteMode::Smart {
        smart_hybrid_required_rules().to_vec()
    } else {
        Vec::new()
    };
    let missing = direct_required
        .iter()
        .filter(|rule| !rule_strings.contains(*rule))
        .copied()
        .collect::<Vec<_>>();
    let fallback_rule = rule_strings.iter().copied().find(|rule| {
        let normalized = rule.trim().to_ascii_uppercase();
        normalized.starts_with("MATCH,") || normalized.starts_with("FINAL,")
    });
    if missing.is_empty() {
        let Some(fallback_rule) = fallback_rule else {
            return Err(
                "Mihomo config has no MATCH/FINAL fallback rule for provider proxy groups."
                    .to_string(),
            );
        };
        if expected_route_mode == RouteMode::Smart {
            Ok(format!(
                "Config contains {} rules, including Discord/YouTube DIRECT and fallback {fallback_rule}.",
                rules.len(),
            ))
        } else {
            Ok(format!(
                "Config contains {} rules with fallback {fallback_rule}. Flowseal DIRECT rules are not expected in current runtime mode.",
                rules.len(),
            ))
        }
    } else {
        Err(format!(
            "Mihomo config is missing rules: {}",
            missing.join(", ")
        ))
    }
}

fn smart_hybrid_required_rules() -> [&'static str; 3] {
    [
        "DOMAIN-SUFFIX,discord.com,DIRECT",
        "DOMAIN-SUFFIX,youtube.com,DIRECT",
        "DOMAIN-SUFFIX,googlevideo.com,DIRECT",
    ]
}

fn detect_mihomo_config_route_mode() -> Option<RouteMode> {
    let path = mihomo_config_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    if mihomo_config_has_smart_hybrid_rules(&content) {
        Some(RouteMode::Smart)
    } else {
        Some(RouteMode::VpnOnly)
    }
}

fn mihomo_config_has_smart_hybrid_rules(content: &str) -> bool {
    let Ok(yaml) = serde_yaml::from_str::<YamlValue>(content) else {
        return false;
    };
    let Some(rules) = yaml.get("rules").and_then(YamlValue::as_sequence) else {
        return false;
    };
    let rule_strings = rules
        .iter()
        .filter_map(YamlValue::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    smart_hybrid_required_rules()
        .iter()
        .all(|rule| rule_strings.contains(*rule))
}

fn check_flowseal_lists() -> Result<String, String> {
    let assets = flowseal_zapret_assets()?;
    let required = [
        (&assets.list_general, "list-general.txt", 10_usize),
        (&assets.list_google, "list-google.txt", 5_usize),
        (&assets.list_exclude, "list-exclude.txt", 10_usize),
        (&assets.ipset_exclude, "ipset-exclude.txt", 5_usize),
        (&assets.ipset_all, "ipset-all.txt", 1_usize),
    ];
    let mut messages = Vec::new();
    for (path, label, min_lines) in required {
        if !path.exists() {
            return Err(format!("{label} is missing at {}.", path.display()));
        }
        let count = fs::read_to_string(path)
            .map_err(|error| format!("Failed to read {label}: {error}"))?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        if count < min_lines {
            return Err(format!("{label} has only {count} entries."));
        }
        messages.push(format!("{label}: {count}"));
    }
    if fs::metadata(&assets.ipset_all).map_or(0, |metadata| metadata.len()) < 1024 {
        messages.push("ipset-all is in fallback stub mode".to_string());
    }
    Ok(messages.join(", "))
}

fn child_is_running(lock: &Mutex<Option<Child>>) -> Result<bool, String> {
    let mut child = lock
        .lock()
        .map_err(|_| "process lock is poisoned".to_string())?;
    let Some(running) = child.as_mut() else {
        return Ok(false);
    };
    match running
        .try_wait()
        .map_err(|error| format!("Failed to inspect child process: {error}"))?
    {
        Some(_) => {
            *child = None;
            Ok(false)
        }
        None => Ok(true),
    }
}

fn check_windows_service(id: &str, label: &str, service_names: &[&str]) -> RuntimeDiagnosticCheck {
    #[cfg(not(windows))]
    {
        let _ = service_names;
        RuntimeDiagnosticCheck {
            id: id.to_string(),
            label: label.to_string(),
            status: RuntimeCheckStatus::Warning,
            message: "Windows service checks are only available on Windows.".to_string(),
        }
    }

    #[cfg(windows)]
    {
        let states = service_names
            .iter()
            .filter_map(|name| {
                windows_service_state(name).map(|state| ((*name).to_string(), state))
            })
            .collect::<Vec<_>>();
        if states.iter().any(|(_, state)| state.contains("RUNNING")) {
            RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Ok,
                message: states
                    .iter()
                    .map(|(name, state)| format!("{name}: {state}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        } else if states.is_empty() {
            RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Warning,
                message: format!("{} service is not registered.", service_names.join("/")),
            }
        } else {
            RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Warning,
                message: states
                    .iter()
                    .map(|(name, state)| format!("{name}: {state}"))
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        }
    }
}

#[cfg(windows)]
fn windows_service_state(name: &str) -> Option<String> {
    let mut command = Command::new("sc");
    command.args(["query", name]);
    hide_process_window(&mut command);
    let output = command.output().ok()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(state) = stdout
            .lines()
            .find(|line| line.contains("STATE"))
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        {
            return Some(state);
        }
    }

    let mut fallback = Command::new("powershell");
    let script = format!(
        "(Get-Service -Name '{}' -ErrorAction SilentlyContinue).Status",
        powershell_single_quote(name)
    );
    fallback.args(["-NoProfile", "-Command", &script]);
    hide_process_window(&mut fallback);
    let output = fallback.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!status.is_empty()).then_some(status)
}

fn read_badvpn_agent_service_status() -> AgentServiceStatus {
    #[cfg(not(windows))]
    {
        AgentServiceStatus {
            service_name: BADVPN_AGENT_SERVICE.to_string(),
            installed: false,
            running: false,
            state: None,
            ipc_ready: false,
            message: "BadVpn agent service is only available on Windows.".to_string(),
        }
    }

    #[cfg(windows)]
    {
        let state = windows_service_state(BADVPN_AGENT_SERVICE);
        let installed = state.is_some();
        let running = state
            .as_deref()
            .map(|state| state.to_ascii_uppercase().contains("RUNNING"))
            .unwrap_or(false);
        let ipc_ready = agent_ipc_ready();
        let message = match (&state, running, ipc_ready) {
            (Some(state), true, true) => {
                format!("{BADVPN_AGENT_SERVICE}: {state}; IPC is reachable.")
            }
            (Some(state), true, false) => {
                format!("{BADVPN_AGENT_SERVICE}: {state}; IPC is not reachable yet.")
            }
            (Some(state), false, _) => {
                format!("{BADVPN_AGENT_SERVICE} is installed but not running: {state}.")
            }
            (None, _, _) => format!("{BADVPN_AGENT_SERVICE} is not installed."),
        };
        AgentServiceStatus {
            service_name: BADVPN_AGENT_SERVICE.to_string(),
            installed,
            running,
            state,
            ipc_ready,
            message,
        }
    }
}

fn install_badvpn_agent_service() -> Result<AgentServiceStatus, String> {
    #[cfg(not(windows))]
    {
        Err("BadVpn agent service install is only available on Windows.".to_string())
    }

    #[cfg(windows)]
    {
        log_event("agent-service", "install/repair requested");
        let agent_bin = resolve_agent_bin()?;
        let service_agent_bin = programdata_dir()?.join("agent").join(if cfg!(windows) {
            "badvpn-agent.exe"
        } else {
            "badvpn-agent"
        });
        let invoking_user_sid = current_process_user_sid()?;
        let staging_script = stage_runtime_assets_powershell()?;
        let script = render_agent_install_powershell(
            &agent_bin,
            &service_agent_bin,
            &invoking_user_sid,
            &staging_script,
        );
        run_elevated_powershell_script(&script)?;
        let status = read_badvpn_agent_service_status();
        log_event(
            "agent-service",
            format!("install/repair completed: {}", status.message),
        );
        Ok(status)
    }
}

#[cfg(windows)]
fn render_agent_install_powershell(
    agent_bin: &Path,
    service_agent_bin: &Path,
    invoking_user_sid: &str,
    staging_script: &str,
) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
$sourceAgent = '{agent}'
$serviceAgent = '{service_agent}'
$serviceAgentDir = Split-Path -Parent $serviceAgent
New-Item -ItemType Directory -Path $serviceAgentDir -Force | Out-Null
$invokingUserSid = '{invoking_user_sid}'
Set-Content -LiteralPath (Join-Path $serviceAgentDir 'allowed-user.sid') -Value $invokingUserSid -Encoding ascii -NoNewline
$service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
$wasRunning = [bool]($service -and $service.Status -eq 'Running')
$serviceAgentBackup = $null
try {{
  if ($service -and $service.Status -ne 'Stopped') {{
    sc.exe stop '{service_name}' | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    do {{
      Start-Sleep -Milliseconds 250
      $service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    }} while ($service -and $service.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
    if ($service -and $service.Status -ne 'Stopped') {{ throw "{service_name} did not stop before agent repair" }}
  }}
{staging_script}
  if (Test-Path -LiteralPath $serviceAgent -PathType Leaf) {{
    $serviceAgentBackup = "$serviceAgent.backup-$([Guid]::NewGuid().ToString('N'))"
    Copy-Item -LiteralPath $serviceAgent -Destination $serviceAgentBackup -Force
  }}
  Copy-Item -LiteralPath $sourceAgent -Destination $serviceAgent -Force
  & $serviceAgent install-service | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw "badvpn-agent install-service failed with exit code $LASTEXITCODE" }}
  if (-not $wasRunning) {{
    $service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {{
      Stop-Service -Name '{service_name}' -ErrorAction Stop
      $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }}
  }}
  if ($runtimeAssetsBackup -and (Test-Path -LiteralPath $runtimeAssetsBackup)) {{
    Remove-Item -LiteralPath $runtimeAssetsBackup -Recurse -Force -ErrorAction SilentlyContinue
  }}
  if ($serviceAgentBackup -and (Test-Path -LiteralPath $serviceAgentBackup)) {{
    Remove-Item -LiteralPath $serviceAgentBackup -Force -ErrorAction SilentlyContinue
  }}
}} catch {{
  $installFailure = $_.Exception.Message
  if ($runtimeAssetsBackup -and (Test-Path -LiteralPath $runtimeAssetsBackup)) {{
    if (Test-Path -LiteralPath $runtimeAssetsTarget) {{
      Remove-Item -LiteralPath $runtimeAssetsTarget -Recurse -Force
    }}
    Move-Item -LiteralPath $runtimeAssetsBackup -Destination $runtimeAssetsTarget
  }}
  if ($serviceAgentBackup -and (Test-Path -LiteralPath $serviceAgentBackup)) {{
    Copy-Item -LiteralPath $serviceAgentBackup -Destination $serviceAgent -Force
    Remove-Item -LiteralPath $serviceAgentBackup -Force -ErrorAction SilentlyContinue
  }}
  $restartFailure = $null
  if ($wasRunning) {{
    try {{
      Start-Service -Name '{service_name}' -ErrorAction Stop
      $service = Get-Service -Name '{service_name}' -ErrorAction Stop
      $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    }} catch {{
      $restartFailure = $_.Exception.Message
    }}
  }}
  if ($restartFailure) {{
    throw "$installFailure Previously running {service_name} could not be restarted: $restartFailure"
  }}
  throw $installFailure
}}
"#,
        agent = powershell_single_quote(&agent_bin.to_string_lossy()),
        service_agent = powershell_single_quote(&service_agent_bin.to_string_lossy()),
        invoking_user_sid = powershell_single_quote(invoking_user_sid),
        service_name = BADVPN_AGENT_SERVICE,
        staging_script = staging_script,
    )
}

#[cfg(windows)]
fn current_process_user_sid() -> Result<String, String> {
    let mut command = Command::new("whoami.exe");
    command
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let output = command
        .output()
        .map_err(|error| format!("Failed to query invoking user SID: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Failed to query invoking user SID: whoami exited with {}",
            output.status
        ));
    }
    parse_user_sid(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| "Failed to parse invoking user SID from whoami output".to_string())
}

#[cfg(windows)]
fn parse_user_sid(output: &str) -> Option<String> {
    output
        .split([',', '\r', '\n'])
        .map(|field| field.trim().trim_matches('"'))
        .find(|field| is_valid_windows_sid(field))
        .map(ToOwned::to_owned)
}

#[cfg(windows)]
fn is_valid_windows_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    if parts.next() != Some("S") {
        return false;
    }
    let revision = parts.next();
    let authority = parts.next();
    let sub_authorities = parts.collect::<Vec<_>>();
    revision.is_some_and(is_decimal_field)
        && authority.is_some_and(is_decimal_field)
        && !sub_authorities.is_empty()
        && sub_authorities.into_iter().all(is_decimal_field)
}

#[cfg(windows)]
fn is_decimal_field(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| character.is_ascii_digit())
}

fn stage_runtime_assets_powershell() -> Result<String, String> {
    let source_components = data_dir()?.join("components");
    let target_components = programdata_dir()?.join("components");
    let source_lists = data_dir()?.join("zapret").join("lists");
    let required_profiles = ZapretProfile::all()
        .iter()
        .map(|profile| format!("'{}'", powershell_single_quote(profile.bat_file_name())))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        r#"$runtimeAssetsBackup = $null
$runtimeAssetsTarget = $null
$sourceComponents = '{source_components}'
$targetComponents = '{target_components}'
$runtimeAssetsTarget = $targetComponents
if (Test-Path -LiteralPath $sourceComponents) {{
  $mihomoCandidates = @(
    (Join-Path $sourceComponents 'mihomo.exe'),
    (Join-Path $sourceComponents 'mihomo\mihomo.exe')
  )
  $hasMihomo = $false
  foreach ($candidate in $mihomoCandidates) {{
    if (Test-Path -LiteralPath $candidate) {{ $hasMihomo = $true; break }}
  }}
  if (-not $hasMihomo) {{
    throw "Refusing ProgramData staging because source components are incomplete (mihomo.exe missing)."
  }}
  $sourceZapret = Join-Path $sourceComponents 'zapret'
  $targetZapret = Join-Path $targetComponents 'zapret'
  if ((Test-Path -LiteralPath $sourceZapret) -or (Test-Path -LiteralPath $targetZapret)) {{
    $requiredZapretAssets = @(
      'zapret\bin\winws.exe',
      'zapret\bin\WinDivert.dll',
      'zapret\bin\WinDivert64.sys',
      'zapret\bin\cygwin1.dll',
      'zapret\bin\quic_initial_www_google_com.bin',
      'zapret\bin\tls_clienthello_www_google_com.bin'
    )
    $missingZapretAssets = @($requiredZapretAssets | Where-Object {{
      -not (Test-Path -LiteralPath (Join-Path $sourceComponents $_) -PathType Leaf)
    }})
    $requiredZapretProfiles = @({required_profiles})
    foreach ($profile in $requiredZapretProfiles) {{
      $rootProfile = Join-Path $sourceZapret $profile
      $nestedProfile = Join-Path (Join-Path $sourceZapret 'profiles') $profile
      if (-not (Test-Path -LiteralPath $rootProfile -PathType Leaf) -and -not (Test-Path -LiteralPath $nestedProfile -PathType Leaf)) {{
        $missingZapretAssets += "zapret profile: $profile"
      }}
    }}
    if ($missingZapretAssets.Count -gt 0) {{
      throw "Refusing ProgramData staging because source zapret components are incomplete: $($missingZapretAssets -join ', ')"
    }}
  }}
  $targetParent = Split-Path -Parent $targetComponents
  New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
  $nonce = [Guid]::NewGuid().ToString('N')
  $stagingComponents = Join-Path $targetParent ("components.stage-" + $nonce)
  $backupComponents = Join-Path $targetParent ("components.backup-" + $nonce)
  $targetWasMoved = $false

  function Assert-StagedTreeContent([string]$source, [string]$destination) {{
    $sourceRoot = [IO.Path]::GetFullPath($source).TrimEnd('\') + '\'
    foreach ($sourceFile in Get-ChildItem -LiteralPath $source -File -Recurse) {{
      $relative = $sourceFile.FullName.Substring($sourceRoot.Length)
      $destinationFile = Join-Path $destination $relative
      if (-not (Test-Path -LiteralPath $destinationFile -PathType Leaf)) {{
        throw "Staged runtime asset is missing: $relative"
      }}
      $sourceHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash
      $destinationHash = (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash
      if ($sourceHash -ne $destinationHash) {{
        throw "Staged runtime asset hash mismatch: $relative"
      }}
    }}
  }}

  try {{
    New-Item -ItemType Directory -Path $stagingComponents -Force | Out-Null
    robocopy $sourceComponents $stagingComponents /E /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -gt 7) {{ throw "component staging failed with robocopy exit code $LASTEXITCODE" }}
    $global:LASTEXITCODE = 0
    Assert-StagedTreeContent $sourceComponents $stagingComponents

    $sourceLists = '{source_lists}'
    if (Test-Path -LiteralPath $sourceLists) {{
      $stagingLists = Join-Path $stagingComponents 'zapret\lists'
      New-Item -ItemType Directory -Path $stagingLists -Force | Out-Null
      # /MIR is safe only inside the disposable staging tree and makes the list set exact.
      robocopy $sourceLists $stagingLists /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
      if ($LASTEXITCODE -gt 7) {{ throw "Flowseal list staging failed with robocopy exit code $LASTEXITCODE" }}
      $global:LASTEXITCODE = 0
      Assert-StagedTreeContent $sourceLists $stagingLists
    }}

    $stagedMihomoCandidates = @(
      (Join-Path $stagingComponents 'mihomo.exe'),
      (Join-Path $stagingComponents 'mihomo\mihomo.exe')
    )
    if (-not ($stagedMihomoCandidates | Where-Object {{ Test-Path -LiteralPath $_ -PathType Leaf }})) {{
      throw "Refusing ProgramData swap because staged components are incomplete (mihomo.exe missing)."
    }}

    if (Test-Path -LiteralPath $targetComponents) {{
      Move-Item -LiteralPath $targetComponents -Destination $backupComponents
      $targetWasMoved = $true
      $runtimeAssetsBackup = $backupComponents
    }}
    try {{
      Move-Item -LiteralPath $stagingComponents -Destination $targetComponents
    }} catch {{
      if (Test-Path -LiteralPath $targetComponents) {{
        Remove-Item -LiteralPath $targetComponents -Recurse -Force
      }}
      if ($targetWasMoved -and (Test-Path -LiteralPath $backupComponents)) {{
        Move-Item -LiteralPath $backupComponents -Destination $targetComponents
        $targetWasMoved = $false
        $runtimeAssetsBackup = $null
      }}
      throw
    }}
  }} catch {{
    if (Test-Path -LiteralPath $stagingComponents) {{
      Remove-Item -LiteralPath $stagingComponents -Recurse -Force -ErrorAction SilentlyContinue
    }}
    if ($targetWasMoved -and (Test-Path -LiteralPath $backupComponents) -and -not (Test-Path -LiteralPath $targetComponents)) {{
      Move-Item -LiteralPath $backupComponents -Destination $targetComponents
      $runtimeAssetsBackup = $null
    }}
    throw
  }}
}}
"#,
        source_components = powershell_single_quote(&source_components.to_string_lossy()),
        target_components = powershell_single_quote(&target_components.to_string_lossy()),
        source_lists = powershell_single_quote(&source_lists.to_string_lossy()),
        required_profiles = required_profiles,
    ))
}

fn stage_runtime_assets_to_programdata() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        Ok(())
    }

    #[cfg(windows)]
    {
        let script = format!(
            r#"$ErrorActionPreference = 'Stop'
{}
"#,
            stage_runtime_assets_powershell()?
        );
        let script = format!(
            "{script}\nif ($runtimeAssetsBackup -and (Test-Path -LiteralPath $runtimeAssetsBackup)) {{ Remove-Item -LiteralPath $runtimeAssetsBackup -Recurse -Force }}\n"
        );
        run_elevated_powershell_script(&script)
    }
}

fn remove_badvpn_agent_service() -> Result<AgentServiceStatus, String> {
    #[cfg(not(windows))]
    {
        Err("BadVpn agent service removal is only available on Windows.".to_string())
    }

    #[cfg(windows)]
    {
        log_event("agent-service", "remove requested");
        let agent_bin = resolve_agent_bin()?;
        let script = format!(
            r#"$ErrorActionPreference = 'Continue'
$agent = '{agent}'
& $agent uninstall-service | Out-Null
"#,
            agent = powershell_single_quote(&agent_bin.to_string_lossy()),
        );
        run_elevated_powershell_script(&script)?;
        let status = read_badvpn_agent_service_status();
        log_event(
            "agent-service",
            format!("remove completed: {}", status.message),
        );
        Ok(status)
    }
}

fn start_badvpn_agent_service_normal() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        Err("BadVpn agent service start is only available on Windows.".to_string())
    }

    #[cfg(windows)]
    {
        let mut command = Command::new("sc");
        command.args(["start", BADVPN_AGENT_SERVICE]);
        hide_process_window(&mut command);
        let output = command
            .output()
            .map_err(|error| format!("Failed to start {BADVPN_AGENT_SERVICE}: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Failed to start {BADVPN_AGENT_SERVICE}: {}{}",
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

fn read_badvpn_zapret_service_status() -> ZapretServiceStatus {
    #[cfg(not(windows))]
    {
        ZapretServiceStatus {
            service_name: BADVPN_ZAPRET_SERVICE.to_string(),
            installed: false,
            running: false,
            state: None,
            config_hash: None,
            expected_hash: None,
            repair_required: false,
            message: "Legacy BadVpnZapret detection is only available on Windows.".to_string(),
        }
    }

    #[cfg(windows)]
    {
        let state = windows_service_state(BADVPN_ZAPRET_SERVICE);
        let installed = state.is_some();
        let running = state
            .as_deref()
            .map(|state| state.to_ascii_uppercase().contains("RUNNING"))
            .unwrap_or(false);
        let config_hash =
            windows_service_registry_value(BADVPN_ZAPRET_SERVICE, "badvpn-config-hash");
        let repair_required = installed;
        let message = match (&state, running) {
            (Some(state), true) => format!(
                "{BADVPN_ZAPRET_SERVICE}: {state}. Legacy service is running; cleanup must be requested through badvpn-agent."
            ),
            (Some(state), false) => format!(
                "{BADVPN_ZAPRET_SERVICE} is installed but legacy-only: {state}. Cleanup must be requested through badvpn-agent."
            ),
            (None, _) => format!("{BADVPN_ZAPRET_SERVICE} is not installed."),
        };
        ZapretServiceStatus {
            service_name: BADVPN_ZAPRET_SERVICE.to_string(),
            installed,
            running,
            state,
            config_hash,
            expected_hash: None,
            repair_required,
            message,
        }
    }
}

#[cfg(windows)]
fn windows_service_registry_value(service_name: &str, value_name: &str) -> Option<String> {
    let key = format!(r"HKLM\System\CurrentControlSet\Services\{service_name}");
    let mut command = Command::new("reg");
    command.args(["query", &key, "/v", value_name]);
    hide_process_window(&mut command);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed
            .to_ascii_lowercase()
            .starts_with(&value_name.to_ascii_lowercase())
        {
            return None;
        }
        trimmed
            .split_once("REG_SZ")
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn run_elevated_powershell_script(script: &str) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = script;
        Err("Elevated PowerShell is only available on Windows.".to_string())
    }

    #[cfg(windows)]
    {
        let encoded_script = general_purpose::STANDARD.encode(
            script
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let launcher = format!(
            "$argsList = @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','{}'); $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argsList -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
            encoded_script
        );
        let mut command = Command::new("powershell");
        command.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &launcher,
        ]);
        hide_process_window(&mut command);
        let output = command
            .output()
            .map_err(|error| format!("Failed to request administrator rights: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Administrator action failed or was cancelled. stdout: {} stderr: {}",
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

#[cfg(windows)]
#[cfg(windows)]
fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn stable_config_hash(value: &str) -> String {
    stable_bytes_hash(value.as_bytes())
}

fn stable_bytes_hash(value: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn format_game_filter(mode: ZapretGameFilter) -> &'static str {
    match mode {
        ZapretGameFilter::Off => "off",
        ZapretGameFilter::TcpUdp => "tcp_udp",
        ZapretGameFilter::Tcp => "tcp",
        ZapretGameFilter::Udp => "udp",
    }
}

fn format_game_bypass_mode(mode: crate::settings::GameBypassMode) -> &'static str {
    match mode {
        crate::settings::GameBypassMode::Off => "off",
        crate::settings::GameBypassMode::Auto => "auto",
        crate::settings::GameBypassMode::Manual => "manual",
    }
}

fn format_game_filter_mode(mode: crate::settings::GameFilterMode) -> &'static str {
    match mode {
        crate::settings::GameFilterMode::UdpFirst => "udp_first",
        crate::settings::GameFilterMode::TcpUdp => "tcp_udp",
        crate::settings::GameFilterMode::Aggressive => "aggressive",
    }
}

fn runtime_game_profile_from_settings(
    profile: &crate::settings::GameProfileSettings,
) -> RuntimeGameProfile {
    RuntimeGameProfile {
        id: profile.id.clone(),
        title: profile.title.clone(),
        process_names: profile.process_names.clone(),
        domains: profile.domains.clone(),
        cidrs: profile.cidrs.clone(),
        tcp_ports: profile.tcp_ports.clone(),
        udp_ports: profile.udp_ports.clone(),
        filter_mode: format_game_filter_mode(profile.filter_mode).to_string(),
        risk_level: profile.risk_level.clone(),
        detected: profile.detected,
        enabled: profile.enabled,
    }
}

fn format_ipset_filter(mode: ZapretIpSetFilter) -> &'static str {
    match mode {
        ZapretIpSetFilter::None => "none",
        ZapretIpSetFilter::Any => "any",
        ZapretIpSetFilter::Loaded => "loaded",
    }
}

fn format_zapret_strategy(mode: ZapretStrategy) -> &'static str {
    match mode {
        ZapretStrategy::Auto => "auto",
        ZapretStrategy::General => "general",
        ZapretStrategy::Alt => "alt",
        ZapretStrategy::Alt2 => "alt2",
        ZapretStrategy::Alt3 => "alt3",
        ZapretStrategy::Alt4 => "alt4",
        ZapretStrategy::Alt5 => "alt5",
        ZapretStrategy::Alt6 => "alt6",
        ZapretStrategy::Alt7 => "alt7",
        ZapretStrategy::Alt8 => "alt8",
        ZapretStrategy::Alt9 => "alt9",
        ZapretStrategy::Alt10 => "alt10",
        ZapretStrategy::Alt11 => "alt11",
        ZapretStrategy::FakeTlsAuto => "fake_tls_auto",
        ZapretStrategy::FakeTlsAutoAlt => "fake_tls_auto_alt",
        ZapretStrategy::FakeTlsAutoAlt2 => "fake_tls_auto_alt2",
        ZapretStrategy::FakeTlsAutoAlt3 => "fake_tls_auto_alt3",
        ZapretStrategy::SimpleFake => "simple_fake",
        ZapretStrategy::SimpleFakeAlt => "simple_fake_alt",
        ZapretStrategy::SimpleFakeAlt2 => "simple_fake_alt2",
    }
}

fn check_known_conflicts() -> Vec<RuntimeDiagnosticCheck> {
    let process_conflicts = [
        ("goodbyedpi.exe", "GoodbyeDPI"),
        ("AdguardSvc.exe", "AdGuard"),
    ];
    let mut checks = process_conflicts
        .iter()
        .map(|(process, label)| RuntimeDiagnosticCheck {
            id: format!(
                "conflict_{}",
                process.trim_end_matches(".exe").to_ascii_lowercase()
            ),
            label: format!("{label} conflict"),
            status: if has_windows_process(&[*process]) {
                RuntimeCheckStatus::Warning
            } else {
                RuntimeCheckStatus::Ok
            },
            message: if has_windows_process(&[*process]) {
                format!("{label} is running and can conflict with WinDivert/zapret.")
            } else {
                format!("{label} process was not found.")
            },
        })
        .collect::<Vec<_>>();

    #[cfg(windows)]
    {
        for service in ["Killer", "SmartByte", "TracSrvWrapper", "EPWD"] {
            let state = windows_service_state(service);
            checks.push(RuntimeDiagnosticCheck {
                id: format!("conflict_service_{}", service.to_ascii_lowercase()),
                label: format!("{service} service"),
                status: if state.is_some() {
                    RuntimeCheckStatus::Warning
                } else {
                    RuntimeCheckStatus::Ok
                },
                message: state
                    .map(|state| {
                        format!("{service} is present: {state}. It may conflict with zapret.")
                    })
                    .unwrap_or_else(|| format!("{service} service was not found.")),
            });
        }
    }

    checks
}

async fn check_https_endpoint(id: &str, label: &str, url: &str) -> RuntimeDiagnosticCheck {
    let client = match reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: RuntimeCheckStatus::Error,
                message: format!("Failed to create probe client: {error}"),
            }
        }
    };
    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status();
            let status_ok = status.is_success() || status.as_u16() == 403 || status.as_u16() == 429;
            RuntimeDiagnosticCheck {
                id: id.to_string(),
                label: label.to_string(),
                status: if status_ok {
                    RuntimeCheckStatus::Ok
                } else {
                    RuntimeCheckStatus::Warning
                },
                message: format!("{url} returned HTTP {status}."),
            }
        }
        Err(error) => RuntimeDiagnosticCheck {
            id: id.to_string(),
            label: label.to_string(),
            status: RuntimeCheckStatus::Error,
            message: format!("{url} probe failed: {error}"),
        },
    }
}

fn local_proxy_catalog() -> Result<Vec<ProxyGroupView>, String> {
    let path = active_mihomo_config_path()?;
    if !path.exists() {
        return Err("Import a subscription before opening server groups.".to_string());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read Mihomo config: {error}"))?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content)
        .map_err(|error| format!("Failed to parse Mihomo config: {error}"))?;

    let proxy_meta = yaml
        .get("proxies")
        .and_then(YamlValue::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = yaml_field(item, "name")?.to_string();
                    Some((
                        name,
                        (
                            yaml_field(item, "type").map(ToOwned::to_owned),
                            yaml_field(item, "server").map(ToOwned::to_owned),
                        ),
                    ))
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let group_names = yaml
        .get("proxy-groups")
        .and_then(YamlValue::as_sequence)
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| yaml_field(group, "name").map(ToOwned::to_owned))
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();

    let groups = yaml
        .get("proxy-groups")
        .and_then(YamlValue::as_sequence)
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| {
                    let name = yaml_field(group, "name")?.to_string();
                    let group_type = yaml_field(group, "type").unwrap_or("select").to_string();
                    let nodes = group
                        .get("proxies")
                        .and_then(YamlValue::as_sequence)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(YamlValue::as_str)
                                .map(|node_name| {
                                    let meta = proxy_meta.get(node_name);
                                    ProxyNodeView {
                                        name: node_name.to_string(),
                                        proxy_type: meta
                                            .and_then(|(proxy_type, _)| proxy_type.clone())
                                            .or_else(|| {
                                                if group_names.contains(node_name) {
                                                    Some("group".to_string())
                                                } else {
                                                    Some("built-in".to_string())
                                                }
                                            }),
                                        server: meta.and_then(|(_, server)| server.clone()),
                                        delay_ms: None,
                                        alive: None,
                                        is_group: group_names.contains(node_name),
                                        selected: false,
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    Some(ProxyGroupView {
                        name,
                        group_type,
                        selected: None,
                        nodes,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if groups.is_empty() {
        Err("Mihomo config has no proxy groups.".to_string())
    } else {
        Ok(groups)
    }
}

fn validate_proxy_selection(
    api: &MihomoProxiesResponse,
    group: &str,
    proxy: &str,
) -> Result<(), String> {
    let state = api.proxies.get(group).ok_or_else(|| {
        format!(
            "Proxy group '{group}' is not present in the active Mihomo runtime. Refresh the server list or reconnect before selecting a node."
        )
    })?;
    if state
        .proxy_type
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("selector"))
    {
        return Err(format!(
            "Proxy group '{group}' is not selectable in the active Mihomo runtime."
        ));
    }
    if !state.members.is_empty() && !state.members.iter().any(|member| member == proxy) {
        return Err(format!(
            "Proxy '{proxy}' is not a member of active Mihomo group '{group}'. Refresh the server list before selecting a node."
        ));
    }
    Ok(())
}

fn proxy_selection_http_error(status: reqwest::StatusCode, detail: &str) -> String {
    let detail = detail.trim();
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(
            " Mihomo response: {}",
            detail.chars().take(512).collect::<String>()
        )
    };
    format!(
        "Mihomo rejected proxy selection with HTTP {status}. Refresh the active server list or reconnect and try again.{detail}"
    )
}

fn merge_proxy_runtime_state(groups: &mut [ProxyGroupView], api: &MihomoProxiesResponse) {
    for group in groups {
        if let Some(state) = api.proxies.get(&group.name) {
            group.selected = state.now.clone();
        }

        for node in &mut group.nodes {
            if let Some(state) = api.proxies.get(&node.name) {
                node.proxy_type = state.proxy_type.clone().or_else(|| node.proxy_type.clone());
                node.alive = state.alive;
                node.delay_ms = state
                    .delay
                    .or_else(|| state.history.iter().rev().find_map(|item| item.delay));
            }
            node.selected = group.selected.as_deref() == Some(node.name.as_str());
        }
    }
}

fn yaml_field<'a>(value: &'a YamlValue, key: &str) -> Option<&'a str> {
    value
        .get(YamlValue::String(key.to_string()))
        .and_then(YamlValue::as_str)
}

fn mihomo_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| format!("Failed to create Mihomo API client: {error}"))
}

fn add_mihomo_auth(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match mihomo_controller_secret() {
        Ok(secret) if !secret.is_empty() => {
            builder.header(AUTHORIZATION, format!("Bearer {secret}"))
        }
        _ => builder,
    }
}

fn mihomo_controller_base() -> Result<String, String> {
    let path = active_mihomo_config_path()?;
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read Mihomo controller config: {error}"))?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content)
        .map_err(|error| format!("Failed to parse Mihomo controller config: {error}"))?;
    let controller = yaml
        .get("external-controller")
        .and_then(YamlValue::as_str)
        .unwrap_or("127.0.0.1:9090");
    if controller.starts_with("http://") || controller.starts_with("https://") {
        Ok(controller.trim_end_matches('/').to_string())
    } else {
        Ok(format!("http://{}", controller.trim_end_matches('/')))
    }
}

fn mihomo_controller_secret() -> Result<String, String> {
    let path = active_mihomo_config_path()?;
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read Mihomo controller secret: {error}"))?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content)
        .map_err(|error| format!("Failed to parse Mihomo controller secret: {error}"))?;
    Ok(yaml
        .get("secret")
        .and_then(YamlValue::as_str)
        .unwrap_or_default()
        .to_string())
}

fn path_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            byte => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        _ => String::new(),
    }
}

fn json_value_to_u64(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Number(value) => value.as_u64().unwrap_or_default(),
        serde_json::Value::String(value) => value.parse::<u64>().unwrap_or_default(),
        _ => 0,
    }
}

fn deserialize_lossy_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.as_ref().map(json_value_to_string).unwrap_or_default())
}

fn deserialize_lossy_option_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .map(json_value_to_string)
        .filter(|value| !value.trim().is_empty()))
}

fn deserialize_lossy_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(json_value_to_string)
            .filter(|value| !value.trim().is_empty())
            .collect(),
        Some(value) => {
            let item = json_value_to_string(&value);
            if item.is_empty() {
                Vec::new()
            } else {
                vec![item]
            }
        }
        None => Vec::new(),
    })
}

fn deserialize_nullable_json_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Array(items)) => items,
        Some(serde_json::Value::Null) | None => Vec::new(),
        Some(item) => vec![item],
    })
}

fn uppercase_or_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "UNKNOWN".to_string()
    } else {
        value.to_ascii_uppercase()
    }
}

async fn ensure_agent_runtime_components(settings: &AppSettings) -> Result<(), String> {
    let needs_zapret =
        settings.effective_route_mode() == RouteMode::Smart && settings.zapret.enabled;
    let service_installed = read_badvpn_agent_service_status().installed;
    if service_installed {
        if programdata_runtime_components_ready(needs_zapret) {
            return Ok(());
        }
        if !user_runtime_components_ready(needs_zapret) {
            log_event(
                "components",
                "first-run runtime component preparation requested for badvpn-agent",
            );
            install_components(false).await?;
        }
        stage_runtime_assets_to_programdata()?;
        log_event(
            "components",
            "first-run runtime components staged to ProgramData for badvpn-agent",
        );
        return if programdata_runtime_components_ready(needs_zapret) {
            Ok(())
        } else {
            Err("Runtime components are still missing from ProgramData after staging.".to_string())
        };
    }

    if user_runtime_components_ready(needs_zapret) {
        return Ok(());
    }

    log_event(
        "components",
        "first-run user runtime component preparation requested",
    );
    install_components(false).await?;

    if user_runtime_components_ready(needs_zapret) {
        Ok(())
    } else {
        Err("Runtime components are still missing after first-run preparation.".to_string())
    }
}

fn user_mihomo_ready() -> bool {
    resolve_mihomo_bin().is_ok()
}

fn programdata_mihomo_ready() -> bool {
    programdata_mihomo_bin()
        .map(|path| path.exists())
        .unwrap_or(false)
}

fn user_runtime_components_ready(needs_zapret: bool) -> bool {
    user_mihomo_ready() && (!needs_zapret || zapret_runtime_assets_ready().is_ok())
}

fn programdata_runtime_components_ready(needs_zapret: bool) -> bool {
    programdata_mihomo_ready()
        && (!needs_zapret || programdata_zapret_runtime_assets_ready().is_ok())
}

async fn install_components(force: bool) -> Result<(), String> {
    fs::create_dir_all(data_dir()?.join("downloads"))
        .map_err(|error| format!("Failed to create downloads directory: {error}"))?;
    let client = reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    if force || resolve_mihomo_bin().is_err() {
        let release = latest_release(&client, MIHOMO_REPO).await?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == format!("mihomo-windows-amd64-{}.zip", release.tag_name))
            .or_else(|| {
                release.assets.iter().find(|asset| {
                    asset.name.starts_with("mihomo-windows-amd64-")
                        && asset.name.ends_with(".zip")
                        && !asset.name.contains("-go")
                        && !asset.name.contains("-v1-")
                        && !asset.name.contains("-v2-")
                        && !asset.name.contains("-v3-")
                })
            })
            .ok_or_else(|| "No suitable Windows amd64 Mihomo asset found.".to_string())?;
        let bytes = download_asset(&client, &asset.browser_download_url).await?;
        let version = release.tag_name.clone();
        install_component_with_backup("mihomo", |backup| {
            let result = extract_mihomo_zip(&bytes)
                .and_then(|_| resolve_mihomo_bin().map(|_| ()))
                .and_then(|_| write_component_version("mihomo", &version));
            restore_component_backup_on_error("mihomo", backup, result)
        })?;
    }

    if force || zapret_runtime_assets_ready().is_err() {
        let release = latest_release(&client, FLOWSEAL_ZAPRET_REPO).await?;
        let asset = release
            .assets
            .iter()
            .find(|asset| {
                asset.name.starts_with("zapret-discord-youtube-") && asset.name.ends_with(".zip")
            })
            .or_else(|| {
                release
                    .assets
                    .iter()
                    .find(|asset| asset.name.ends_with(".zip"))
            })
            .ok_or_else(|| "No suitable Flowseal zapret zip asset found.".to_string())?;
        let bytes = download_asset(&client, &asset.browser_download_url).await?;
        let version = release.tag_name.clone();
        install_component_with_backup("zapret", |backup| {
            let result = extract_zapret_zip(&bytes)
                .and_then(|_| zapret_runtime_assets_ready())
                .and_then(|_| write_component_version("zapret", &version));
            restore_component_backup_on_error("zapret", backup, result)
        })?;
    }

    Ok(())
}

async fn latest_release(client: &reqwest::Client, repo: &str) -> Result<GithubRelease, String> {
    client
        .get(format!(
            "https://api.github.com/repos/{repo}/releases/latest"
        ))
        .send()
        .await
        .map_err(|error| format!("Failed to check GitHub release: {error}"))?
        .error_for_status()
        .map_err(|error| format!("GitHub returned an error: {error}"))?
        .json::<GithubRelease>()
        .await
        .map_err(|error| format!("Failed to parse GitHub release: {error}"))
}

async fn download_asset(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("Failed to download component: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Component download failed: {error}"))?
        .bytes()
        .await
        .map_err(|error| format!("Failed to read component download: {error}"))?;
    Ok(bytes.to_vec())
}

async fn check_github_component(
    client: &reqwest::Client,
    name: &str,
    current_version: &str,
    repo: &str,
) -> ComponentUpdate {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let result = async {
        let release = client
            .get(url)
            .send()
            .await
            .map_err(|error| format!("Failed to check GitHub release: {error}"))?
            .error_for_status()
            .map_err(|error| format!("GitHub returned an error: {error}"))?
            .json::<GithubRelease>()
            .await
            .map_err(|error| format!("Failed to parse GitHub release: {error}"))?;
        Ok::<GithubRelease, String>(release)
    }
    .await;

    match result {
        Ok(release) => ComponentUpdate {
            name: name.to_string(),
            current_version: current_version.to_string(),
            update_available: release.tag_name != current_version,
            latest_version: Some(release.tag_name),
            release_url: Some(release.html_url),
            error: None,
        },
        Err(error) => ComponentUpdate {
            name: name.to_string(),
            current_version: current_version.to_string(),
            latest_version: None,
            release_url: None,
            update_available: false,
            error: Some(error),
        },
    }
}

async fn check_flowseal_lists_component(client: &reqwest::Client) -> ComponentUpdate {
    let current_version = local_flowseal_version().unwrap_or_else(|| "local".to_string());
    let result = client
        .get(FLOWSEAL_VERSION_URL)
        .send()
        .await
        .map_err(|error| format!("Failed to check Flowseal list version: {error}"));
    match result {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.text().await {
                Ok(version) => {
                    let latest = version.trim().to_string();
                    ComponentUpdate {
                        name: "flowseal lists".to_string(),
                        current_version: current_version.clone(),
                        latest_version: Some(latest.clone()),
                        release_url: Some(
                            "https://github.com/Flowseal/zapret-discord-youtube".to_string(),
                        ),
                        update_available: latest != current_version,
                        error: None,
                    }
                }
                Err(error) => ComponentUpdate {
                    name: "flowseal lists".to_string(),
                    current_version,
                    latest_version: None,
                    release_url: None,
                    update_available: false,
                    error: Some(format!("Failed to read Flowseal list version: {error}")),
                },
            },
            Err(error) => ComponentUpdate {
                name: "flowseal lists".to_string(),
                current_version,
                latest_version: None,
                release_url: None,
                update_available: false,
                error: Some(format!(
                    "Flowseal version endpoint returned an error: {error}"
                )),
            },
        },
        Err(error) => ComponentUpdate {
            name: "flowseal lists".to_string(),
            current_version,
            latest_version: None,
            release_url: None,
            update_available: false,
            error: Some(error),
        },
    }
}

fn local_mihomo_version() -> Result<String, String> {
    if let Some(version) = local_component_version("mihomo") {
        return Ok(version);
    }
    let path = resolve_mihomo_bin()?;
    command_version(path, &["-v"]).map(|value| normalize_version_text(&value))
}

fn local_zapret_version() -> Result<String, String> {
    if let Some(version) = local_component_version("zapret") {
        return Ok(version);
    }
    let path = resolve_winws_bin()?;
    command_version(path, &["--version"])
        .or_else(|_| command_version(resolve_winws_bin()?, &["-h"]))
        .map(|value| {
            normalize_version_text(
                value
                    .lines()
                    .find(|line| line.to_ascii_lowercase().contains("winws"))
                    .unwrap_or(value.lines().next().unwrap_or("installed")),
            )
        })
}

fn write_component_version(component: &str, version: &str) -> Result<(), String> {
    let path = component_dir(component)?.join("component-version.txt");
    fs::write(&path, normalize_version_text(version)).map_err(|error| {
        format!(
            "Failed to write component version stamp {}: {error}",
            path.display()
        )
    })
}

fn local_component_version(component: &str) -> Option<String> {
    fs::read_to_string(component_dir(component).ok()?.join("component-version.txt"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn local_flowseal_version() -> Option<String> {
    fs::read_to_string(zapret_lists_dir().ok()?.join("flowseal-version.txt"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn command_version(path: PathBuf, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(path);
    command.args(args);
    hide_process_window(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("Failed to run version command: {error}"))?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Err("version command returned no output".to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn normalize_version_text(value: &str) -> String {
    value
        .lines()
        .next()
        .unwrap_or(value)
        .trim()
        .trim_start_matches("Mihomo Meta ")
        .trim()
        .to_string()
}

struct ImportedSubscription {
    subscription: SubscriptionState,
    body: String,
}

async fn fetch_subscription(url: &str) -> Result<ImportedSubscription, String> {
    fetch_subscription_with_options(url, &PersistedSubscriptionFetchOptions::default()).await
}

async fn fetch_active_subscription_profile(url: &str) -> Result<ImportedSubscription, String> {
    let store = read_persisted_subscription_profiles().unwrap_or_default();
    let options = store
        .active_id
        .as_deref()
        .and_then(|active_id| {
            store
                .profiles
                .iter()
                .find(|profile| profile.id == active_id)
        })
        .and_then(|profile| {
            profile
                .subscription
                .url
                .as_deref()
                .filter(|stored| stored.eq_ignore_ascii_case(url))
                .map(|_| profile.fetch_options.clone())
        })
        .unwrap_or_default();
    fetch_subscription_with_options(url, &options).await
}

async fn fetch_subscription_with_options(
    url: &str,
    options: &PersistedSubscriptionFetchOptions,
) -> Result<ImportedSubscription, String> {
    let client = subscription_http_client(options)?;

    let response = client
        .get(url)
        .header(ACCEPT, "application/x-yaml,text/yaml,text/plain,*/*")
        .send()
        .await
        .map_err(|error| {
            format_subscription_fetch_error("Failed to fetch subscription", url, error)
        })?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.map_err(|error| {
        format_subscription_fetch_error("Failed to read subscription body", url, error)
    })?;

    if !status.is_success() {
        if let Some(failure) = classify_subscription_failure(Some(status.as_u16()), &body) {
            return Err(format!(
                "Subscription provider rejected the profile: {}",
                failure.message
            ));
        }
        return Err(format!(
            "Subscription server returned an error from {}: HTTP {}",
            redact_url(url),
            status
        ));
    }

    let summary = summarize_subscription_body(&body);
    log_event(
        "subscription",
        format!(
            "fetched format={:?} nodes={} decoded_size={} content_type={} timeout={}s proxy_mode={:?}",
            summary.format,
            summary.node_count,
            summary.decoded_size_bytes,
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown"),
            options.timeout_seconds,
            options.proxy_mode,
        ),
    );
    if summary.node_count == 0 {
        if let Some(failure) = classify_subscription_failure(None, &body) {
            return Err(format!(
                "Subscription provider returned no usable nodes: {}",
                failure.message
            ));
        }
        return Err("Subscription fetched, but no supported nodes were found.".to_string());
    }

    Ok(ImportedSubscription {
        subscription: SubscriptionState {
            url: Some(url.to_string()),
            is_valid: Some(true),
            validation_error: None,
            last_refreshed_at: Some(current_unix_timestamp().to_string()),
            profile_title: decoded_header_any(
                &headers,
                &["profile-title", "subscription-title", "profile_title"],
            ),
            announce: decoded_header_any(
                &headers,
                &[
                    "announce",
                    "announcement",
                    "profile-announce",
                    "profile_announce",
                ],
            ),
            announce_url: plain_header_any(
                &headers,
                &["announce-url", "announcement-url", "announce_url"],
            ),
            support_url: plain_header_any(&headers, &["support-url", "support_url"]),
            profile_web_page_url: plain_header_any(
                &headers,
                &[
                    "profile-web-page-url",
                    "profile-web-url",
                    "profile_web_page_url",
                ],
            ),
            update_interval_hours: plain_header_any(
                &headers,
                &["profile-update-interval", "profile_update_interval"],
            )
            .and_then(|value| value.parse::<u64>().ok()),
            user_info: parse_subscription_userinfo(
                plain_header_any(
                    &headers,
                    &[
                        "subscription-userinfo",
                        "subscription-user-info",
                        "subscription_userinfo",
                    ],
                )
                .as_deref(),
            ),
            node_count: summary.node_count,
            format: summary.format,
        },
        body,
    })
}

fn subscription_http_client(
    options: &PersistedSubscriptionFetchOptions,
) -> Result<reqwest::Client, String> {
    let timeout = options.timeout_seconds.clamp(5, 120);
    let user_agent = options
        .user_agent
        .as_deref()
        .unwrap_or(SUBSCRIPTION_USER_AGENT);
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(timeout));

    match options.proxy_mode {
        SubscriptionFetchProxyMode::Direct => {
            builder = builder.no_proxy();
        }
        SubscriptionFetchProxyMode::System => {}
        SubscriptionFetchProxyMode::Custom => {
            let proxy_url = options
                .protected_custom_proxy_url
                .as_deref()
                .and_then(|value| unprotect_secret(value).ok())
                .ok_or_else(|| "Custom subscription fetch proxy is not configured.".to_string())?;
            validate_custom_fetch_proxy_url(&proxy_url)?;
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|_| "Custom subscription fetch proxy is invalid.".to_string())?;
            builder = builder.no_proxy().proxy(proxy);
        }
    }

    builder
        .build()
        .map_err(|error| format!("Failed to create subscription HTTP client: {error}"))
}

fn validate_custom_fetch_proxy_url(value: &str) -> Result<(), String> {
    let parsed = url::Url::parse(value)
        .map_err(|_| "Custom subscription fetch proxy URL is invalid.".to_string())?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(
                "Custom subscription fetch proxy must use http:// or https://.".to_string(),
            );
        }
    }
    if parsed.host_str().is_none() {
        return Err("Custom subscription fetch proxy must include a host.".to_string());
    }
    Ok(())
}

fn normalize_subscription_fetch_user_agent(
    value: Option<String>,
    current: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(current.map(ToOwned::to_owned));
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 256 {
        return Err("Subscription fetch user-agent is too long.".to_string());
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err("Subscription fetch user-agent cannot contain control characters.".to_string());
    }
    Ok(Some(value.to_string()))
}

fn format_subscription_fetch_error(action: &str, url: &str, error: reqwest::Error) -> String {
    let redacted_url = redact_url(url);
    if let Some(status) = error.status() {
        return format!("{action} from {redacted_url}: HTTP {status}");
    }

    let reason = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect failed"
    } else if error.is_body() {
        "response body read failed"
    } else if error.is_decode() {
        "response decode failed"
    } else if error.is_request() {
        "request failed"
    } else {
        "network error"
    };
    format!("{action} from {redacted_url}: {reason}")
}

fn write_mihomo_config(subscription_body: &str) -> Result<(), String> {
    let secret = badvpn_common::generate_controller_secret()?;
    let settings = load_app_settings();
    write_zapret_lists()?;
    let options = mihomo_options_for_runtime_route(&settings, settings.effective_route_mode());
    let generated = generate_mihomo_config_from_subscription_with_options(
        subscription_body,
        &secret,
        &options,
    )?;
    store_preview_policy(&generated.policy);
    let config_path = mihomo_config_path()?;
    let parent = config_path
        .parent()
        .ok_or_else(|| "Failed to resolve Mihomo config directory.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create Mihomo config directory: {error}"))?;
    write_mihomo_config_atomically(&config_path, &generated.yaml, "subscription import")?;
    Ok(())
}

async fn maybe_reload_mihomo_after_subscription_change(context: &str) -> Option<String> {
    if should_use_agent_runtime() {
        log_event(
            "mihomo",
            format!(
                "{context}: service-first runtime owns reload; reconnect to apply profile changes"
            ),
        );
        return Some("Profile saved. Reconnect to apply it through badvpn-agent.".to_string());
    }

    let running = state().lock().map(|state| state.running).unwrap_or(false);
    if !running {
        return None;
    }
    let config_path = match mihomo_config_path() {
        Ok(path) => path,
        Err(error) => {
            log_event(
                "mihomo",
                format!("{context}: failed to resolve config path for reload: {error}"),
            );
            return Some(format!(
                "Profile saved, but Mihomo reload failed: {error}. Reconnect to apply."
            ));
        }
    };
    match reload_mihomo_config_via_api(&config_path).await {
        Ok(()) => {
            log_event("mihomo", format!("{context}: running config reloaded"));
            Some("Profile saved and running Mihomo config was reloaded.".to_string())
        }
        Err(error) => {
            log_event("mihomo", format!("{context}: reload failed: {error}"));
            Some(format!(
                "Profile saved, but running Mihomo reload failed: {error}. Reconnect to apply."
            ))
        }
    }
}

fn ensure_mihomo_config_routing(
    config_path: &PathBuf,
    settings: &AppSettings,
    route_mode: RouteMode,
) -> Result<(), String> {
    let content = fs::read_to_string(config_path)
        .map_err(|error| format!("Failed to read Mihomo config for route migration: {error}"))?;
    let secret = match serde_yaml::from_str::<YamlValue>(&content)
        .ok()
        .and_then(|yaml| {
            yaml.get("secret")
                .and_then(YamlValue::as_str)
                .map(ToOwned::to_owned)
        }) {
        Some(existing) => existing,
        None => badvpn_common::generate_controller_secret()?,
    };
    let rendered = overlay_mihomo_config_yaml(
        &content,
        &secret,
        &mihomo_options_for_runtime_route(settings, route_mode),
    )?;
    write_mihomo_config_atomically(config_path, &rendered, "route migration")
}

fn mihomo_options_for_runtime_route(
    settings: &AppSettings,
    route_mode: RouteMode,
) -> MihomoConfigOptions {
    let mut options = settings.mihomo_options();
    options.route_mode = route_mode;
    if route_mode == RouteMode::Smart {
        let targets = zapret_direct_targets_for_mihomo(settings);
        options.zapret_direct_domains = targets.domains;
        options.zapret_direct_cidrs = targets.cidrs;
        options.zapret_direct_processes = targets.processes;
        options.zapret_direct_tcp_ports = targets.tcp_ports;
        options.zapret_direct_udp_ports = targets.udp_ports;
    }
    options
}

#[derive(Debug, Default)]
struct ZapretDirectTargets {
    domains: Vec<String>,
    cidrs: Vec<String>,
    processes: Vec<String>,
    tcp_ports: Vec<String>,
    udp_ports: Vec<String>,
}

fn zapret_direct_targets_for_mihomo(settings: &AppSettings) -> ZapretDirectTargets {
    match read_zapret_direct_targets_for_mihomo(settings) {
        Ok(targets) => {
            log_event(
                "mihomo-config",
                format!(
                    "zapret direct targets loaded for YAML overlay: domains={} cidrs={} processes={}",
                    targets.domains.len(),
                    targets.cidrs.len(),
                    targets.processes.len()
                ),
            );
            targets
        }
        Err(error) => {
            log_event(
                "mihomo-config",
                format!("failed to read runtime zapret direct targets: {error}; using embedded defaults"),
            );
            ZapretDirectTargets::default()
        }
    }
}

fn read_zapret_direct_targets_for_mihomo(
    settings: &AppSettings,
) -> Result<ZapretDirectTargets, String> {
    let lists_dir = zapret_lists_dir()?;
    let mut domains = Vec::new();
    for name in [
        "list-general.txt",
        "list-google.txt",
        "list-general-user.txt",
    ] {
        domains.extend(read_clean_list_lines(&lists_dir.join(name)).unwrap_or_default());
    }

    let mut excludes = std::collections::BTreeSet::new();
    for name in ["list-exclude.txt", "list-exclude-user.txt"] {
        excludes.extend(read_clean_list_lines(&lists_dir.join(name)).unwrap_or_default());
    }
    let domains = domains
        .into_iter()
        .filter_map(|domain| normalize_hostlist_domain(&domain))
        .filter(|domain| domain != "domain.example.abc" && !excludes.contains(domain))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let cidrs = if settings.zapret.ipset_filter == ZapretIpSetFilter::Loaded {
        let cidr_excludes = ["ipset-exclude.txt", "ipset-exclude-user.txt"]
            .into_iter()
            .flat_map(|name| read_clean_list_lines(&lists_dir.join(name)).unwrap_or_default())
            .map(|cidr| cidr.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        read_clean_list_lines(&lists_dir.join("ipset-all.txt"))
            .unwrap_or_default()
            .into_iter()
            .map(|cidr| cidr.to_ascii_lowercase())
            .filter(|cidr| {
                cidr != "203.0.113.113/32" && !cidr.is_empty() && !cidr_excludes.contains(cidr)
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Ok(ZapretDirectTargets {
        domains,
        cidrs,
        processes: Vec::new(),
        tcp_ports: Vec::new(),
        udp_ports: Vec::new(),
    })
}

fn read_clean_list_lines(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read zapret list {}: {error}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn normalize_hostlist_domain(value: &str) -> Option<String> {
    let domain = value
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() || domain.contains('/') || domain.contains('*') {
        None
    } else {
        Some(domain)
    }
}

fn write_mihomo_config_atomically(
    config_path: &Path,
    rendered_yaml: &str,
    reason: &str,
) -> Result<(), String> {
    let parent = config_path
        .parent()
        .ok_or_else(|| "Failed to resolve Mihomo config directory.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create Mihomo config directory: {error}"))?;

    let next_path = config_path.with_file_name("config.yaml.next");
    let backup_path = config_path.with_file_name("config.yaml.last-good");

    let mut yaml = rendered_yaml.to_string();
    let geosite_available = geodata_asset_exists(parent, &["GeoSite.dat", "geosite.dat"]);
    let geoip_available = geodata_asset_exists(parent, &["GeoIP.dat", "geoip.dat"]);
    for message in strip_missing_geodata_rules(&mut yaml, geosite_available, geoip_available)? {
        log_event("mihomo-config", message);
    }

    fs::write(&next_path, &yaml)
        .map_err(|error| format!("Failed to write staged Mihomo config: {error}"))?;

    if let Err(error) = validate_mihomo_config_yaml_structure(&yaml) {
        let _ = fs::remove_file(&next_path);
        log_event(
            "mihomo-config",
            format!("staged config rejected for {reason}: {error}"),
        );
        return Err(format!(
            "Generated Mihomo config failed structural validation: {error}"
        ));
    }

    if let Ok(mihomo_bin) = resolve_mihomo_bin() {
        if let Err(error) = test_mihomo_config(&mihomo_bin, &next_path, parent) {
            let _ = fs::remove_file(&next_path);
            log_event(
                "mihomo-config",
                format!("staged config rejected for {reason}: {error}"),
            );
            return Err(format!(
                "Generated Mihomo config failed validation: {error}"
            ));
        }
    } else {
        log_event(
            "mihomo-config",
            format!("staged config for {reason} was written without preflight; Mihomo binary is not installed yet"),
        );
    }

    if config_path.exists() {
        fs::copy(config_path, &backup_path)
            .map_err(|error| format!("Failed to save last-good Mihomo config: {error}"))?;
    }

    if let Err(error) = fs::copy(&next_path, config_path) {
        let rollback = restore_mihomo_config_backup(config_path, &backup_path)
            .map(|restored| {
                if restored {
                    "last-good restored".to_string()
                } else {
                    "no last-good backup available".to_string()
                }
            })
            .unwrap_or_else(|rollback_error| format!("rollback failed: {rollback_error}"));
        let _ = fs::remove_file(&next_path);
        return Err(format!(
            "Failed to promote staged Mihomo config: {error}; {rollback}"
        ));
    }
    let _ = fs::remove_file(&next_path);
    log_event(
        "mihomo-config",
        format!(
            "promoted staged config for {reason}; backup={}",
            backup_path.display()
        ),
    );
    Ok(())
}

fn restore_mihomo_config_backup(config_path: &Path, backup_path: &Path) -> Result<bool, String> {
    if !backup_path.exists() {
        return Ok(false);
    }
    fs::copy(backup_path, config_path)
        .map_err(|error| format!("Failed to restore last-good Mihomo config: {error}"))?;
    Ok(true)
}

fn validate_mihomo_config_yaml_structure(rendered_yaml: &str) -> Result<(), String> {
    let value = serde_yaml::from_str::<YamlValue>(rendered_yaml)
        .map_err(|error| format!("YAML parse error: {error}"))?;
    let map = value
        .as_mapping()
        .ok_or_else(|| "top-level Mihomo config must be a mapping".to_string())?;

    if let Some(tun) = map.get(YamlValue::String("tun".to_string())) {
        validate_yaml_mapping(tun, "tun")?;
        validate_optional_bool(tun, "tun", "enable")?;
        validate_optional_integer(tun, "tun", "mtu")?;
        validate_optional_sequence(tun, "tun", "dns-hijack")?;
        validate_optional_sequence(tun, "tun", "route-exclude-address")?;
    }
    if let Some(dns) = map.get(YamlValue::String("dns".to_string())) {
        validate_yaml_mapping(dns, "dns")?;
        validate_optional_bool(dns, "dns", "enable")?;
        validate_optional_string(dns, "dns", "enhanced-mode")?;
        validate_optional_string(dns, "dns", "fake-ip-range")?;
        validate_optional_sequence(dns, "dns", "nameserver")?;
        validate_optional_mapping(dns, "dns", "nameserver-policy")?;
    }
    if let Some(sniffer) = map.get(YamlValue::String("sniffer".to_string())) {
        validate_yaml_mapping(sniffer, "sniffer")?;
        validate_optional_bool(sniffer, "sniffer", "enable")?;
        validate_optional_mapping(sniffer, "sniffer", "sniff")?;
        validate_optional_sequence(sniffer, "sniffer", "force-domain")?;
        validate_optional_sequence(sniffer, "sniffer", "skip-domain")?;
        validate_optional_sequence(sniffer, "sniffer", "skip-src-address")?;
        validate_optional_sequence(sniffer, "sniffer", "skip-dst-address")?;
    }

    Ok(())
}

fn validate_yaml_mapping<'a>(
    value: &'a YamlValue,
    section: &str,
) -> Result<&'a serde_yaml::Mapping, String> {
    value
        .as_mapping()
        .ok_or_else(|| format!("{section} section must be a mapping"))
}

fn yaml_section_field<'a>(
    value: &'a YamlValue,
    section: &str,
    field: &str,
) -> Result<Option<&'a YamlValue>, String> {
    Ok(validate_yaml_mapping(value, section)?.get(YamlValue::String(field.to_string())))
}

fn validate_optional_bool(value: &YamlValue, section: &str, field: &str) -> Result<(), String> {
    if let Some(field_value) = yaml_section_field(value, section, field)? {
        if !field_value.is_bool() {
            return Err(format!("{section}.{field} must be a boolean"));
        }
    }
    Ok(())
}

fn validate_optional_integer(value: &YamlValue, section: &str, field: &str) -> Result<(), String> {
    if let Some(field_value) = yaml_section_field(value, section, field)? {
        if field_value.as_i64().is_none() {
            return Err(format!("{section}.{field} must be an integer"));
        }
    }
    Ok(())
}

fn validate_optional_string(value: &YamlValue, section: &str, field: &str) -> Result<(), String> {
    if let Some(field_value) = yaml_section_field(value, section, field)? {
        if field_value.as_str().is_none() {
            return Err(format!("{section}.{field} must be a string"));
        }
    }
    Ok(())
}

fn validate_optional_sequence(value: &YamlValue, section: &str, field: &str) -> Result<(), String> {
    if let Some(field_value) = yaml_section_field(value, section, field)? {
        if !field_value.is_sequence() {
            return Err(format!("{section}.{field} must be a sequence"));
        }
    }
    Ok(())
}

fn validate_optional_mapping(value: &YamlValue, section: &str, field: &str) -> Result<(), String> {
    if let Some(field_value) = yaml_section_field(value, section, field)? {
        if !field_value.is_mapping() {
            return Err(format!("{section}.{field} must be a mapping"));
        }
    }
    Ok(())
}

fn start_mihomo_process(mihomo_bin: &PathBuf, config_path: &PathBuf) -> Result<(), String> {
    stop_child(mihomo_process())?;
    let mihomo_dir = config_path
        .parent()
        .ok_or_else(|| "Failed to resolve Mihomo home directory.".to_string())?;
    test_mihomo_config(mihomo_bin, config_path, mihomo_dir)?;
    let mut command = Command::new(mihomo_bin);
    command.arg("-d").arg(mihomo_dir).arg("-f").arg(config_path);
    command
        .stdin(Stdio::null())
        .stdout(mihomo_log_file("stdout")?)
        .stderr(mihomo_log_file("stderr")?);
    hide_process_window(&mut command);
    let child = command
        .spawn()
        .map_err(|error| format!("Failed to start Mihomo: {error}"))?;
    write_mihomo_pid_file(child.id())?;
    *mihomo_process()
        .lock()
        .map_err(|_| "mihomo process lock is poisoned".to_string())? = Some(child);
    Ok(())
}

fn test_mihomo_config(
    mihomo_bin: &PathBuf,
    config_path: &PathBuf,
    mihomo_dir: &Path,
) -> Result<(), String> {
    let mut command = Command::new(mihomo_bin);
    command
        .arg("-t")
        .arg("-d")
        .arg(mihomo_dir)
        .arg("-f")
        .arg(config_path);
    hide_process_window(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("Failed to run Mihomo config test: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    log_event(
        "mihomo-test",
        format!(
            "status={} stdout={} stderr={}",
            output.status,
            last_log_lines(&stdout, 3),
            last_log_lines(&stderr, 8)
        ),
    );
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Mihomo config test failed: {}",
            last_log_lines(&format!("{stdout}\n{stderr}"), 8)
        ))
    }
}

fn mihomo_log_file(kind: &str) -> Result<std::fs::File, String> {
    let dir = data_dir()?.join("logs");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create Mihomo log directory: {error}"))?;
    let path = dir.join(format!("mihomo.{kind}.log"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("Failed to open Mihomo log {}: {error}", path.display()))
}

fn last_log_lines(value: &str, count: usize) -> String {
    let lines = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let start = lines.len().saturating_sub(count);
    lines[start..].join(" | ")
}

fn start_zapret_process(settings: &AppSettings) -> Result<String, String> {
    let winws_bin = resolve_winws_bin()?;
    stop_child(zapret_process())?;
    if settings.zapret.run_mode == ZapretRunMode::Service {
        log_event(
            "zapret",
            "service run mode maps to the BadVpn-owned winws process path; BadVpnZapret is not created",
        );
    }
    if has_windows_process(&["winws.exe"]) {
        return Err(
            "Mihomo started, but another winws.exe is already running. Stop external zapret/GoodbyeDPI first, then reconnect BadVpn so it can apply the Flowseal profile.".to_string(),
        );
    }

    let assets = flowseal_zapret_assets()?;
    let preferred = selected_zapret_profile(&assets, settings);
    let mut errors = Vec::new();
    let attempts = if settings.zapret.auto_profile_fallback {
        zapret_profile_attempt_order(preferred)
    } else {
        vec![preferred]
    };
    for profile in attempts {
        match spawn_zapret_profile(&winws_bin, &assets, profile, settings) {
            Ok(child) => {
                let auto_selected = profile != preferred;
                if auto_selected {
                    persist_zapret_profile(profile).ok();
                }
                *zapret_process()
                    .lock()
                    .map_err(|_| "zapret process lock is poisoned".to_string())? = Some(child);
                let suffix = if auto_selected {
                    "; auto-selected after selected profile failed"
                } else {
                    ""
                };
                return Ok(format!("zapret running ({}){suffix}", profile.label()));
            }
            Err(error) => errors.push(format!("{}: {error}", profile.label())),
        }
    }

    Err(format!(
        "Mihomo started, but all zapret Flowseal profiles failed: {}",
        errors.join("; ")
    ))
}

fn spawn_zapret_profile(
    winws_bin: &PathBuf,
    assets: &FlowsealZapretAssets,
    profile: ZapretProfile,
    settings: &AppSettings,
) -> Result<Child, String> {
    let args = flowseal_zapret_args(assets, profile, settings)?;
    let mut command = Command::new(winws_bin);
    command.current_dir(&assets.bin_dir).args(args);
    prepare_background_process(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("zapret/winws did not start: {error}"))?;
    std::thread::sleep(Duration::from_millis(900));
    if let Some(status) = child
        .try_wait()
        .map_err(|error| format!("Failed to verify zapret/winws status: {error}"))?
    {
        return Err(format!(
            "winws exited immediately with {status}. This usually means WinDivert needs elevation, a conflicting bypass is running, or required Flowseal assets are missing."
        ));
    }
    Ok(child)
}

#[derive(Debug, Clone)]
struct FlowsealZapretAssets {
    root_dir: PathBuf,
    bin_dir: PathBuf,
    profiles_dir: PathBuf,
    list_general: PathBuf,
    list_general_user: PathBuf,
    list_google: PathBuf,
    list_exclude: PathBuf,
    list_exclude_user: PathBuf,
    ipset_all: PathBuf,
    ipset_effective: PathBuf,
    ipset_exclude: PathBuf,
    ipset_exclude_user: PathBuf,
    fake_quic: PathBuf,
    fake_tls_google: PathBuf,
    fake_tls_4pda: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZapretProfile {
    General,
    Alt,
    Alt2,
    Alt3,
    Alt4,
    Alt5,
    Alt6,
    Alt7,
    Alt8,
    Alt9,
    Alt10,
    Alt11,
    FakeTlsAuto,
    FakeTlsAutoAlt,
    FakeTlsAutoAlt2,
    FakeTlsAutoAlt3,
    SimpleFake,
    SimpleFakeAlt,
    SimpleFakeAlt2,
}

impl ZapretProfile {
    fn all() -> &'static [ZapretProfile] {
        &[
            ZapretProfile::General,
            ZapretProfile::Alt,
            ZapretProfile::Alt2,
            ZapretProfile::Alt3,
            ZapretProfile::Alt4,
            ZapretProfile::Alt5,
            ZapretProfile::Alt6,
            ZapretProfile::Alt7,
            ZapretProfile::Alt8,
            ZapretProfile::Alt9,
            ZapretProfile::Alt10,
            ZapretProfile::Alt11,
            ZapretProfile::FakeTlsAuto,
            ZapretProfile::FakeTlsAutoAlt,
            ZapretProfile::FakeTlsAutoAlt2,
            ZapretProfile::FakeTlsAutoAlt3,
            ZapretProfile::SimpleFake,
            ZapretProfile::SimpleFakeAlt,
            ZapretProfile::SimpleFakeAlt2,
        ]
    }

    fn id(self) -> &'static str {
        match self {
            ZapretProfile::General => "general",
            ZapretProfile::Alt => "alt",
            ZapretProfile::Alt2 => "alt2",
            ZapretProfile::Alt3 => "alt3",
            ZapretProfile::Alt4 => "alt4",
            ZapretProfile::Alt5 => "alt5",
            ZapretProfile::Alt6 => "alt6",
            ZapretProfile::Alt7 => "alt7",
            ZapretProfile::Alt8 => "alt8",
            ZapretProfile::Alt9 => "alt9",
            ZapretProfile::Alt10 => "alt10",
            ZapretProfile::Alt11 => "alt11",
            ZapretProfile::FakeTlsAuto => "fake_tls_auto",
            ZapretProfile::FakeTlsAutoAlt => "fake_tls_auto_alt",
            ZapretProfile::FakeTlsAutoAlt2 => "fake_tls_auto_alt2",
            ZapretProfile::FakeTlsAutoAlt3 => "fake_tls_auto_alt3",
            ZapretProfile::SimpleFake => "simple_fake",
            ZapretProfile::SimpleFakeAlt => "simple_fake_alt",
            ZapretProfile::SimpleFakeAlt2 => "simple_fake_alt2",
        }
    }

    fn label(self) -> &'static str {
        match self {
            ZapretProfile::General => "Flowseal general",
            ZapretProfile::Alt => "Flowseal ALT",
            ZapretProfile::Alt2 => "Flowseal ALT2",
            ZapretProfile::Alt3 => "Flowseal ALT3",
            ZapretProfile::Alt4 => "Flowseal ALT4",
            ZapretProfile::Alt5 => "Flowseal ALT5",
            ZapretProfile::Alt6 => "Flowseal ALT6",
            ZapretProfile::Alt7 => "Flowseal ALT7",
            ZapretProfile::Alt8 => "Flowseal ALT8",
            ZapretProfile::Alt9 => "Flowseal ALT9",
            ZapretProfile::Alt10 => "Flowseal ALT10",
            ZapretProfile::Alt11 => "Flowseal ALT11",
            ZapretProfile::FakeTlsAuto => "Fake TLS auto",
            ZapretProfile::FakeTlsAutoAlt => "Fake TLS auto ALT",
            ZapretProfile::FakeTlsAutoAlt2 => "Fake TLS auto ALT2",
            ZapretProfile::FakeTlsAutoAlt3 => "Fake TLS auto ALT3",
            ZapretProfile::SimpleFake => "Simple fake",
            ZapretProfile::SimpleFakeAlt => "Simple fake ALT",
            ZapretProfile::SimpleFakeAlt2 => "Simple fake ALT2",
        }
    }

    fn description(self) -> &'static str {
        match self {
            ZapretProfile::General => {
                "Default Flowseal multisplit strategy; uses the full fake packet set."
            }
            ZapretProfile::Alt => {
                "Flowseal fake/fakedsplit strategy for providers where general is unstable."
            }
            ZapretProfile::Alt2 => {
                "Fallback multisplit strategy that works with the minimal bundled fake packets."
            }
            ZapretProfile::Alt3
            | ZapretProfile::Alt4
            | ZapretProfile::Alt5
            | ZapretProfile::Alt6
            | ZapretProfile::Alt7
            | ZapretProfile::Alt8
            | ZapretProfile::Alt9
            | ZapretProfile::Alt10
            | ZapretProfile::Alt11 => {
                "Flowseal alternative profile from the Windows bundle; useful when default profiles are unstable."
            }
            ZapretProfile::FakeTlsAuto
            | ZapretProfile::FakeTlsAutoAlt
            | ZapretProfile::FakeTlsAutoAlt2
            | ZapretProfile::FakeTlsAutoAlt3 => {
                "Flowseal fake TLS AUTO profile; usually tested manually for strict DPI/provider combinations."
            }
            ZapretProfile::SimpleFake
            | ZapretProfile::SimpleFakeAlt
            | ZapretProfile::SimpleFakeAlt2 => {
                "Flowseal simple fake profile; lower-complexity fallback for environments where split modes fail."
            }
        }
    }

    fn bat_file_name(self) -> &'static str {
        match self {
            ZapretProfile::General => "general.bat",
            ZapretProfile::Alt => "general (ALT).bat",
            ZapretProfile::Alt2 => "general (ALT2).bat",
            ZapretProfile::Alt3 => "general (ALT3).bat",
            ZapretProfile::Alt4 => "general (ALT4).bat",
            ZapretProfile::Alt5 => "general (ALT5).bat",
            ZapretProfile::Alt6 => "general (ALT6).bat",
            ZapretProfile::Alt7 => "general (ALT7).bat",
            ZapretProfile::Alt8 => "general (ALT8).bat",
            ZapretProfile::Alt9 => "general (ALT9).bat",
            ZapretProfile::Alt10 => "general (ALT10).bat",
            ZapretProfile::Alt11 => "general (ALT11).bat",
            ZapretProfile::FakeTlsAuto => "general (FAKE TLS AUTO).bat",
            ZapretProfile::FakeTlsAutoAlt => "general (FAKE TLS AUTO ALT).bat",
            ZapretProfile::FakeTlsAutoAlt2 => "general (FAKE TLS AUTO ALT2).bat",
            ZapretProfile::FakeTlsAutoAlt3 => "general (FAKE TLS AUTO ALT3).bat",
            ZapretProfile::SimpleFake => "general (SIMPLE FAKE).bat",
            ZapretProfile::SimpleFakeAlt => "general (SIMPLE FAKE ALT).bat",
            ZapretProfile::SimpleFakeAlt2 => "general (SIMPLE FAKE ALT2).bat",
        }
    }

    fn strategy(self) -> ZapretStrategy {
        match self {
            ZapretProfile::General => ZapretStrategy::General,
            ZapretProfile::Alt => ZapretStrategy::Alt,
            ZapretProfile::Alt2 => ZapretStrategy::Alt2,
            ZapretProfile::Alt3 => ZapretStrategy::Alt3,
            ZapretProfile::Alt4 => ZapretStrategy::Alt4,
            ZapretProfile::Alt5 => ZapretStrategy::Alt5,
            ZapretProfile::Alt6 => ZapretStrategy::Alt6,
            ZapretProfile::Alt7 => ZapretStrategy::Alt7,
            ZapretProfile::Alt8 => ZapretStrategy::Alt8,
            ZapretProfile::Alt9 => ZapretStrategy::Alt9,
            ZapretProfile::Alt10 => ZapretStrategy::Alt10,
            ZapretProfile::Alt11 => ZapretStrategy::Alt11,
            ZapretProfile::FakeTlsAuto => ZapretStrategy::FakeTlsAuto,
            ZapretProfile::FakeTlsAutoAlt => ZapretStrategy::FakeTlsAutoAlt,
            ZapretProfile::FakeTlsAutoAlt2 => ZapretStrategy::FakeTlsAutoAlt2,
            ZapretProfile::FakeTlsAutoAlt3 => ZapretStrategy::FakeTlsAutoAlt3,
            ZapretProfile::SimpleFake => ZapretStrategy::SimpleFake,
            ZapretProfile::SimpleFakeAlt => ZapretStrategy::SimpleFakeAlt,
            ZapretProfile::SimpleFakeAlt2 => ZapretStrategy::SimpleFakeAlt2,
        }
    }
}

fn selected_zapret_profile(assets: &FlowsealZapretAssets, settings: &AppSettings) -> ZapretProfile {
    match settings.zapret.strategy {
        ZapretStrategy::General => ZapretProfile::General,
        ZapretStrategy::Alt => ZapretProfile::Alt,
        ZapretStrategy::Alt2 => ZapretProfile::Alt2,
        ZapretStrategy::Alt3 => ZapretProfile::Alt3,
        ZapretStrategy::Alt4 => ZapretProfile::Alt4,
        ZapretStrategy::Alt5 => ZapretProfile::Alt5,
        ZapretStrategy::Alt6 => ZapretProfile::Alt6,
        ZapretStrategy::Alt7 => ZapretProfile::Alt7,
        ZapretStrategy::Alt8 => ZapretProfile::Alt8,
        ZapretStrategy::Alt9 => ZapretProfile::Alt9,
        ZapretStrategy::Alt10 => ZapretProfile::Alt10,
        ZapretStrategy::Alt11 => ZapretProfile::Alt11,
        ZapretStrategy::FakeTlsAuto => ZapretProfile::FakeTlsAuto,
        ZapretStrategy::FakeTlsAutoAlt => ZapretProfile::FakeTlsAutoAlt,
        ZapretStrategy::FakeTlsAutoAlt2 => ZapretProfile::FakeTlsAutoAlt2,
        ZapretStrategy::FakeTlsAutoAlt3 => ZapretProfile::FakeTlsAutoAlt3,
        ZapretStrategy::SimpleFake => ZapretProfile::SimpleFake,
        ZapretStrategy::SimpleFakeAlt => ZapretProfile::SimpleFakeAlt,
        ZapretStrategy::SimpleFakeAlt2 => ZapretProfile::SimpleFakeAlt2,
        ZapretStrategy::Auto => {
            read_persisted_zapret_profile().unwrap_or(if assets.fake_tls_4pda.exists() {
                ZapretProfile::General
            } else {
                ZapretProfile::Alt2
            })
        }
    }
}

fn configured_zapret_profile() -> ZapretProfile {
    let settings = load_app_settings();
    selected_zapret_profile(
        &flowseal_zapret_assets().unwrap_or_else(|_| FlowsealZapretAssets::fallback()),
        &settings,
    )
}

fn parse_zapret_profile_id(value: &str) -> Option<ZapretProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "general" | "flowseal-general" => Some(ZapretProfile::General),
        "alt" | "flowseal-alt" => Some(ZapretProfile::Alt),
        "alt2" | "flowseal-alt2" => Some(ZapretProfile::Alt2),
        "alt3" => Some(ZapretProfile::Alt3),
        "alt4" => Some(ZapretProfile::Alt4),
        "alt5" => Some(ZapretProfile::Alt5),
        "alt6" => Some(ZapretProfile::Alt6),
        "alt7" => Some(ZapretProfile::Alt7),
        "alt8" => Some(ZapretProfile::Alt8),
        "alt9" => Some(ZapretProfile::Alt9),
        "alt10" => Some(ZapretProfile::Alt10),
        "alt11" => Some(ZapretProfile::Alt11),
        "fake_tls_auto" => Some(ZapretProfile::FakeTlsAuto),
        "fake_tls_auto_alt" => Some(ZapretProfile::FakeTlsAutoAlt),
        "fake_tls_auto_alt2" => Some(ZapretProfile::FakeTlsAutoAlt2),
        "fake_tls_auto_alt3" => Some(ZapretProfile::FakeTlsAutoAlt3),
        "simple_fake" => Some(ZapretProfile::SimpleFake),
        "simple_fake_alt" => Some(ZapretProfile::SimpleFakeAlt),
        "simple_fake_alt2" => Some(ZapretProfile::SimpleFakeAlt2),
        _ => None,
    }
}

fn zapret_profile_attempt_order(preferred: ZapretProfile) -> Vec<ZapretProfile> {
    let mut profiles = vec![preferred];
    for profile in ZapretProfile::all() {
        if !profiles.contains(profile) {
            profiles.push(*profile);
        }
    }
    profiles
}

fn read_persisted_zapret_profile() -> Option<ZapretProfile> {
    let content = fs::read_to_string(zapret_profile_path().ok()?).ok()?;
    parse_zapret_profile_id(&content)
}

fn persist_zapret_profile(profile: ZapretProfile) -> Result<(), String> {
    let path = zapret_profile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create zapret profile directory: {error}"))?;
    }
    fs::write(&path, profile.id())
        .map_err(|error| format!("Failed to write zapret profile {}: {error}", path.display()))
}

fn build_zapret_profile_state(selected: ZapretProfile) -> ZapretProfileState {
    let options = ZapretProfile::all()
        .iter()
        .copied()
        .map(|profile| ZapretProfileOption {
            id: profile.id().to_string(),
            label: profile.label().to_string(),
            description: profile.description().to_string(),
            selected: profile == selected,
        })
        .collect();
    ZapretProfileState {
        selected: selected.id().to_string(),
        options,
    }
}

fn flowseal_zapret_assets() -> Result<FlowsealZapretAssets, String> {
    let root_dir = data_dir()?.join("components").join("zapret");
    let bin_dir = zapret_bin_dir()?;
    let profiles_dir = root_dir.join("profiles");
    let lists_dir = zapret_lists_dir()?;
    Ok(FlowsealZapretAssets {
        root_dir,
        profiles_dir,
        list_general: lists_dir.join("list-general.txt"),
        list_general_user: lists_dir.join("list-general-user.txt"),
        list_google: lists_dir.join("list-google.txt"),
        list_exclude: lists_dir.join("list-exclude.txt"),
        list_exclude_user: lists_dir.join("list-exclude-user.txt"),
        ipset_all: lists_dir.join("ipset-all.txt"),
        ipset_effective: lists_dir.join("ipset-all.effective.txt"),
        ipset_exclude: lists_dir.join("ipset-exclude.txt"),
        ipset_exclude_user: lists_dir.join("ipset-exclude-user.txt"),
        fake_quic: bin_dir.join("quic_initial_www_google_com.bin"),
        fake_tls_google: bin_dir.join("tls_clienthello_www_google_com.bin"),
        fake_tls_4pda: bin_dir.join("tls_clienthello_4pda_to.bin"),
        bin_dir,
    })
}

impl FlowsealZapretAssets {
    fn fallback() -> Self {
        let root_dir = data_dir()
            .unwrap_or_else(|_| PathBuf::from(".").join("runtime").join("BadVpn"))
            .join("components")
            .join("zapret");
        let bin_dir = root_dir.join("bin");
        let profiles_dir = root_dir.join("profiles");
        let lists_dir = data_dir()
            .unwrap_or_else(|_| PathBuf::from(".").join("runtime").join("BadVpn"))
            .join("zapret")
            .join("lists");
        Self {
            root_dir,
            bin_dir: bin_dir.clone(),
            profiles_dir,
            list_general: lists_dir.join("list-general.txt"),
            list_general_user: lists_dir.join("list-general-user.txt"),
            list_google: lists_dir.join("list-google.txt"),
            list_exclude: lists_dir.join("list-exclude.txt"),
            list_exclude_user: lists_dir.join("list-exclude-user.txt"),
            ipset_all: lists_dir.join("ipset-all.txt"),
            ipset_effective: lists_dir.join("ipset-all.effective.txt"),
            ipset_exclude: lists_dir.join("ipset-exclude.txt"),
            ipset_exclude_user: lists_dir.join("ipset-exclude-user.txt"),
            fake_quic: bin_dir.join("quic_initial_www_google_com.bin"),
            fake_tls_google: bin_dir.join("tls_clienthello_www_google_com.bin"),
            fake_tls_4pda: bin_dir.join("tls_clienthello_4pda_to.bin"),
        }
    }
}

fn zapret_bin_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BADVPN_WINWS_BIN") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    Ok(data_dir()?.join("components").join("zapret").join("bin"))
}

fn flowseal_zapret_args(
    assets: &FlowsealZapretAssets,
    profile: ZapretProfile,
    settings: &AppSettings,
) -> Result<Vec<String>, String> {
    let mut active_assets = assets.clone();
    active_assets.ipset_all = assets.ipset_effective.clone();

    if let Ok(args) = parse_flowseal_profile_bat(&active_assets, profile, settings) {
        return Ok(args);
    }

    if !matches!(
        profile,
        ZapretProfile::General | ZapretProfile::Alt | ZapretProfile::Alt2
    ) {
        return Err(format!(
            "{} requires Flowseal BAT profile {}, but it was not extracted. Refresh zapret components first.",
            profile.label(),
            profile.bat_file_name()
        ));
    }

    let (game_tcp, game_udp) = game_filter_ports(settings.zapret.game_filter);
    let common_tcp = format!("80,443,2053,2083,2087,2096,8443,{game_tcp}");
    let common_udp = format!("443,19294-19344,50000-50100,{game_udp}");
    let mut args = vec![
        format!("--wf-tcp={common_tcp}"),
        format!("--wf-udp={common_udp}"),
        "--wf-l3=ipv4,ipv6".to_string(),
        "--wf-filter-lan=1".to_string(),
    ];

    push_common_udp_hostlist_filter(&mut args, &active_assets);
    args.push("--new".to_string());
    args.extend([
        "--filter-udp=19294-19344,50000-50100".to_string(),
        "--filter-l7=discord,stun".to_string(),
        "--dpi-desync=fake".to_string(),
        "--dpi-desync-repeats=6".to_string(),
        "--new".to_string(),
    ]);

    match profile {
        ZapretProfile::General => {
            push_general_multisplit_filters(&mut args, &active_assets, game_tcp, game_udp)
        }
        ZapretProfile::Alt => {
            push_alt_fakedsplit_filters(&mut args, &active_assets, game_tcp, game_udp)
        }
        ZapretProfile::Alt2 => {
            push_alt2_multisplit_filters(&mut args, &active_assets, game_tcp, game_udp)
        }
        _ => {}
    }

    Ok(args)
}

fn game_filter_ports(mode: ZapretGameFilter) -> (&'static str, &'static str) {
    match mode {
        ZapretGameFilter::Off => ("12", "12"),
        ZapretGameFilter::TcpUdp => ("1024-65535", "1024-65535"),
        ZapretGameFilter::Tcp => ("1024-65535", "12"),
        ZapretGameFilter::Udp => ("12", "1024-65535"),
    }
}

fn parse_flowseal_profile_bat(
    assets: &FlowsealZapretAssets,
    profile: ZapretProfile,
    settings: &AppSettings,
) -> Result<Vec<String>, String> {
    let path = flowseal_profile_bat_path(assets, profile.bat_file_name());
    let content = fs::read_to_string(&path).map_err(|error| {
        format!(
            "Failed to read Flowseal profile {}: {error}",
            path.display()
        )
    })?;
    let command_line = extract_winws_command_from_bat(&content)
        .ok_or_else(|| format!("{} does not contain a winws.exe command.", path.display()))?;
    let (game_tcp, game_udp) = game_filter_ports(settings.zapret.game_filter);
    let mut args = command_line;
    args = replace_case_insensitive(&args, "%GameFilterTCP%", game_tcp);
    args = replace_case_insensitive(&args, "%GameFilterUDP%", game_udp);
    args = replace_case_insensitive(
        &args,
        "%GameFilter%",
        max_game_filter_port(game_tcp, game_udp),
    );
    args = replace_case_insensitive(&args, "%BIN%", &format!("{}\\", assets.bin_dir.display()));
    args = replace_case_insensitive(
        &args,
        "%LISTS%",
        &format!("{}\\", zapret_lists_dir()?.display()),
    );
    args = replace_case_insensitive(
        &args,
        "%~dp0bin\\",
        &format!("{}\\", assets.bin_dir.display()),
    );
    args = replace_case_insensitive(
        &args,
        "%~dp0lists\\",
        &format!("{}\\", zapret_lists_dir()?.display()),
    );
    args = replace_case_insensitive(&args, "%~dp0", &format!("{}\\", assets.root_dir.display()));
    let mut parsed = split_windows_command_line(&args)?;
    rewrite_ipset_all_args(&mut parsed, &assets.ipset_all);
    append_winws_filter_safety_args(&mut parsed);
    if parsed.is_empty() {
        return Err(format!("{} generated no winws arguments.", profile.label()));
    }
    Ok(parsed)
}

fn flowseal_profile_bat_path(assets: &FlowsealZapretAssets, file_name: &str) -> PathBuf {
    let root_profile = assets.root_dir.join(file_name);
    if root_profile.exists() {
        root_profile
    } else {
        assets.profiles_dir.join(file_name)
    }
}

fn rewrite_ipset_all_args(args: &mut [String], effective_ipset: &Path) {
    for arg in args {
        let Some(value) = arg.strip_prefix("--ipset=") else {
            continue;
        };
        let normalized = value.trim_matches('"').replace('\\', "/");
        if normalized.ends_with("/ipset-all.txt") || normalized == "ipset-all.txt" {
            *arg = ipset_arg(effective_ipset);
        }
    }
}

fn append_winws_filter_safety_args(args: &mut Vec<String>) {
    if !args.iter().any(|arg| arg.starts_with("--wf-filter-lan")) {
        args.push("--wf-filter-lan=1".to_string());
    }
    if !args.iter().any(|arg| arg.starts_with("--wf-l3")) {
        args.push("--wf-l3=ipv4,ipv6".to_string());
    }
}

fn extract_winws_command_from_bat(content: &str) -> Option<String> {
    let mut captured = Vec::new();
    let mut active = false;
    for raw in content.lines() {
        let mut line = raw.trim().to_string();
        if line.is_empty()
            || line.starts_with("::")
            || line.to_ascii_lowercase().starts_with("rem ")
        {
            continue;
        }
        let has_winws = line.to_ascii_lowercase().contains("winws.exe");
        if has_winws {
            active = true;
            if let Some(index) = line.to_ascii_lowercase().find("winws.exe") {
                line = line[index + "winws.exe".len()..].to_string();
            }
            line = line.trim_start_matches('"').trim().to_string();
        }
        if active {
            let continued = line.ends_with('^');
            if continued {
                line.pop();
            }
            captured.push(line.trim().to_string());
            if !continued {
                break;
            }
        }
    }
    let joined = captured
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.trim().is_empty()).then_some(joined)
}

fn max_game_filter_port(tcp: &str, udp: &str) -> &'static str {
    if tcp == "1024-65535" || udp == "1024-65535" {
        "1024-65535"
    } else {
        "12"
    }
}

fn replace_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    let lower_input = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut out = String::new();
    let mut cursor = 0;
    while let Some(relative) = lower_input[cursor..].find(&lower_needle) {
        let index = cursor + relative;
        out.push_str(&input[cursor..index]);
        out.push_str(replacement);
        cursor = index + needle.len();
    }
    out.push_str(&input[cursor..]);
    out
}

fn split_windows_command_line(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '^' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ch if ch.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if in_quotes {
        return Err("Flowseal BAT command has an unclosed quote.".to_string());
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn push_common_udp_hostlist_filter(args: &mut Vec<String>, assets: &FlowsealZapretAssets) {
    args.extend([
        "--filter-udp=443".to_string(),
        hostlist_arg(&assets.list_general),
        hostlist_arg(&assets.list_general_user),
        hostlist_exclude_arg(&assets.list_exclude),
        hostlist_exclude_arg(&assets.list_exclude_user),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=fake".to_string(),
        "--dpi-desync-repeats=6".to_string(),
        format!("--dpi-desync-fake-quic={}", assets.fake_quic.display()),
    ]);
}

fn push_general_multisplit_filters(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    game_tcp: &str,
    game_udp: &str,
) {
    push_multisplit_domain_filter(
        args,
        "2053,2083,2087,2096,8443",
        "--hostlist-domains=discord.media",
        681,
        1,
        &assets.fake_tls_google,
    );
    args.push("--new".to_string());
    push_multisplit_domain_filter(
        args,
        "443",
        &hostlist_arg(&assets.list_google),
        681,
        1,
        &assets.fake_tls_google,
    );
    args.push("--ip-id=zero".to_string());
    args.push("--new".to_string());
    push_multisplit_hostlist_filter(args, assets, "80,443", 568, 1, &assets.fake_tls_4pda);
    args.push("--new".to_string());
    push_ipset_udp_filter(args, assets, "443", 6, "n2");
    args.push("--new".to_string());
    push_multisplit_ipset_filter(
        args,
        assets,
        "80,443,8443",
        568,
        1,
        &assets.fake_tls_4pda,
        None,
    );
    args.push("--new".to_string());
    push_multisplit_ipset_filter(
        args,
        assets,
        game_tcp,
        568,
        1,
        &assets.fake_tls_4pda,
        Some("n3"),
    );
    args.push("--new".to_string());
    push_ipset_game_udp_filter(args, assets, game_udp, 12, "n2");
}

fn push_alt2_multisplit_filters(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    game_tcp: &str,
    game_udp: &str,
) {
    push_multisplit_domain_filter(
        args,
        "2053,2083,2087,2096,8443",
        "--hostlist-domains=discord.media",
        652,
        2,
        &assets.fake_tls_google,
    );
    args.push("--new".to_string());
    push_multisplit_domain_filter(
        args,
        "443",
        &hostlist_arg(&assets.list_google),
        652,
        2,
        &assets.fake_tls_google,
    );
    args.push("--ip-id=zero".to_string());
    args.push("--new".to_string());
    push_multisplit_hostlist_filter(args, assets, "80,443", 652, 2, &assets.fake_tls_google);
    args.push("--new".to_string());
    push_ipset_udp_filter(args, assets, "443", 6, "n2");
    args.push("--new".to_string());
    push_multisplit_ipset_filter(
        args,
        assets,
        "80,443,8443",
        652,
        2,
        &assets.fake_tls_google,
        None,
    );
    args.push("--new".to_string());
    push_multisplit_ipset_filter(
        args,
        assets,
        game_tcp,
        652,
        2,
        &assets.fake_tls_google,
        Some("n3"),
    );
    args.push("--new".to_string());
    push_ipset_game_udp_filter(args, assets, game_udp, 12, "n2");
}

fn push_alt_fakedsplit_filters(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    game_tcp: &str,
    game_udp: &str,
) {
    push_fakedsplit_domain_filter(
        args,
        "2053,2083,2087,2096,8443",
        "--hostlist-domains=discord.media",
        &assets.fake_tls_google,
    );
    args.push("--new".to_string());
    push_fakedsplit_domain_filter(
        args,
        "443",
        &hostlist_arg(&assets.list_google),
        &assets.fake_tls_google,
    );
    args.push("--ip-id=zero".to_string());
    args.push("--new".to_string());
    push_fakedsplit_hostlist_filter(args, assets, "80,443", &assets.fake_tls_google);
    args.push("--new".to_string());
    push_ipset_udp_filter(args, assets, "443", 6, "n3");
    args.push("--new".to_string());
    push_fakedsplit_ipset_filter(args, assets, "80,443,8443", &assets.fake_tls_google, None);
    args.push("--new".to_string());
    push_fakedsplit_ipset_filter(args, assets, game_tcp, &assets.fake_tls_google, Some("n4"));
    args.push("--new".to_string());
    push_ipset_game_udp_filter(args, assets, game_udp, 12, "n3");
}

fn push_multisplit_domain_filter(
    args: &mut Vec<String>,
    ports: &str,
    target_arg: &str,
    seqovl: u16,
    split_pos: u16,
    pattern: &PathBuf,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        target_arg.to_string(),
        format!("--dpi-desync=multisplit"),
        format!("--dpi-desync-split-seqovl={seqovl}"),
        format!("--dpi-desync-split-pos={split_pos}"),
        format!("--dpi-desync-split-seqovl-pattern={}", pattern.display()),
    ]);
}

fn push_multisplit_hostlist_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    seqovl: u16,
    split_pos: u16,
    pattern: &PathBuf,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        hostlist_arg(&assets.list_general),
        hostlist_arg(&assets.list_general_user),
        hostlist_exclude_arg(&assets.list_exclude),
        hostlist_exclude_arg(&assets.list_exclude_user),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=multisplit".to_string(),
        format!("--dpi-desync-split-seqovl={seqovl}"),
        format!("--dpi-desync-split-pos={split_pos}"),
        format!("--dpi-desync-split-seqovl-pattern={}", pattern.display()),
    ]);
}

fn push_multisplit_ipset_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    seqovl: u16,
    split_pos: u16,
    pattern: &PathBuf,
    cutoff: Option<&str>,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        ipset_arg(&assets.ipset_all),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=multisplit".to_string(),
    ]);
    if cutoff.is_some() {
        args.push("--dpi-desync-any-protocol=1".to_string());
    }
    if let Some(cutoff) = cutoff {
        args.push(format!("--dpi-desync-cutoff={cutoff}"));
    }
    args.extend([
        format!("--dpi-desync-split-seqovl={seqovl}"),
        format!("--dpi-desync-split-pos={split_pos}"),
        format!("--dpi-desync-split-seqovl-pattern={}", pattern.display()),
    ]);
}

fn push_fakedsplit_domain_filter(
    args: &mut Vec<String>,
    ports: &str,
    target_arg: &str,
    fake_tls: &PathBuf,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        target_arg.to_string(),
        "--dpi-desync=fake,fakedsplit".to_string(),
        "--dpi-desync-repeats=6".to_string(),
        "--dpi-desync-fooling=ts".to_string(),
        "--dpi-desync-fakedsplit-pattern=0x00".to_string(),
        format!("--dpi-desync-fake-tls={}", fake_tls.display()),
    ]);
}

fn push_fakedsplit_hostlist_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    fake_tls: &PathBuf,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        hostlist_arg(&assets.list_general),
        hostlist_arg(&assets.list_general_user),
        hostlist_exclude_arg(&assets.list_exclude),
        hostlist_exclude_arg(&assets.list_exclude_user),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=fake,fakedsplit".to_string(),
        "--dpi-desync-repeats=6".to_string(),
        "--dpi-desync-fooling=ts".to_string(),
        "--dpi-desync-fakedsplit-pattern=0x00".to_string(),
        format!("--dpi-desync-fake-tls={}", fake_tls.display()),
    ]);
}

fn push_fakedsplit_ipset_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    fake_tls: &PathBuf,
    cutoff: Option<&str>,
) {
    args.extend([
        format!("--filter-tcp={ports}"),
        ipset_arg(&assets.ipset_all),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=fake,fakedsplit".to_string(),
        "--dpi-desync-repeats=6".to_string(),
    ]);
    if cutoff.is_some() {
        args.push("--dpi-desync-any-protocol=1".to_string());
    }
    if let Some(cutoff) = cutoff {
        args.push(format!("--dpi-desync-cutoff={cutoff}"));
    }
    args.extend([
        "--dpi-desync-fooling=ts".to_string(),
        "--dpi-desync-fakedsplit-pattern=0x00".to_string(),
        format!("--dpi-desync-fake-tls={}", fake_tls.display()),
    ]);
}

fn push_ipset_udp_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    repeats: u8,
    _cutoff: &str,
) {
    args.extend([
        format!("--filter-udp={ports}"),
        ipset_arg(&assets.ipset_all),
        hostlist_exclude_arg(&assets.list_exclude),
        hostlist_exclude_arg(&assets.list_exclude_user),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=fake".to_string(),
        format!("--dpi-desync-repeats={repeats}"),
        format!("--dpi-desync-fake-quic={}", assets.fake_quic.display()),
    ]);
}

fn push_ipset_game_udp_filter(
    args: &mut Vec<String>,
    assets: &FlowsealZapretAssets,
    ports: &str,
    repeats: u8,
    cutoff: &str,
) {
    args.extend([
        format!("--filter-udp={ports}"),
        ipset_arg(&assets.ipset_all),
        ipset_exclude_arg(&assets.ipset_exclude),
        ipset_exclude_arg(&assets.ipset_exclude_user),
        "--dpi-desync=fake".to_string(),
        format!("--dpi-desync-repeats={repeats}"),
        "--dpi-desync-any-protocol=1".to_string(),
        format!(
            "--dpi-desync-fake-unknown-udp={}",
            assets.fake_quic.display()
        ),
        format!("--dpi-desync-cutoff={cutoff}"),
    ]);
}

fn hostlist_arg(path: &PathBuf) -> String {
    format!("--hostlist={}", path.display())
}

fn hostlist_exclude_arg(path: &PathBuf) -> String {
    format!("--hostlist-exclude={}", path.display())
}

fn ipset_arg(path: &Path) -> String {
    format!("--ipset={}", path.display())
}

fn ipset_exclude_arg(path: &PathBuf) -> String {
    format!("--ipset-exclude={}", path.display())
}

fn install_component_with_backup<F>(component: &str, install: F) -> Result<(), String>
where
    F: FnOnce(Option<PathBuf>) -> Result<(), String>,
{
    let backup = backup_component_dir(component)?;
    install(backup.clone())?;
    if let Some(path) = backup {
        if let Err(error) = retire_path_to_del(&path) {
            log_event(
                "components",
                format!(
                    "component backup quarantine failed for {}: {error}",
                    redact_path(&path)
                ),
            );
        }
    }
    Ok(())
}

fn restore_component_backup_on_error(
    component: &str,
    backup: Option<PathBuf>,
    result: Result<(), String>,
) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Some(backup) = backup {
                let target = component_dir(component)?;
                if let Err(retire_error) = retire_path_to_del(&target) {
                    log_event(
                        "components",
                        format!(
                            "failed component quarantine before rollback for {}: {retire_error}",
                            redact_path(&target)
                        ),
                    );
                }
                let _ = fs::rename(&backup, &target);
            }
            Err(error)
        }
    }
}

fn backup_component_dir(component: &str) -> Result<Option<PathBuf>, String> {
    let target = component_dir(component)?;
    if !target.exists() {
        return Ok(None);
    }
    let backup = target.with_file_name(format!(
        "{}.backup.{}",
        target
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(component),
        current_unix_timestamp()
    ));
    if backup.exists() {
        fs::remove_dir_all(&backup).map_err(|error| {
            format!("Failed to remove old backup {}: {error}", backup.display())
        })?;
    }
    fs::rename(&target, &backup).map_err(|error| {
        format!(
            "Failed to create backup for component {component}. Stop running processes and retry: {error}"
        )
    })?;
    Ok(Some(backup))
}

fn retire_path_to_del(path: &Path) -> Result<Option<PathBuf>, String> {
    retire_path_to_del_at(path, current_unix_timestamp())
}

fn retire_path_to_del_at(path: &Path, timestamp: u64) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("Cannot retire path without parent: {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("Cannot retire path with invalid name: {}", path.display()))?;
    for attempt in 0..100u8 {
        let suffix = if attempt == 0 {
            format!(".del.{timestamp}")
        } else {
            format!(".del.{timestamp}.{attempt}")
        };
        let retired = parent.join(format!("{name}{suffix}"));
        if retired.exists() {
            continue;
        }
        fs::rename(path, &retired).map_err(|error| {
            format!(
                "Failed to quarantine retired path {} to {}: {error}",
                path.display(),
                retired.display()
            )
        })?;
        return Ok(Some(retired));
    }
    Err(format!(
        "Failed to choose quarantine path for {} after repeated collisions.",
        path.display()
    ))
}

fn component_dir(component: &str) -> Result<PathBuf, String> {
    Ok(data_dir()?.join("components").join(component))
}

fn programdata_component_dir(component: &str) -> Result<PathBuf, String> {
    Ok(programdata_dir()?.join("components").join(component))
}

fn programdata_mihomo_bin() -> Result<PathBuf, String> {
    Ok(programdata_component_dir("mihomo")?.join("mihomo.exe"))
}

fn programdata_flowseal_zapret_assets() -> Result<FlowsealZapretAssets, String> {
    let root_dir = programdata_component_dir("zapret")?;
    let bin_dir = root_dir.join("bin");
    let profiles_dir = root_dir.join("profiles");
    let lists_dir = root_dir.join("lists");
    Ok(FlowsealZapretAssets {
        root_dir,
        bin_dir: bin_dir.clone(),
        profiles_dir,
        list_general: lists_dir.join("list-general.txt"),
        list_general_user: lists_dir.join("list-general-user.txt"),
        list_google: lists_dir.join("list-google.txt"),
        list_exclude: lists_dir.join("list-exclude.txt"),
        list_exclude_user: lists_dir.join("list-exclude-user.txt"),
        ipset_all: lists_dir.join("ipset-all.txt"),
        ipset_effective: lists_dir.join("ipset-all.effective.txt"),
        ipset_exclude: lists_dir.join("ipset-exclude.txt"),
        ipset_exclude_user: lists_dir.join("ipset-exclude-user.txt"),
        fake_quic: bin_dir.join("quic_initial_www_google_com.bin"),
        fake_tls_google: bin_dir.join("tls_clienthello_www_google_com.bin"),
        fake_tls_4pda: bin_dir.join("tls_clienthello_4pda_to.bin"),
    })
}

fn extract_mihomo_zip(bytes: &[u8]) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("Failed to open Mihomo zip: {error}"))?;
    let out_dir = data_dir()?.join("components").join("mihomo");
    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("Failed to create Mihomo component directory: {error}"))?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("Failed to read Mihomo zip entry: {error}"))?;
        let name = file.name().replace('\\', "/");
        if name.ends_with(".exe") {
            let out_path = out_dir.join("mihomo.exe");
            let mut out = fs::File::create(&out_path)
                .map_err(|error| format!("Failed to create {}: {error}", out_path.display()))?;
            std::io::copy(&mut file, &mut out)
                .map_err(|error| format!("Failed to extract Mihomo: {error}"))?;
            return Ok(());
        }
    }

    Err("Mihomo zip did not contain an exe file.".to_string())
}

fn extract_zapret_zip(bytes: &[u8]) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("Failed to open zapret zip: {error}"))?;
    let component_dir = data_dir()?.join("components").join("zapret");
    fs::create_dir_all(&component_dir)
        .map_err(|error| format!("Failed to create zapret component directory: {error}"))?;

    let mut extracted_winws = false;
    let mut extracted_profiles = 0_usize;
    let mut extracted_files = 0_usize;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("Failed to read zapret zip entry: {error}"))?;
        if file.is_dir() {
            continue;
        }
        let Some(enclosed) = file.enclosed_name() else {
            continue;
        };
        let relative_path = strip_flowseal_archive_root(&enclosed);
        if relative_path.as_os_str().is_empty() {
            continue;
        }
        let file_name = relative_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if file_name.is_empty() {
            continue;
        }
        let out_path = component_dir.join(&relative_path);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
        }
        let mut out = fs::File::create(&out_path)
            .map_err(|error| format!("Failed to create {}: {error}", out_path.display()))?;
        std::io::copy(&mut file, &mut out)
            .map_err(|error| format!("Failed to extract zapret file {file_name}: {error}"))?;
        extracted_files += 1;
        let lower_file_name = file_name.to_ascii_lowercase();
        if lower_file_name == "winws.exe" {
            extracted_winws = true;
        }
        if lower_file_name.ends_with(".bat") && !lower_file_name.starts_with("service") {
            extracted_profiles += 1;
        }
    }

    let missing_profiles = missing_zapret_profile_names(&flowseal_zapret_assets()?);
    if extracted_winws && missing_profiles.is_empty() {
        log_event(
            "components",
            format!(
                "zapret bundle mirrored; files={extracted_files} profiles={extracted_profiles}"
            ),
        );
        Ok(())
    } else if extracted_winws {
        Err(format!(
            "zapret zip did not contain required Flowseal BAT profiles: {}",
            missing_profiles.join(", ")
        ))
    } else {
        Err("zapret zip did not contain winws.exe.".to_string())
    }
}

fn strip_flowseal_archive_root(path: &Path) -> PathBuf {
    let parts = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let skip = if parts.len() > 1 {
        let first = parts[0].to_string_lossy().to_ascii_lowercase();
        !matches!(first.as_str(), "bin" | "lists" | "utils")
            && !first.ends_with(".bat")
            && !first.ends_with(".txt")
            && !first.ends_with(".exe")
            && !first.ends_with(".dll")
            && !first.ends_with(".sys")
    } else {
        false
    } as usize;

    let mut out = PathBuf::new();
    for part in parts.into_iter().skip(skip) {
        out.push(part);
    }
    out
}

fn stop_child(lock: &Mutex<Option<Child>>) -> Result<(), String> {
    let mut child = lock
        .lock()
        .map_err(|_| "process lock is poisoned".to_string())?;
    if let Some(mut running) = child.take() {
        let _ = running.kill();
        let _ = running.wait();
    }
    Ok(())
}

fn mihomo_pid_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("mihomo").join("mihomo.pid"))
}

fn write_mihomo_pid_file(pid: u32) -> Result<(), String> {
    let path = mihomo_pid_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create Mihomo pid directory: {error}"))?;
    }
    fs::write(&path, pid.to_string()).map_err(|error| {
        format!(
            "Failed to write Mihomo pid file {}: {error}",
            path.display()
        )
    })
}

fn read_mihomo_pid_file() -> Option<u32> {
    fs::read_to_string(mihomo_pid_path().ok()?)
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn clear_mihomo_pid_file() {
    if let Ok(path) = mihomo_pid_path() {
        let _ = fs::remove_file(path);
    }
}

fn stop_recorded_mihomo_pid() -> Result<(), String> {
    let Some(pid) = read_mihomo_pid_file() else {
        return Ok(());
    };
    if let Err(error) = stop_windows_process_if_named(pid, "mihomo.exe") {
        log_event(
            "mihomo",
            format!("recorded pid cleanup skipped/failed for {pid}: {error}"),
        );
    }
    clear_mihomo_pid_file();
    Ok(())
}

fn recorded_mihomo_is_running() -> bool {
    let Some(pid) = read_mihomo_pid_file() else {
        return false;
    };
    windows_process_is_named(pid, "mihomo.exe")
}

fn windows_process_is_named(pid: u32, expected_name: &str) -> bool {
    #[cfg(not(windows))]
    {
        let _ = pid;
        let _ = expected_name;
        false
    }

    #[cfg(windows)]
    {
        let script = format!(
            r#"$p = Get-CimInstance Win32_Process -Filter "ProcessId = {pid}" -ErrorAction SilentlyContinue
if ($null -ne $p -and $p.Name.ToLowerInvariant() -eq '{expected}') {{ '1' }} else {{ '0' }}"#,
            expected = powershell_single_quote(&expected_name.to_ascii_lowercase())
        );
        let mut command = Command::new("powershell");
        command.args(["-NoProfile", "-Command", &script]);
        hide_process_window(&mut command);
        command.output().ok().is_some_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "1"
        })
    }
}

fn stop_windows_process_if_named(pid: u32, expected_name: &str) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = pid;
        let _ = expected_name;
        Ok(())
    }

    #[cfg(windows)]
    {
        let script = format!(
            r#"
$ErrorActionPreference = 'Continue'
try {{
  $p = Get-CimInstance Win32_Process -Filter "ProcessId = {pid}" -ErrorAction SilentlyContinue
  if ($null -eq $p) {{ exit 0 }}
  if ($p.Name.ToLowerInvariant() -eq '{expected}') {{
    Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }}
  exit 0
}} catch {{
  Write-Output $_.Exception.Message
  exit 0
}}
"#,
            expected = powershell_single_quote(&expected_name.to_ascii_lowercase())
        );
        let mut command = Command::new("powershell");
        command.args(["-NoProfile", "-Command", &script]);
        hide_process_window(&mut command);
        let output = command
            .output()
            .map_err(|error| format!("Failed to stop recorded Mihomo pid {pid}: {error}"))?;
        if !output.status.success() {
            log_event(
                "mihomo",
                format!(
                    "best-effort pid cleanup command exited with {} stdout={} stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            );
        }
        Ok(())
    }
}

fn prepare_background_process(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_process_window(command);
}

fn hide_process_window(command: &mut Command) {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

fn external_runtime_hint() -> Option<String> {
    let mut hints = Vec::new();
    let own_mihomo =
        child_is_running(mihomo_process()).unwrap_or(false) || recorded_mihomo_is_running();

    if !own_mihomo && has_windows_process(&["mihomo.exe", "clash-meta.exe"]) {
        hints.push("external Mihomo/Clash process is already running".to_string());
    }
    if has_windows_process(&["winws.exe", "goodbyedpi.exe"]) {
        hints.push("external zapret/GoodbyeDPI process is already running".to_string());
    }
    if !own_mihomo {
        if let Some(ports) = occupied_mihomo_ports() {
            hints.push(format!("Mihomo ports are already occupied: {ports}"));
        }
    }

    if hints.is_empty() {
        None
    } else {
        Some(format!(
            "{}. BadVpn can open normally, but connection may fail until the other VPN/DPI tool is stopped or ports are changed.",
            hints.join("; ")
        ))
    }
}

fn occupied_mihomo_ports_hint() -> Option<String> {
    occupied_mihomo_ports().map(|ports| {
        format!(
            "Mihomo cannot start because ports {ports} are already occupied. Stop the other VPN/Mihomo client or change BadVpn ports."
        )
    })
}

fn occupied_mihomo_ports() -> Option<String> {
    let settings = load_app_settings();
    occupied_mihomo_ports_for_ports(&[settings.core.mixed_port, settings.core.controller_port])
}

fn occupied_mihomo_ports_for_ports(ports: &[u16]) -> Option<String> {
    #[cfg(not(windows))]
    {
        let _ = ports;
        None
    }

    #[cfg(windows)]
    {
        let mut command = Command::new("netstat");
        command.args(["-ano", "-p", "tcp"]);
        hide_process_window(&mut command);
        let output = command.output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut occupied = Vec::new();
        for port in ports.iter().copied() {
            let marker = format!(":{port}");
            if stdout.lines().any(|line| {
                line.contains(&marker)
                    && (line.contains("LISTENING") || line.contains("ESTABLISHED"))
            }) {
                occupied.push(port.to_string());
            }
        }

        if occupied.is_empty() {
            None
        } else {
            Some(occupied.join(", "))
        }
    }
}

fn has_windows_process(names: &[&str]) -> bool {
    #[cfg(not(windows))]
    {
        let _ = names;
        false
    }

    #[cfg(windows)]
    {
        let mut command = Command::new("tasklist");
        hide_process_window(&mut command);
        let output = command.output();
        let Ok(output) = output else {
            return false;
        };
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        names
            .iter()
            .any(|name| stdout.contains(&name.to_ascii_lowercase()))
    }
}

async fn ensure_zapret_runtime_lists() -> Result<(), String> {
    write_zapret_lists()?;
    refresh_flowseal_lists(false).await?;
    apply_ipset_filter_mode(&load_app_settings())
}

async fn ensure_zapret_runtime_lists_force() -> Result<(), String> {
    write_zapret_lists()?;
    refresh_flowseal_lists(true).await?;
    apply_ipset_filter_mode(&load_app_settings())
}

fn zapret_runtime_assets_ready() -> Result<(), String> {
    let assets = flowseal_zapret_assets()?;
    zapret_runtime_assets_ready_for_assets(&assets)
}

fn programdata_zapret_runtime_assets_ready() -> Result<(), String> {
    let assets = programdata_flowseal_zapret_assets()?;
    zapret_runtime_assets_ready_for_assets(&assets)
}

fn zapret_runtime_assets_ready_for_assets(assets: &FlowsealZapretAssets) -> Result<(), String> {
    let required = [
        assets.bin_dir.join("winws.exe"),
        assets.bin_dir.join("WinDivert.dll"),
        assets.bin_dir.join("WinDivert64.sys"),
        assets.bin_dir.join("cygwin1.dll"),
        assets.fake_quic.clone(),
        assets.fake_tls_google.clone(),
    ];

    let missing = required
        .iter()
        .filter(|path| !path.exists())
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        let missing_profiles = missing_zapret_profile_names(&assets);
        if missing_profiles.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Missing Flowseal BAT profiles: {}",
                missing_profiles.join(", ")
            ))
        }
    } else {
        Err(format!(
            "Missing zapret runtime assets: {}",
            missing.join(", ")
        ))
    }
}

fn missing_zapret_profile_names(assets: &FlowsealZapretAssets) -> Vec<String> {
    ZapretProfile::all()
        .iter()
        .map(|profile| profile.bat_file_name())
        .filter(|file_name| !flowseal_profile_bat_path(assets, file_name).exists())
        .map(ToOwned::to_owned)
        .collect()
}

async fn refresh_flowseal_lists(force: bool) -> Result<(), String> {
    let assets = flowseal_zapret_assets()?;
    let client = reqwest::Client::builder()
        .user_agent("BadVpn/0.1.0")
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|error| format!("Failed to create Flowseal list HTTP client: {error}"))?;

    let sources = [
        (FLOWSEAL_LIST_GENERAL_URL, assets.list_general, 10_usize),
        (FLOWSEAL_LIST_GOOGLE_URL, assets.list_google, 5_usize),
        (FLOWSEAL_LIST_EXCLUDE_URL, assets.list_exclude, 10_usize),
        (FLOWSEAL_IPSET_EXCLUDE_URL, assets.ipset_exclude, 5_usize),
        (FLOWSEAL_IPSET_URL, assets.ipset_all, 10_usize),
    ];

    let mut errors = Vec::new();
    for (url, path, min_lines) in sources {
        if !force && !should_refresh_flowseal_list(&path) {
            continue;
        }
        if let Err(error) = download_flowseal_list(&client, url, &path, min_lines).await {
            errors.push(error);
        }
    }

    if errors.is_empty() {
        write_flowseal_version_stamp(&client).await.ok();
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn download_flowseal_list(
    client: &reqwest::Client,
    url: &str,
    path: &PathBuf,
    min_lines: usize,
) -> Result<(), String> {
    let body = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("Failed to download {url}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Flowseal endpoint returned an error for {url}: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Failed to read Flowseal list {url}: {error}"))?;
    let normalized = normalize_list_body(&body);
    if normalized.lines().count() < min_lines {
        return Err(format!(
            "Downloaded Flowseal list {url} is unexpectedly small."
        ));
    }
    fs::write(path, normalized)
        .map_err(|error| format!("Failed to write Flowseal list {}: {error}", path.display()))
}

async fn write_flowseal_version_stamp(client: &reqwest::Client) -> Result<(), String> {
    let version = client
        .get(FLOWSEAL_VERSION_URL)
        .send()
        .await
        .map_err(|error| format!("Failed to download Flowseal version: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Flowseal version endpoint returned an error: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Failed to read Flowseal version: {error}"))?;
    let path = zapret_lists_dir()?.join("flowseal-version.txt");
    fs::write(path, normalize_list_body(&version))
        .map_err(|error| format!("Failed to write Flowseal version stamp: {error}"))
}

fn should_refresh_flowseal_list(path: &PathBuf) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return true;
    };
    if metadata.len() < 1024 {
        return true;
    }
    let Ok(modified) = metadata.modified() else {
        return true;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age.as_secs() > FLOWSEAL_IPSET_MAX_AGE_SECONDS
}

fn write_zapret_lists() -> Result<(), String> {
    let dir = zapret_lists_dir()?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create zapret list directory: {error}"))?;

    write_list_file(
        dir.join("list-general.txt"),
        &flowseal_general_hostlist(),
        true,
    )?;
    write_list_file(
        dir.join("list-google.txt"),
        &flowseal_google_hostlist(),
        true,
    )?;
    write_list_file(
        dir.join("list-exclude.txt"),
        &flowseal_exclude_hostlist(),
        true,
    )?;
    write_list_file(
        dir.join("ipset-exclude.txt"),
        &flowseal_ipset_exclude(),
        true,
    )?;
    write_list_file(
        dir.join("list-general-user.txt"),
        &zapret_user_placeholder_hostlist(),
        false,
    )?;
    write_list_file(
        dir.join("list-exclude-user.txt"),
        &zapret_user_placeholder_hostlist(),
        false,
    )?;
    write_list_file(
        dir.join("ipset-exclude-user.txt"),
        &zapret_default_ipset(),
        false,
    )?;
    write_list_file(dir.join("ipset-all.txt"), &zapret_default_ipset(), false)?;
    apply_ipset_filter_mode(&load_app_settings())
}

fn apply_ipset_filter_mode(settings: &AppSettings) -> Result<(), String> {
    let assets = flowseal_zapret_assets()?;
    if let Some(parent) = assets.ipset_effective.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create zapret list directory: {error}"))?;
    }
    match settings.zapret.ipset_filter {
        ZapretIpSetFilter::None => fs::write(&assets.ipset_effective, "203.0.113.113/32\n")
            .map_err(|error| {
                format!(
                    "Failed to switch IPSet filter to none at {}: {error}",
                    assets.ipset_effective.display()
                )
            }),
        ZapretIpSetFilter::Any => fs::write(&assets.ipset_effective, "").map_err(|error| {
            format!(
                "Failed to switch IPSet filter to any at {}: {error}",
                assets.ipset_effective.display()
            )
        }),
        ZapretIpSetFilter::Loaded => {
            if assets.ipset_all.exists() {
                fs::copy(&assets.ipset_all, &assets.ipset_effective)
                    .map(|_| ())
                    .map_err(|error| {
                        format!(
                            "Failed to stage loaded IPSet filter from {} to {}: {error}",
                            assets.ipset_all.display(),
                            assets.ipset_effective.display()
                        )
                    })
            } else {
                fs::write(&assets.ipset_effective, "203.0.113.113/32\n").map_err(|error| {
                    format!(
                        "Failed to create fallback IPSet filter at {}: {error}",
                        assets.ipset_effective.display()
                    )
                })
            }
        }
    }
}

fn write_list_file(path: PathBuf, values: &[&str], overwrite: bool) -> Result<(), String> {
    if !overwrite && path.exists() {
        return Ok(());
    }
    fs::write(&path, normalize_list_body(&values.join("\n")))
        .map_err(|error| format!("Failed to write zapret list {}: {error}", path.display()))
}

fn normalize_list_body(body: &str) -> String {
    let mut normalized = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    normalized.push('\n');
    normalized
}

fn resolve_mihomo_bin() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BADVPN_MIHOMO_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let path = data_dir()?
        .join("components")
        .join("mihomo")
        .join("mihomo.exe");
    if path.exists() {
        return Ok(path);
    }

    Err(format!(
        "Mihomo binary was not found. Put mihomo.exe into {} or set BADVPN_MIHOMO_BIN.",
        path.display()
    ))
}

fn resolve_winws_bin() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BADVPN_WINWS_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let path = data_dir()?
        .join("components")
        .join("zapret")
        .join("bin")
        .join("winws.exe");
    if path.exists() {
        return Ok(path);
    }

    Err(format!(
        "zapret/winws binary was not found. Put winws.exe into {} or set BADVPN_WINWS_BIN.",
        path.display()
    ))
}

fn mihomo_config_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("mihomo").join("config.yaml"))
}

fn agent_mihomo_config_path() -> Option<PathBuf> {
    std::env::var("PROGRAMDATA").ok().map(|path| {
        PathBuf::from(path)
            .join("BadVpn")
            .join("mihomo")
            .join("config.yaml")
    })
}

fn active_mihomo_config_path() -> Result<PathBuf, String> {
    if should_use_agent_runtime() {
        if let Some(path) = agent_mihomo_config_path().filter(|path| path.exists()) {
            return Ok(path);
        }
    }
    mihomo_config_path()
}

fn zapret_lists_dir() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("zapret").join("lists"))
}

fn zapret_profile_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("zapret").join("profile.txt"))
}

fn settings_file_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("settings.json"))
}

fn subscription_file_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("subscription.json"))
}

fn subscription_profiles_file_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("subscriptions.json"))
}

fn proxy_selections_file_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("proxy-selections.json"))
}

fn app_log_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("logs").join("badvpn.log"))
}

fn hydrate_persisted_state() -> Result<(), String> {
    let config_exists = mihomo_config_path().map_or(false, |path| path.exists());
    let persisted_subscription = active_persisted_subscription_profile()
        .or_else(|| read_persisted_subscription_state())
        .or_else(|| {
            config_exists
                .then(subscription_state_from_existing_config)
                .flatten()
        });

    let mut current = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;

    if current.subscription.url.is_none() {
        if let Some(subscription) = persisted_subscription {
            current.subscription = subscription;
            if matches!(current.phase, AppPhase::Init | AppPhase::Onboarding) {
                current.phase = AppPhase::Ready;
            }
        } else if config_exists && matches!(current.phase, AppPhase::Init | AppPhase::Onboarding) {
            current.phase = AppPhase::Ready;
        }
    }

    if !current.running {
        current.connection.route_mode = detect_mihomo_config_route_mode()
            .unwrap_or_else(|| load_app_settings().effective_route_mode());
    }

    Ok(())
}

fn persist_subscription_state_with_body(
    subscription: &SubscriptionState,
    profile_body: Option<&str>,
) -> Result<(), String> {
    write_legacy_subscription_state(subscription, profile_body)?;
    if let Err(error) = upsert_active_subscription_profile(subscription, None, profile_body) {
        log_event(
            "subscription-profile",
            format!("failed to update profile store from active subscription: {error}"),
        );
    }
    Ok(())
}

fn write_legacy_subscription_state(
    subscription: &SubscriptionState,
    profile_body: Option<&str>,
) -> Result<(), String> {
    let path = subscription_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create subscription state directory: {error}"))?;
    }
    let mut stored_subscription = subscription.clone();
    let protected_url = stored_subscription
        .url
        .take()
        .map(|url| protect_secret(&url))
        .transpose()?;
    let protected_body = profile_body.map(protect_secret).transpose()?;
    let persisted = PersistedSubscriptionState {
        subscription: stored_subscription,
        protected_url,
        protected_body,
    };
    let content = serde_json::to_string_pretty(&persisted)
        .map_err(|error| format!("Failed to serialize subscription state: {error}"))?;
    fs::write(&path, content)
        .map_err(|error| format!("Failed to write subscription state: {error}"))?;
    Ok(())
}

fn clear_legacy_subscription_state() -> Result<(), String> {
    let path = subscription_file_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("Failed to remove legacy subscription state: {error}"))?;
    }
    Ok(())
}

fn read_persisted_subscription_state() -> Option<SubscriptionState> {
    let path = subscription_file_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    match serde_json::from_str::<PersistedSubscriptionState>(&content) {
        Ok(persisted) => {
            let mut subscription = persisted.subscription;
            if subscription.url.is_none() {
                subscription.url = persisted.protected_url.as_deref().and_then(|value| {
                    match unprotect_secret(value) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            log_event("subscription", format!("failed to unprotect URL: {error}"));
                            None
                        }
                    }
                });
            }
            Some(subscription)
        }
        Err(_) => match serde_json::from_str::<SubscriptionState>(&content) {
            Ok(subscription) => Some(subscription),
            Err(error) => {
                log_event(
                    "subscription",
                    format!("ignored corrupt subscription state: {error}"),
                );
                None
            }
        },
    }
}

fn validate_subscription_url(url: &str) -> Result<&str, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("Subscription URL is required.".to_string());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err("Subscription URL must start with http:// or https://.".to_string());
    }
    Ok(trimmed)
}

fn active_persisted_subscription_profile() -> Option<SubscriptionState> {
    let store = read_persisted_subscription_profiles().ok()?;
    let active_id = store.active_id.as_deref()?;
    store
        .profiles
        .into_iter()
        .find(|profile| profile.id == active_id)
        .map(|profile| profile.subscription)
}

fn active_persisted_subscription_profile_body() -> Option<String> {
    let store = read_persisted_subscription_profiles().ok()?;
    let active_id = store.active_id.as_deref()?;
    let profile = store
        .profiles
        .into_iter()
        .find(|profile| profile.id == active_id)?;
    profile
        .protected_body
        .as_deref()
        .and_then(|value| match unprotect_secret(value) {
            Ok(body) => Some(body),
            Err(error) => {
                log_event(
                    "subscription-profile",
                    format!("failed to unprotect cached profile body: {error}"),
                );
                None
            }
        })
}

fn existing_mihomo_config_profile_body() -> Option<String> {
    let path = active_mihomo_config_path().ok()?;
    let body = fs::read_to_string(&path).ok()?;
    let summary = summarize_subscription_body(&body);
    if summary.node_count == 0 {
        return None;
    }
    Some(body)
}

fn merged_subscription_for_ui(
    agent_subscription: SubscriptionState,
    previous_subscription: SubscriptionState,
) -> SubscriptionState {
    let local_subscription = active_persisted_subscription_profile()
        .or_else(|| read_persisted_subscription_state())
        .or_else(|| {
            subscription_is_present(&previous_subscription).then_some(previous_subscription)
        });

    let Some(local_subscription) = local_subscription else {
        return agent_subscription;
    };

    if !subscription_is_present(&agent_subscription) {
        return local_subscription;
    }

    let mut merged = agent_subscription;
    if merged.url.is_none() {
        merged.url = local_subscription.url;
    }
    if merged.profile_title.is_none() {
        merged.profile_title = local_subscription.profile_title;
    }
    if merged.announce.is_none() {
        merged.announce = local_subscription.announce;
    }
    if merged.announce_url.is_none() {
        merged.announce_url = local_subscription.announce_url;
    }
    if merged.support_url.is_none() {
        merged.support_url = local_subscription.support_url;
    }
    if merged.profile_web_page_url.is_none() {
        merged.profile_web_page_url = local_subscription.profile_web_page_url;
    }
    if merged.update_interval_hours.is_none() {
        merged.update_interval_hours = local_subscription.update_interval_hours;
    }
    if merged.node_count == 0 {
        merged.node_count = local_subscription.node_count;
    }
    if matches!(merged.format, SubscriptionFormat::Unknown) {
        merged.format = local_subscription.format;
    }
    if merged.user_info == Default::default() {
        merged.user_info = local_subscription.user_info;
    }
    if merged.is_valid.is_none() {
        merged.is_valid = local_subscription.is_valid;
    }
    if merged.validation_error.is_none() {
        merged.validation_error = local_subscription.validation_error;
    }
    if merged.last_refreshed_at.is_none() {
        merged.last_refreshed_at = local_subscription.last_refreshed_at;
    }
    merged
}

fn read_persisted_subscription_profiles() -> Result<PersistedSubscriptionProfiles, String> {
    let path = subscription_profiles_file_path()?;
    let mut store = if path.exists() {
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read subscription profiles: {error}"))?;
        serde_json::from_str::<PersistedSubscriptionProfiles>(&content)
            .map_err(|error| format!("Failed to parse subscription profiles: {error}"))?
    } else {
        migrate_legacy_subscription_profile()
    };
    hydrate_subscription_profile_urls(&mut store);
    if store.active_id.is_none() {
        store.active_id = store.profiles.first().map(|profile| profile.id.clone());
    }
    if let Some(active_id) = store.active_id.as_deref() {
        if !store.profiles.iter().any(|profile| profile.id == active_id) {
            store.active_id = store.profiles.first().map(|profile| profile.id.clone());
        }
    }
    Ok(store)
}

fn write_persisted_subscription_profiles(
    store: &PersistedSubscriptionProfiles,
) -> Result<(), String> {
    let path = subscription_profiles_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!("Failed to create subscription profiles directory: {error}")
        })?;
    }
    let mut safe_store = store.clone();
    for profile in &mut safe_store.profiles {
        if profile.protected_url.is_none() {
            if let Some(url) = profile.subscription.url.as_deref() {
                profile.protected_url = Some(protect_secret(url)?);
            }
        }
        profile.subscription.url = None;
    }
    let content = serde_json::to_string_pretty(&safe_store)
        .map_err(|error| format!("Failed to serialize subscription profiles: {error}"))?;
    fs::write(&path, content)
        .map_err(|error| format!("Failed to write subscription profiles: {error}"))
}

fn subscription_profiles_backup_snapshot() -> Result<PersistedSubscriptionProfiles, String> {
    let mut store = read_persisted_subscription_profiles()?;
    for profile in &mut store.profiles {
        profile.subscription.url = None;
    }
    Ok(store)
}

fn write_subscription_profiles_backup(
    store: &PersistedSubscriptionProfiles,
    reason: &str,
) -> Result<(), String> {
    let dir = data_dir()?.join("backups");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create backup directory: {error}"))?;
    let mut safe_store = store.clone();
    for profile in &mut safe_store.profiles {
        profile.subscription.url = None;
    }
    let path = dir.join(format!(
        "subscriptions-{reason}-{}.json",
        current_unix_timestamp()
    ));
    let content = serde_json::to_string_pretty(&safe_store)
        .map_err(|error| format!("Failed to serialize subscription backup: {error}"))?;
    fs::write(&path, content).map_err(|error| {
        format!(
            "Failed to write subscription profile backup {}: {error}",
            path.display()
        )
    })
}

fn read_proxy_selections() -> Result<BTreeMap<String, String>, String> {
    let path = proxy_selections_file_path()?;
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str::<BTreeMap<String, String>>(&content)
        .map_err(|error| format!("Failed to parse proxy selections: {error}"))
}

fn persist_proxy_selections(selections: &BTreeMap<String, String>) -> Result<(), String> {
    let path = proxy_selections_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create proxy selection directory: {error}"))?;
    }
    let content = serde_json::to_string_pretty(selections)
        .map_err(|error| format!("Failed to serialize proxy selections: {error}"))?;
    fs::write(path, content).map_err(|error| format!("Failed to write proxy selections: {error}"))
}

fn persist_proxy_selection(group: &str, proxy: &str) -> Result<(), String> {
    if group.trim().is_empty() || proxy.trim().is_empty() {
        return Ok(());
    }
    let mut selections = read_proxy_selections().unwrap_or_default();
    selections.insert(group.trim().to_string(), proxy.trim().to_string());
    persist_proxy_selections(&selections)
}

fn migrate_legacy_subscription_profile() -> PersistedSubscriptionProfiles {
    let Some(subscription) = read_persisted_subscription_state() else {
        return PersistedSubscriptionProfiles::default();
    };
    if !subscription_is_present(&subscription) {
        return PersistedSubscriptionProfiles::default();
    }
    let now = current_unix_timestamp();
    let id = subscription
        .url
        .as_deref()
        .map(|url| subscription_profile_id(url, now))
        .unwrap_or_else(|| format!("local-{now}"));
    PersistedSubscriptionProfiles {
        active_id: Some(id.clone()),
        profiles: vec![PersistedSubscriptionProfile {
            id,
            name: subscription_profile_display_name(None, &subscription, 1),
            description: None,
            protected_url: subscription
                .url
                .as_deref()
                .and_then(|url| protect_secret(url).ok()),
            protected_body: None,
            subscription,
            last_successful_refresh_at: None,
            last_failed_refresh_at: None,
            last_refresh_error: None,
            next_refresh_at: None,
            fetch_options: PersistedSubscriptionFetchOptions::default(),
            created_at: now,
            updated_at: now,
        }],
    }
}

fn hydrate_subscription_profile_urls(store: &mut PersistedSubscriptionProfiles) {
    for profile in &mut store.profiles {
        if profile.subscription.url.is_none() {
            profile.subscription.url =
                profile
                    .protected_url
                    .as_deref()
                    .and_then(|value| match unprotect_secret(value) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            log_event(
                                "subscription-profile",
                                format!("failed to unprotect profile URL: {error}"),
                            );
                            None
                        }
                    });
        }
    }
}

fn upsert_active_subscription_profile(
    subscription: &SubscriptionState,
    name: Option<&str>,
    profile_body: Option<&str>,
) -> Result<(), String> {
    if subscription.url.is_none() && !subscription_is_present(subscription) {
        return Ok(());
    }
    let mut store = read_persisted_subscription_profiles()?;
    let now = current_unix_timestamp();
    let url = subscription.url.as_deref();
    let active_index = store
        .active_id
        .as_deref()
        .and_then(|active_id| {
            store
                .profiles
                .iter()
                .position(|profile| profile.id == active_id)
        })
        .or_else(|| {
            url.and_then(|url| {
                store.profiles.iter().position(|profile| {
                    profile
                        .subscription
                        .url
                        .as_deref()
                        .map(|stored| stored.eq_ignore_ascii_case(url))
                        .unwrap_or(false)
                })
            })
        });

    let display_name =
        subscription_profile_display_name(name, subscription, store.profiles.len() + 1);
    let id = if let Some(index) = active_index {
        let profile = &mut store.profiles[index];
        if name.is_some() || profile.name.trim().is_empty() {
            profile.name = display_name;
        }
        profile.subscription = subscription.clone();
        profile.protected_url = url.map(protect_secret).transpose()?;
        if let Some(profile_body) = profile_body {
            profile.protected_body = Some(protect_secret(profile_body)?);
            profile.last_successful_refresh_at = Some(now);
            profile.last_failed_refresh_at = None;
            profile.last_refresh_error = None;
            profile.next_refresh_at = next_profile_refresh_at(&profile.subscription, now);
        }
        profile.updated_at = now;
        profile.id.clone()
    } else {
        let id = url
            .map(|url| subscription_profile_id(url, now))
            .unwrap_or_else(|| format!("local-{now}"));
        store.profiles.push(PersistedSubscriptionProfile {
            id: id.clone(),
            name: display_name,
            description: None,
            subscription: subscription.clone(),
            protected_url: url.map(protect_secret).transpose()?,
            protected_body: profile_body.map(protect_secret).transpose()?,
            last_successful_refresh_at: profile_body.map(|_| now),
            last_failed_refresh_at: None,
            last_refresh_error: None,
            next_refresh_at: profile_body.and_then(|_| next_profile_refresh_at(&subscription, now)),
            fetch_options: PersistedSubscriptionFetchOptions::default(),
            created_at: now,
            updated_at: now,
        });
        id
    };
    store.active_id = Some(id);
    write_persisted_subscription_profiles(&store)
}

fn mark_active_subscription_profile_refresh_success(
    subscription: &SubscriptionState,
    profile_body: &str,
) -> Result<(), String> {
    let mut store = read_persisted_subscription_profiles()?;
    let now = current_unix_timestamp();
    hydrate_subscription_profile_urls(&mut store);
    let active_index = store
        .active_id
        .as_deref()
        .and_then(|active_id| {
            store
                .profiles
                .iter()
                .position(|profile| profile.id == active_id)
        })
        .or_else(|| {
            subscription.url.as_deref().and_then(|url| {
                store.profiles.iter().position(|profile| {
                    profile
                        .subscription
                        .url
                        .as_deref()
                        .map(|stored| stored.eq_ignore_ascii_case(url))
                        .unwrap_or(false)
                })
            })
        });

    let Some(index) = active_index else {
        return upsert_active_subscription_profile(subscription, None, Some(profile_body));
    };

    let profile = &mut store.profiles[index];
    profile.subscription = subscription.clone();
    profile.protected_url = subscription
        .url
        .as_deref()
        .map(protect_secret)
        .transpose()?;
    profile.protected_body = Some(protect_secret(profile_body)?);
    profile.last_successful_refresh_at = Some(now);
    profile.last_failed_refresh_at = None;
    profile.last_refresh_error = None;
    profile.next_refresh_at = next_profile_refresh_at(subscription, now);
    profile.updated_at = now;
    store.active_id = Some(profile.id.clone());
    write_persisted_subscription_profiles(&store)
}

fn mark_active_subscription_profile_refresh_failure(error: &str) -> Result<(), String> {
    let mut store = read_persisted_subscription_profiles()?;
    mark_active_profile_refresh_failure_in_store(
        &mut store,
        current_unix_timestamp(),
        &redact_sensitive_text(error),
    );
    write_persisted_subscription_profiles(&store)
}

fn mark_active_profile_refresh_failure_in_store(
    store: &mut PersistedSubscriptionProfiles,
    timestamp: u64,
    error: &str,
) {
    let Some(active_id) = store.active_id.as_deref() else {
        return;
    };
    let Some(profile) = store
        .profiles
        .iter_mut()
        .find(|profile| profile.id == active_id)
    else {
        return;
    };
    profile.last_failed_refresh_at = Some(timestamp);
    profile.last_refresh_error = Some(error.to_string());
}

fn next_profile_refresh_at(subscription: &SubscriptionState, refreshed_at: u64) -> Option<u64> {
    subscription
        .update_interval_hours
        .filter(|hours| *hours > 0)
        .and_then(|hours| refreshed_at.checked_add(hours.saturating_mul(60 * 60)))
}

fn subscription_fetch_options_view(
    options: &PersistedSubscriptionFetchOptions,
) -> SubscriptionFetchOptionsView {
    SubscriptionFetchOptionsView {
        timeout_seconds: options.timeout_seconds,
        proxy_mode: options.proxy_mode,
        custom_proxy_redacted: options
            .protected_custom_proxy_url
            .as_deref()
            .and_then(|value| unprotect_secret(value).ok())
            .map(|url| redact_url(&url)),
        user_agent: options.user_agent.clone(),
    }
}

fn build_subscription_profiles_state() -> Result<SubscriptionProfilesState, String> {
    let store = read_persisted_subscription_profiles()?;
    let active_id = store.active_id.clone();
    let profiles = store
        .profiles
        .into_iter()
        .map(|profile| {
            let mut subscription = profile.subscription.clone();
            let redacted_url = subscription.url.as_deref().map(redact_url);
            subscription.url = None;
            SubscriptionProfileView {
                active: active_id.as_deref() == Some(profile.id.as_str()),
                id: profile.id,
                name: profile.name,
                description: profile.description,
                redacted_url,
                subscription,
                last_successful_refresh_at: profile.last_successful_refresh_at,
                last_failed_refresh_at: profile.last_failed_refresh_at,
                last_refresh_error: profile.last_refresh_error,
                next_refresh_at: profile.next_refresh_at,
                fetch_options: subscription_fetch_options_view(&profile.fetch_options),
                created_at: profile.created_at,
                updated_at: profile.updated_at,
            }
        })
        .collect();
    Ok(SubscriptionProfilesState {
        active_id,
        profiles,
    })
}

fn subscription_profile_id(url: &str, timestamp: u64) -> String {
    format!("sub-{}", stable_config_hash(&format!("{timestamp}:{url}")))
}

fn subscription_profile_display_name(
    explicit: Option<&str>,
    subscription: &SubscriptionState,
    fallback_index: usize,
) -> String {
    explicit
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            subscription
                .profile_title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("Profile {fallback_index}"))
}

fn redact_url(url: &str) -> String {
    let trimmed = url.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return "subscription".to_string();
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return format!("{scheme}://<redacted>/...");
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("{scheme}://{host}/...")
}

fn normalize_subscription_profile_description(
    value: Option<String>,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > 1000 {
        return Err("Subscription profile notes are too long.".to_string());
    }
    if value.chars().any(|ch| ch.is_control() && ch != '\t') {
        return Err("Subscription profile notes cannot contain control characters.".to_string());
    }
    Ok(Some(value.to_string()))
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn programdata_staging_uses_verified_tree_swap_with_rollback() {
        let script = stage_runtime_assets_powershell().unwrap();
        let robocopy_lines = script
            .lines()
            .filter(|line| line.trim_start().starts_with("robocopy "))
            .collect::<Vec<_>>();

        assert_eq!(robocopy_lines.len(), 2);
        for line in robocopy_lines {
            assert!(
                line.contains("$staging"),
                "copy must target staging: {line}"
            );
            assert!(!line.contains("$targetComponents"));
            assert!(!line.contains("/XO"));
            assert!(
                line.contains(" /R:2 /W:1 "),
                "retries must be bounded: {line}"
            );
        }
        assert!(script.contains("Get-FileHash"));
        assert!(script.contains("robocopy $sourceLists $stagingLists /MIR"));
        let backup = script
            .find("Move-Item -LiteralPath $targetComponents -Destination $backupComponents")
            .unwrap();
        let promote = script
            .find("Move-Item -LiteralPath $stagingComponents -Destination $targetComponents")
            .unwrap();
        let rollback = script
            .rfind("Move-Item -LiteralPath $backupComponents -Destination $targetComponents")
            .unwrap();
        assert!(backup < promote);
        assert!(promote < rollback);
        assert!(!script.contains("robocopy $sourceComponents $targetComponents"));

        let syntax = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:BADVPN_TEST_SCRIPT,[ref]$tokens,[ref]$errors); if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }",
            ])
            .env("BADVPN_TEST_SCRIPT", &script)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "PowerShell staging script syntax failed: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn agent_install_stops_service_before_staging_and_binary_replacement() {
        let staging_marker = "# runtime-staging-marker";
        let script = render_agent_install_powershell(
            Path::new(r"C:\Users\alice\badvpn-agent.exe"),
            Path::new(r"C:\ProgramData\BadVpn\agent\badvpn-agent.exe"),
            "S-1-5-21-1-2-3-1001",
            staging_marker,
        );

        let stop = script.find("sc.exe stop").unwrap();
        let staging = script.find(staging_marker).unwrap();
        let replace = script.find("Copy-Item -LiteralPath").unwrap();
        assert!(stop < staging, "service must stop before runtime staging");
        assert!(
            staging < replace,
            "staging must finish before agent replacement"
        );
        assert!(script.contains("$invokingUserSid = 'S-1-5-21-1-2-3-1001'"));
        assert!(!script.contains("Win32_ComputerSystem"));
        assert!(
            script.contains("$wasRunning = [bool]($service -and $service.Status -eq 'Running')")
        );
        assert!(script.contains("if ($wasRunning) {"));
        assert!(script.contains("Start-Service -Name 'badvpn-agent' -ErrorAction Stop"));
        assert!(script.contains("if (-not $wasRunning) {"));
        assert!(script.contains("Stop-Service -Name 'badvpn-agent' -ErrorAction Stop"));
        assert!(script.contains("Previously running badvpn-agent could not be restarted"));
        let catch = script.find("} catch {").unwrap();
        let restore_assets = script
            .find("Move-Item -LiteralPath $runtimeAssetsBackup -Destination $runtimeAssetsTarget")
            .unwrap();
        let restart = script.find("Start-Service -Name 'badvpn-agent'").unwrap();
        assert!(catch < restore_assets);
        assert!(restore_assets < restart);

        let syntax = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:BADVPN_TEST_SCRIPT,[ref]$tokens,[ref]$errors); if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }",
            ])
            .env("BADVPN_TEST_SCRIPT", &script)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "PowerShell install script syntax failed: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_client_uses_overlapped_io_with_bounded_cancellation() {
        let source = include_str!("commands.rs");
        let open_pipe = source
            .find("FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED")
            .unwrap();
        let read = source.find("fn read_pipe_line").unwrap();
        let wait = source
            .find("WaitForSingleObject(event, timeout_ms)")
            .unwrap();
        let cancel = source.find("CancelIoEx(handle, &overlapped)").unwrap();
        let complete = source
            .find("GetOverlappedResult(handle, &overlapped, &mut transferred, 1)")
            .unwrap();
        assert!(open_pipe < read);
        assert!(read < wait && wait < cancel && cancel < complete);
        assert!(source.contains("Instant::now() + Duration::from_secs(30)"));
    }

    #[cfg(windows)]
    #[test]
    fn invoking_user_sid_parser_accepts_only_strict_sid_fields() {
        assert_eq!(
            parse_user_sid("\"DESKTOP\\alice\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert!(parse_user_sid("DESKTOP\\alice,S-1-5-21-1-2-3-1001;evil").is_none());
        assert!(parse_user_sid("DESKTOP\\alice,not-a-sid").is_none());
        assert!(parse_user_sid("DESKTOP\\alice,S-1-").is_none());
    }

    #[test]
    fn proxy_selection_validation_rejects_stale_group_and_unknown_member() {
        let mut api = MihomoProxiesResponse::default();
        api.proxies.insert(
            "__BADVPN_VPN_ONLY__".to_string(),
            MihomoProxyState {
                proxy_type: Some("Selector".to_string()),
                members: vec!["Germany".to_string(), "Switzerland".to_string()],
                ..MihomoProxyState::default()
            },
        );

        let stale = validate_proxy_selection(&api, "Выбор сервера", "Germany").unwrap_err();
        assert!(stale.contains("not present in the active Mihomo runtime"));
        let unknown = validate_proxy_selection(&api, "__BADVPN_VPN_ONLY__", "Poland").unwrap_err();
        assert!(unknown.contains("not a member"));
        validate_proxy_selection(&api, "__BADVPN_VPN_ONLY__", "Germany").unwrap();
    }

    #[test]
    fn proxy_selection_path_encoding_preserves_one_unicode_segment() {
        assert_eq!(
            path_encode("Выбор сервера/основной"),
            "%D0%92%D1%8B%D0%B1%D0%BE%D1%80%20%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D0%B0%2F%D0%BE%D1%81%D0%BD%D0%BE%D0%B2%D0%BD%D0%BE%D0%B9"
        );
    }

    #[test]
    fn subscription_url_redaction_keeps_origin_only() {
        let redacted =
            redact_url("https://example.com/sub/token-secret?user=alice&password=hidden");

        assert_eq!(redacted, "https://example.com/...");
        assert!(!redacted.contains("token-secret"));
        assert!(!redacted.contains("password"));
        assert!(!redacted.contains("alice"));
    }

    #[test]
    fn subscription_url_redaction_removes_userinfo_credentials() {
        let redacted = redact_url("https://alice:secret@example.com/sub/token-secret");

        assert_eq!(redacted, "https://example.com/...");
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn invalid_subscription_url_redaction_uses_generic_label() {
        assert_eq!(redact_url("not-a-url-with-token-secret"), "subscription");
    }

    #[test]
    fn proxy_uri_redaction_masks_embedded_credentials() {
        let redacted = redact_sensitive_text(
            "vless://uuid-secret@example.com:443?security=reality\nvmess://eyJhZGQiOiJzZWNyZXQifQ==\ntrojan://password-secret@example.com:443\nss://method:password-secret@example.com:443",
        );

        assert!(redacted.contains("vless://<redacted>/..."));
        assert!(redacted.contains("vmess://<redacted>/..."));
        assert!(redacted.contains("trojan://<redacted>/..."));
        assert!(redacted.contains("ss://<redacted>/..."));
        assert!(!redacted.contains("uuid-secret"));
        assert!(!redacted.contains("password-secret"));
        assert!(!redacted.contains("eyJhZGQi"));
    }

    #[test]
    fn redaction_masks_controller_secret_and_local_credentials() {
        let redacted = redact_sensitive_text(
            "secret: badvpn-controller-secret\npassword: hunter2\nhttps://user:pass@example.com/sub/token?password=hunter2",
        );

        assert!(redacted.contains("secret: <redacted>"));
        assert!(redacted.contains("password: <redacted>"));
        assert!(redacted.contains("https://example.com/..."));
        assert!(!redacted.contains("badvpn-controller-secret"));
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("user:pass"));
    }

    #[test]
    fn provider_links_are_redacted_in_support_text() {
        let redacted = redact_sensitive_text(
            "provider_links=https://panel.example/sub/token-secret?user=alice&password=hidden",
        );

        assert!(redacted.contains("https://panel.example/..."));
        assert!(!redacted.contains("token-secret"));
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("hidden"));
    }

    #[test]
    fn subscription_fetch_options_redact_custom_proxy_credentials() {
        let options = PersistedSubscriptionFetchOptions {
            timeout_seconds: 45,
            proxy_mode: SubscriptionFetchProxyMode::Custom,
            protected_custom_proxy_url: Some(
                protect_secret("http://alice:secret@proxy.example:8080").unwrap(),
            ),
            user_agent: Some("BadVpn-Test/1.0".to_string()),
        };

        let view = subscription_fetch_options_view(&options);

        assert_eq!(view.timeout_seconds, 45);
        assert_eq!(view.proxy_mode, SubscriptionFetchProxyMode::Custom);
        assert_eq!(
            view.custom_proxy_redacted.as_deref(),
            Some("http://proxy.example:8080/...")
        );
        assert_eq!(view.user_agent.as_deref(), Some("BadVpn-Test/1.0"));
    }

    #[test]
    fn custom_subscription_fetch_proxy_validation_is_limited_to_http() {
        assert!(validate_custom_fetch_proxy_url("http://proxy.example:8080").is_ok());
        assert!(validate_custom_fetch_proxy_url("https://proxy.example").is_ok());
        assert!(validate_custom_fetch_proxy_url("socks5://proxy.example:1080").is_err());
        assert!(validate_custom_fetch_proxy_url("https://").is_err());
    }

    #[test]
    fn subscription_fetch_user_agent_validation_rejects_header_controls() {
        assert_eq!(
            normalize_subscription_fetch_user_agent(Some("BadVpn Custom/1.0".to_string()), None)
                .unwrap()
                .as_deref(),
            Some("BadVpn Custom/1.0")
        );
        assert_eq!(
            normalize_subscription_fetch_user_agent(Some("   ".to_string()), Some("Old/1.0"))
                .unwrap(),
            None
        );
        assert!(normalize_subscription_fetch_user_agent(
            Some("BadVpn\r\nInjected: header".to_string()),
            None,
        )
        .is_err());
    }

    #[test]
    fn subscription_profile_description_validation_trims_and_rejects_controls() {
        assert_eq!(
            normalize_subscription_profile_description(Some("  Main gaming profile  ".to_string()))
                .unwrap()
                .as_deref(),
            Some("Main gaming profile")
        );
        assert_eq!(
            normalize_subscription_profile_description(Some("   ".to_string())).unwrap(),
            None
        );
        assert!(
            normalize_subscription_profile_description(Some("bad\nnotes".to_string())).is_err()
        );
    }

    #[test]
    fn local_profile_preview_reports_metadata_without_persisting() {
        let preview = preview_profile_body(
            "Preview",
            Some(Path::new("sanitized-profile.yaml")),
            r#"
proxies:
  - name: Example
    type: vless
"#,
        )
        .unwrap();

        assert_eq!(preview.display_name, "Preview");
        assert_eq!(
            preview.source_file_name.as_deref(),
            Some("sanitized-profile.yaml")
        );
        assert_eq!(preview.format, SubscriptionFormat::ClashYaml);
        assert_eq!(preview.node_count, 1);
        assert!(preview.import_ready);
        assert!(preview.warning.is_none());
    }

    #[test]
    fn failed_resource_activation_preserves_previous_resource() {
        let unique = format!("badvpn-resource-test-{}", current_unix_timestamp());
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        fs::write(&path, "old.example\nkeep.example\n").unwrap();
        let def = OperatorResourceDef {
            id: "test-list",
            label: "Test list",
            kind: "test",
            path: path.clone(),
            source: "test",
            url: Some("https://example.invalid/list.txt"),
            min_lines: 3,
        };

        let error = activate_text_resource_body(&def, "new.example\n").unwrap_err();

        assert!(error.contains("structural verification"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "old.example\nkeep.example\n"
        );
        assert!(newest_resource_backup(&path).is_none());
        assert!(!path.with_extension("next").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn successful_resource_activation_records_verified_digest() {
        let unique = format!("badvpn-resource-success-{}", current_unix_timestamp());
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        fs::write(&path, "old.example\n").unwrap();
        let body = "one.example\ntwo.example\n";
        let def = OperatorResourceDef {
            id: "test-list",
            label: "Test list",
            kind: "test",
            path: path.clone(),
            source: "test",
            url: Some("https://example.invalid/list.txt"),
            min_lines: 2,
        };

        activate_text_resource_body(&def, body).unwrap();

        let expected_digest = stable_config_hash(body);
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
        assert_eq!(
            fs::read_to_string(path.with_extension("hash")).unwrap(),
            expected_digest
        );
        assert_eq!(
            resource_digest_status(&path, body.as_bytes()),
            format!("digest verified: {expected_digest}")
        );
        assert!(newest_resource_backup(&path).is_some());
        assert!(!path.with_extension("next").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_advanced_mihomo_yaml_does_not_replace_last_working_config() {
        let unique = format!("badvpn-mihomo-advanced-test-{}", current_unix_timestamp());
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        fs::write(&path, "port: 7890\ndns:\n  enable: true\n").unwrap();

        let error = write_mihomo_config_atomically(
            &path,
            "port: 7890\ndns: []\nsniffer:\n  enable: yes\n",
            "advanced settings test",
        )
        .unwrap_err();

        assert!(error.contains("structural validation"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "port: 7890\ndns:\n  enable: true\n"
        );
        assert!(!path.with_file_name("config.yaml.next").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn advanced_mihomo_yaml_structure_validator_accepts_generated_sections() {
        validate_mihomo_config_yaml_structure(
            r#"
port: 7890
tun:
  enable: true
  mtu: 1500
  dns-hijack:
    - any:53
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query
  nameserver-policy:
    +.example.com:
      - https://9.9.9.9/dns-query
sniffer:
  enable: true
  sniff:
    TLS:
      ports:
        - 443
  force-domain:
    - +.example.com
"#,
        )
        .unwrap();
    }

    #[test]
    fn retire_path_to_del_quarantines_directory_contents() {
        let unique = format!("badvpn-retire-test-{}", current_unix_timestamp());
        let dir = std::env::temp_dir().join(unique);
        let target = dir.join("zapret.backup");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("version.txt"), "old").unwrap();

        let retired = retire_path_to_del_at(&target, 42).unwrap().unwrap();

        assert!(!target.exists());
        assert!(retired
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("zapret.backup.del.")));
        assert_eq!(
            fs::read_to_string(retired.join("version.txt")).unwrap(),
            "old"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn retire_path_to_del_uses_collision_suffix() {
        let unique = format!("badvpn-retire-collision-{}", current_unix_timestamp());
        let dir = std::env::temp_dir().join(unique);
        let target = dir.join("mihomo.backup");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("mihomo.exe"), "old").unwrap();
        let first_retired = dir.join("mihomo.backup.del.42");
        fs::create_dir_all(&first_retired).unwrap();

        let retired = retire_path_to_del_at(&target, 42).unwrap().unwrap();

        assert!(!target.exists());
        assert_ne!(retired, first_retired);
        assert!(retired
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.contains(".del.") && name.ends_with(".1")));
        assert_eq!(
            fs::read_to_string(retired.join("mihomo.exe")).unwrap(),
            "old"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn text_artifact_redacts_before_rendering() {
        let artifact = text_artifact(
            "Generated runtime YAML",
            None,
            Some("secret: controller-secret\nproxies:\n  - password: node-secret\n"),
            None,
        );

        assert!(artifact.redacted);
        assert!(artifact.text.contains("secret: <redacted>"));
        assert!(artifact.text.contains("password: <redacted>"));
        assert!(!artifact.text.contains("controller-secret"));
        assert!(!artifact.text.contains("node-secret"));
    }

    #[test]
    fn subscription_metadata_header_aliases_are_read() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "profile_title",
            reqwest::header::HeaderValue::from_static("Alias title"),
        );
        headers.insert(
            "announcement-url",
            reqwest::header::HeaderValue::from_static("https://panel.example/news"),
        );
        headers.insert(
            "subscription-user-info",
            reqwest::header::HeaderValue::from_static("upload=1; download=2; total=10"),
        );

        assert_eq!(
            decoded_header_any(
                &headers,
                &["profile-title", "subscription-title", "profile_title"]
            )
            .as_deref(),
            Some("Alias title")
        );
        assert_eq!(
            plain_header_any(&headers, &["announce-url", "announcement-url"]).as_deref(),
            Some("https://panel.example/news")
        );
        assert_eq!(
            parse_subscription_userinfo(
                plain_header_any(
                    &headers,
                    &["subscription-userinfo", "subscription-user-info"]
                )
                .as_deref(),
            )
            .download_bytes,
            Some(2)
        );
    }

    #[test]
    fn failed_profile_refresh_preserves_cached_body_and_records_reason() {
        let mut store = PersistedSubscriptionProfiles {
            active_id: Some("profile-1".to_string()),
            profiles: vec![PersistedSubscriptionProfile {
                id: "profile-1".to_string(),
                name: "Profile".to_string(),
                description: Some("Primary provider profile".to_string()),
                subscription: SubscriptionState {
                    url: Some("https://example.com/sub/secret-token".to_string()),
                    is_valid: Some(true),
                    node_count: 1,
                    format: SubscriptionFormat::ClashYaml,
                    ..SubscriptionState::default()
                },
                protected_url: Some("protected-url".to_string()),
                protected_body: Some("cached-body".to_string()),
                last_successful_refresh_at: Some(10),
                last_failed_refresh_at: None,
                last_refresh_error: None,
                next_refresh_at: Some(3700),
                fetch_options: PersistedSubscriptionFetchOptions::default(),
                created_at: 1,
                updated_at: 10,
            }],
        };

        mark_active_profile_refresh_failure_in_store(
            &mut store,
            20,
            "Subscription provider rejected the profile: HWID limit",
        );

        let profile = &store.profiles[0];
        assert_eq!(profile.protected_body.as_deref(), Some("cached-body"));
        assert_eq!(profile.last_successful_refresh_at, Some(10));
        assert_eq!(profile.next_refresh_at, Some(3700));
        assert_eq!(profile.last_failed_refresh_at, Some(20));
        assert_eq!(
            profile.last_refresh_error.as_deref(),
            Some("Subscription provider rejected the profile: HWID limit")
        );
    }

    #[test]
    fn next_profile_refresh_uses_provider_interval() {
        let subscription = SubscriptionState {
            update_interval_hours: Some(24),
            ..SubscriptionState::default()
        };

        assert_eq!(
            next_profile_refresh_at(&subscription, 100),
            Some(100 + 24 * 60 * 60)
        );
        assert_eq!(
            next_profile_refresh_at(
                &SubscriptionState {
                    update_interval_hours: None,
                    ..SubscriptionState::default()
                },
                100,
            ),
            None
        );
    }

    #[test]
    fn due_refresh_skips_unscheduled_profiles_after_success() {
        let mut profile = PersistedSubscriptionProfile {
            id: "profile-1".to_string(),
            name: "Profile".to_string(),
            description: None,
            subscription: SubscriptionState {
                url: Some("https://example.com/sub/secret-token".to_string()),
                is_valid: Some(true),
                node_count: 1,
                format: SubscriptionFormat::ClashYaml,
                ..SubscriptionState::default()
            },
            protected_url: Some("protected-url".to_string()),
            protected_body: Some("cached-body".to_string()),
            last_successful_refresh_at: None,
            last_failed_refresh_at: None,
            last_refresh_error: None,
            next_refresh_at: None,
            fetch_options: PersistedSubscriptionFetchOptions::default(),
            created_at: 1,
            updated_at: 1,
        };

        assert!(subscription_profile_is_due_for_refresh(&profile, 100));

        profile.last_successful_refresh_at = Some(10);
        assert!(!subscription_profile_is_due_for_refresh(&profile, 100));

        profile.next_refresh_at = Some(101);
        assert!(!subscription_profile_is_due_for_refresh(&profile, 100));

        profile.next_refresh_at = Some(100);
        assert!(subscription_profile_is_due_for_refresh(&profile, 100));
    }
}

fn apply_active_subscription_state(
    subscription: SubscriptionState,
    message: Option<String>,
) -> Result<AgentState, String> {
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    state.phase = AppPhase::Ready;
    state.subscription = subscription;
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: state.running,
        zapret_healthy: state.diagnostics.zapret_healthy,
        message,
    };
    state.last_error = None;
    Ok(state.clone())
}

fn apply_no_subscription_state(message: &str) -> Result<AgentState, String> {
    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    state.phase = AppPhase::Onboarding;
    state.subscription = SubscriptionState::default();
    state.connection.connected = false;
    state.connection.status = ConnectionStatus::Idle;
    state.diagnostics = DiagnosticSummary {
        mihomo_healthy: false,
        zapret_healthy: false,
        message: Some(message.to_string()),
    };
    state.last_error = None;
    Ok(state.clone())
}

#[cfg(windows)]
fn protect_secret(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!(
            "Windows DPAPI protect failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let protected = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let encoded = general_purpose::STANDARD.encode(protected);
    unsafe {
        let _ = LocalFree(output.pbData.cast());
    }
    Ok(encoded)
}

#[cfg(windows)]
fn unprotect_secret(value: &str) -> Result<String, String> {
    let protected = general_purpose::STANDARD
        .decode(value)
        .map_err(|error| format!("Failed to decode protected URL: {error}"))?;
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!(
            "Windows DPAPI unprotect failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let decoded = String::from_utf8(bytes.to_vec())
        .map_err(|error| format!("Protected subscription URL is not UTF-8: {error}"));
    unsafe {
        let _ = LocalFree(output.pbData.cast());
    }
    decoded
}

#[cfg(not(windows))]
fn protect_secret(value: &str) -> Result<String, String> {
    Ok(general_purpose::STANDARD.encode(value.as_bytes()))
}

#[cfg(not(windows))]
fn unprotect_secret(value: &str) -> Result<String, String> {
    let decoded = general_purpose::STANDARD
        .decode(value)
        .map_err(|error| format!("Failed to decode protected URL: {error}"))?;
    String::from_utf8(decoded)
        .map_err(|error| format!("Protected subscription URL is not UTF-8: {error}"))
}

fn subscription_state_from_existing_config() -> Option<SubscriptionState> {
    let path = mihomo_config_path().ok()?;
    let content = fs::read_to_string(path).ok()?;
    let yaml = serde_yaml::from_str::<YamlValue>(&content).ok()?;
    let node_count = yaml
        .get("proxies")
        .and_then(YamlValue::as_sequence)
        .map(Vec::len)
        .unwrap_or_default();
    if node_count == 0 {
        return None;
    }
    Some(SubscriptionState {
        url: None,
        is_valid: Some(true),
        validation_error: None,
        last_refreshed_at: None,
        profile_title: Some("Local Mihomo profile".to_string()),
        announce: None,
        announce_url: None,
        support_url: None,
        profile_web_page_url: None,
        update_interval_hours: None,
        user_info: Default::default(),
        node_count,
        format: SubscriptionFormat::ClashYaml,
    })
}

fn subscription_is_present(subscription: &SubscriptionState) -> bool {
    subscription.url.is_some() || subscription.node_count > 0 || subscription.is_valid == Some(true)
}

fn load_app_settings() -> AppSettings {
    settings_file_path()
        .map(|path| read_settings_from_path(&path))
        .unwrap_or_default()
}

fn apply_settings(settings: AppSettings) -> Result<SettingsApplyResult, String> {
    settings.validate()?;
    let previous = load_app_settings();
    let restart_relevant = settings_require_restart(&previous, &settings);
    let was_running = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?
        .running;
    let path = settings_file_path()?;
    write_settings_to_path(&path, &settings)?;
    log_event(
        "settings",
        format!(
            "saved restart_relevant={restart_relevant} route={:?} zapret_enabled={} run_mode={:?} strategy={:?} game_filter={:?} ipset_filter={:?}",
            settings.core.route_mode,
            settings.zapret.enabled,
            settings.zapret.run_mode,
            settings.zapret.strategy,
            settings.zapret.game_filter,
            settings.zapret.ipset_filter
        ),
    );
    apply_ipset_filter_mode(&settings)?;
    if mihomo_config_path().map_or(false, |path| path.exists()) {
        patch_mihomo_config_with_settings(&settings)?;
    }

    let mut state = state()
        .lock()
        .map_err(|_| "agent state lock is poisoned".to_string())?;
    if !was_running {
        state.connection.route_mode = settings.effective_route_mode();
    }
    let restart_required = was_running && restart_relevant;
    let message = if restart_required {
        "Settings saved. Restart the connection to apply runtime changes.".to_string()
    } else {
        "Settings saved.".to_string()
    };
    Ok(SettingsApplyResult {
        settings,
        restart_required,
        state: state.clone(),
        message,
    })
}

fn patch_mihomo_config_with_settings(settings: &AppSettings) -> Result<(), String> {
    let config_path = mihomo_config_path()?;
    if !config_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&config_path)
        .map_err(|error| format!("Failed to read Mihomo config for settings apply: {error}"))?;
    let secret = match serde_yaml::from_str::<YamlValue>(&content)
        .ok()
        .and_then(|yaml| {
            yaml.get("secret")
                .and_then(YamlValue::as_str)
                .map(ToOwned::to_owned)
        }) {
        Some(existing) => existing,
        None => badvpn_common::generate_controller_secret()?,
    };
    let rendered = overlay_mihomo_config_yaml(
        &content,
        &secret,
        &mihomo_options_for_runtime_route(settings, settings.effective_route_mode()),
    )?;
    write_mihomo_config_atomically(&config_path, &rendered, "settings apply")
}

fn data_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("APPDATA") {
        return Ok(PathBuf::from(path).join("BadVpn"));
    }
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path).join("BadVpn"));
    }
    std::env::current_dir()
        .map(|path| path.join("runtime").join("BadVpn"))
        .map_err(|error| format!("Failed to resolve BadVpn data directory: {error}"))
}

fn programdata_dir() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("PROGRAMDATA") {
        return Ok(PathBuf::from(path).join("BadVpn"));
    }
    std::env::current_dir()
        .map(|path| path.join("runtime").join("BadVpn"))
        .map_err(|error| format!("Failed to resolve BadVpn ProgramData directory: {error}"))
}

fn decoded_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = plain_header(headers, name)?;
    decode_header_value(Some(&value))
}

fn decoded_header_any(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| decoded_header(headers, name))
}

fn plain_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn plain_header_any(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| plain_header(headers, name))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
