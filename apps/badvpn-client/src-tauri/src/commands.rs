use crate::settings::{
    read_settings_from_path, settings_require_restart, write_settings_to_path, AppSettings,
    ZapretGameFilter, ZapretIpSetFilter, ZapretRunMode, ZapretStrategy,
};
use badvpn_common::{
    decode_header_value, flowseal_exclude_hostlist, flowseal_general_hostlist,
    flowseal_google_hostlist, flowseal_ipset_exclude,
    generate_mihomo_config_from_subscription_with_options, overlay_mihomo_config_yaml,
    parse_subscription_userinfo, summarize_subscription_body, zapret_default_hostlist,
    zapret_default_ipset, zapret_user_placeholder_hostlist, AgentCommand, AgentState, AppPhase,
    CompiledPolicy, ConnectRequest, ConnectionStatus, DiagnosticSummary, MihomoConfigOptions,
    RouteMode, RuntimeDiagnosticsSettings, RuntimeGameProfile, RuntimeMode, RuntimeSettings,
    RuntimeZapretSettings, SubscriptionFormat, SubscriptionState, AGENT_LOCAL_ADDR,
    AGENT_PIPE_NAME,
};
use base64::{engine::general_purpose, Engine};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;
use zip::ZipArchive;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY,
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

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

fn state() -> &'static Mutex<AgentState> {
    STATE.get_or_init(|| Mutex::new(AgentState::default()))
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
        if let Ok(agent_state) = send_agent_command(AgentCommand::RuntimeStatus, false) {
            return apply_agent_state(agent_state);
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
    let url = subscription
        .url
        .as_deref()
        .ok_or_else(|| "Active subscription URL is not available.".to_string())?;
    let imported = match fetch_subscription(url).await {
        Ok(imported) => imported,
        Err(error) => {
            if let Some(body) = active_persisted_subscription_profile_body() {
                log_event(
                    "subscription",
                    format!(
                        "using cached subscription profile for connect because live fetch failed: {error}"
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
                        "using existing Mihomo config for connect because live fetch failed: {error}"
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

fn should_use_agent_runtime() -> bool {
    std::env::var("BADVPN_LEGACY_RUNTIME").ok().as_deref() != Some("1")
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
                FILE_ATTRIBUTE_NORMAL,
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
        let mut written = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                data.as_ptr().cast(),
                data.len().min(u32::MAX as usize) as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } != 0;
        if !ok {
            return Err(format!(
                "Failed to write agent named pipe request: {}",
                std::io::Error::last_os_error()
            ));
        }
        data = &data[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_pipe_line(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<String, String> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        } != 0;
        if !ok {
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_DATA {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            if error == ERROR_BROKEN_PIPE && !data.is_empty() {
                break;
            }
            return Err(format!(
                "Failed to read agent named pipe response: {}",
                std::io::Error::last_os_error()
            ));
        }
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
                    .join("apps")
                    .join("badvpn-client")
                    .join("src-tauri")
                    .join("target-runtime")
                    .join("release")
                    .join(exe_name),
            );
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

    let imported = fetch_subscription(&url).await;
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
                state.subscription.is_valid = Some(false);
                state.subscription.validation_error = Some(error.clone());
                state.last_error = Some(error);
                return Ok(state.clone());
            }
            state.subscription = imported.subscription;
            let _ = persist_subscription_state_with_body(&state.subscription, Some(&imported.body));
            state.last_error = None;
        }
        Err(error) => {
            log_event("subscription", format!("refresh failed: {error}"));
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
    let imported = fetch_subscription(trimmed).await?;
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
        profile.updated_at = now;
        profile.id.clone()
    } else {
        let id = subscription_profile_id(trimmed, now);
        store.profiles.push(PersistedSubscriptionProfile {
            id: id.clone(),
            name: display_name,
            subscription: imported.subscription.clone(),
            protected_url: Some(protect_secret(trimmed)?),
            protected_body: Some(protect_secret(&imported.body)?),
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
    let imported = fetch_subscription(&url).await?;
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
            let imported = fetch_subscription(&url).await?;
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
    subscription: SubscriptionState,
    #[serde(default)]
    protected_url: Option<String>,
    #[serde(default)]
    protected_body: Option<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionProfilesState {
    pub active_id: Option<String>,
    pub profiles: Vec<SubscriptionProfileView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionProfileView {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub redacted_url: Option<String>,
    pub subscription: SubscriptionState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionProfilesApplyResult {
    pub profiles: SubscriptionProfilesState,
    pub state: AgentState,
    pub message: String,
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
    pub rule: Option<String>,
    pub rule_payload: Option<String>,
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
    let mihomo_ready = resolve_mihomo_bin().is_ok()
        || programdata_mihomo_bin()
            .map(|path| path.exists())
            .unwrap_or(false);
    let zapret_ready = !needs_zapret
        || zapret_runtime_assets_ready().is_ok()
        || programdata_zapret_runtime_assets_ready().is_ok();
    let components_ready = mihomo_ready && zapret_ready;
    let ready = agent.installed && agent.ipc_ready && components_ready;
    let message = if ready {
        "Ready to connect.".to_string()
    } else if !agent.installed {
        "Install badvpn-agent before connecting.".to_string()
    } else if !agent.ipc_ready {
        "badvpn-agent is installed but not reachable yet.".to_string()
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
    let client = mihomo_http_client()?;
    let url = format!(
        "{}/proxies/{}",
        mihomo_controller_base()?,
        path_encode(group.trim())
    );
    let response = add_mihomo_auth(client.put(url).json(&json!({ "name": proxy.trim() })))
        .send()
        .await
        .map_err(|error| format!("Failed to select proxy: {error}"))?;
    response
        .error_for_status()
        .map_err(|error| format!("Mihomo rejected proxy selection: {error}"))?;
    persist_proxy_selection(group.trim(), proxy.trim())?;
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

async fn refresh_runtime_state(run_network_tests: bool) -> Result<AgentState, String> {
    hydrate_persisted_state()?;
    let settings = load_app_settings();
    let now = current_unix_timestamp();
    let run_network_tests = run_network_tests && settings.diagnostics.discord_youtube_probes;
    if settings.updates.auto_flowseal_list_refresh && should_attempt_auto_list_refresh() {
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

fn should_attempt_auto_list_refresh() -> bool {
    let now = current_unix_timestamp();
    let Ok(mut last) = last_list_refresh_attempt().lock() else {
        return false;
    };
    if now.saturating_sub(*last) >= 60 * 60 {
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
        let staging_script = stage_runtime_assets_powershell()?;
        let script = format!(
            r#"$ErrorActionPreference = 'Stop'
$sourceAgent = '{agent}'
$serviceAgent = '{service_agent}'
$serviceAgentDir = Split-Path -Parent $serviceAgent
{staging_script}
New-Item -ItemType Directory -Path $serviceAgentDir -Force | Out-Null
$service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {{
  sc.exe stop '{service_name}' | Out-Null
  $deadline = (Get-Date).AddSeconds(20)
  do {{
    Start-Sleep -Milliseconds 250
    $service = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue
  }} while ($service -and $service.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
  if ($service -and $service.Status -ne 'Stopped') {{ throw "{service_name} did not stop before agent repair" }}
}}
Copy-Item -LiteralPath $sourceAgent -Destination $serviceAgent -Force
& $serviceAgent install-service | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw "badvpn-agent install-service failed with exit code $LASTEXITCODE" }}
"#,
            agent = powershell_single_quote(&agent_bin.to_string_lossy()),
            service_agent = powershell_single_quote(&service_agent_bin.to_string_lossy()),
            service_name = BADVPN_AGENT_SERVICE,
            staging_script = staging_script,
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

fn stage_runtime_assets_powershell() -> Result<String, String> {
    let source_components = data_dir()?.join("components");
    let target_components = programdata_dir()?.join("components");
    let source_lists = data_dir()?.join("zapret").join("lists");
    let target_lists = programdata_dir()?
        .join("components")
        .join("zapret")
        .join("lists");
    Ok(format!(
        r#"$sourceComponents = '{source_components}'
$targetComponents = '{target_components}'
if (Test-Path -LiteralPath $sourceComponents) {{
  New-Item -ItemType Directory -Path $targetComponents -Force | Out-Null
  robocopy $sourceComponents $targetComponents /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -gt 7) {{ throw "component staging failed with robocopy exit code $LASTEXITCODE" }}
  $global:LASTEXITCODE = 0
}}
$sourceLists = '{source_lists}'
$targetLists = '{target_lists}'
if (Test-Path -LiteralPath $sourceLists) {{
  New-Item -ItemType Directory -Path $targetLists -Force | Out-Null
  robocopy $sourceLists $targetLists /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -gt 7) {{ throw "Flowseal list staging failed with robocopy exit code $LASTEXITCODE" }}
  $global:LASTEXITCODE = 0
}}
"#,
        source_components = powershell_single_quote(&source_components.to_string_lossy()),
        target_components = powershell_single_quote(&target_components.to_string_lossy()),
        source_lists = powershell_single_quote(&source_lists.to_string_lossy()),
        target_lists = powershell_single_quote(&target_lists.to_string_lossy()),
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
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
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
    let path = mihomo_config_path()?;
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
    if agent_runtime_components_ready(needs_zapret) {
        return Ok(());
    }

    log_event(
        "components",
        "first-run runtime component preparation requested for badvpn-agent",
    );
    install_components(false).await?;

    if read_badvpn_agent_service_status().installed {
        stage_runtime_assets_to_programdata()?;
        log_event(
            "components",
            "first-run runtime components staged to ProgramData for badvpn-agent",
        );
    }

    if agent_runtime_components_ready(needs_zapret) {
        Ok(())
    } else {
        Err("Runtime components are still missing after first-run preparation.".to_string())
    }
}

fn agent_runtime_components_ready(needs_zapret: bool) -> bool {
    let mihomo_ready = resolve_mihomo_bin().is_ok()
        || programdata_mihomo_bin()
            .map(|path| path.exists())
            .unwrap_or(false);
    let zapret_ready = !needs_zapret
        || zapret_runtime_assets_ready().is_ok()
        || programdata_zapret_runtime_assets_ready().is_ok();
    mihomo_ready && zapret_ready
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
    let client = reqwest::Client::builder()
        .user_agent(SUBSCRIPTION_USER_AGENT)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    let response = client
        .get(url)
        .header(ACCEPT, "application/x-yaml,text/yaml,text/plain,*/*")
        .send()
        .await
        .map_err(|error| format!("Failed to fetch subscription: {error}"))?;

    let headers = response.headers().clone();
    let body = response
        .error_for_status()
        .map_err(|error| format!("Subscription server returned an error: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Failed to read subscription body: {error}"))?;

    let summary = summarize_subscription_body(&body);
    log_event(
        "subscription",
        format!(
            "fetched format={:?} nodes={} decoded_size={} content_type={}",
            summary.format,
            summary.node_count,
            summary.decoded_size_bytes,
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown")
        ),
    );
    if summary.node_count == 0 {
        return Err("Subscription fetched, but no supported nodes were found.".to_string());
    }

    Ok(ImportedSubscription {
        subscription: SubscriptionState {
            url: Some(url.to_string()),
            is_valid: Some(true),
            validation_error: None,
            last_refreshed_at: Some(current_unix_timestamp().to_string()),
            profile_title: decoded_header(&headers, "profile-title"),
            announce: decoded_header(&headers, "announce"),
            announce_url: plain_header(&headers, "announce-url"),
            support_url: plain_header(&headers, "support-url"),
            profile_web_page_url: plain_header(&headers, "profile-web-page-url"),
            update_interval_hours: plain_header(&headers, "profile-update-interval")
                .and_then(|value| value.parse::<u64>().ok()),
            user_info: parse_subscription_userinfo(
                plain_header(&headers, "subscription-userinfo").as_deref(),
            ),
            node_count: summary.node_count,
            format: summary.format,
        },
        body,
    })
}

fn write_mihomo_config(subscription_body: &str) -> Result<(), String> {
    let secret = format!("badvpn-{}", current_unix_timestamp());
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
    let secret = serde_yaml::from_str::<YamlValue>(&content)
        .ok()
        .and_then(|yaml| {
            yaml.get("secret")
                .and_then(YamlValue::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("badvpn-{}", current_unix_timestamp()));
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

    fs::write(&next_path, rendered_yaml)
        .map_err(|error| format!("Failed to write staged Mihomo config: {error}"))?;

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

    fs::copy(&next_path, config_path)
        .map_err(|error| format!("Failed to promote staged Mihomo config: {error}"))?;
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
        let _ = fs::remove_dir_all(path);
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
                let _ = fs::remove_dir_all(&target);
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

fn read_proxy_selections() -> Result<BTreeMap<String, String>, String> {
    let path = proxy_selections_file_path()?;
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(BTreeMap::new());
    };
    serde_json::from_str::<BTreeMap<String, String>>(&content)
        .map_err(|error| format!("Failed to parse proxy selections: {error}"))
}

fn persist_proxy_selection(group: &str, proxy: &str) -> Result<(), String> {
    if group.trim().is_empty() || proxy.trim().is_empty() {
        return Ok(());
    }
    let path = proxy_selections_file_path()?;
    let mut selections = read_proxy_selections().unwrap_or_default();
    selections.insert(group.trim().to_string(), proxy.trim().to_string());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create proxy selection directory: {error}"))?;
    }
    let content = serde_json::to_string_pretty(&selections)
        .map_err(|error| format!("Failed to serialize proxy selections: {error}"))?;
    fs::write(path, content).map_err(|error| format!("Failed to write proxy selections: {error}"))
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
            protected_url: subscription
                .url
                .as_deref()
                .and_then(|url| protect_secret(url).ok()),
            protected_body: None,
            subscription,
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
            subscription: subscription.clone(),
            protected_url: url.map(protect_secret).transpose()?,
            protected_body: profile_body.map(protect_secret).transpose()?,
            created_at: now,
            updated_at: now,
        });
        id
    };
    store.active_id = Some(id);
    write_persisted_subscription_profiles(&store)
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
                redacted_url,
                subscription,
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
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}/...")
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
    let secret = serde_yaml::from_str::<YamlValue>(&content)
        .ok()
        .and_then(|yaml| {
            yaml.get("secret")
                .and_then(YamlValue::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("badvpn-{}", current_unix_timestamp()));
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

fn plain_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
