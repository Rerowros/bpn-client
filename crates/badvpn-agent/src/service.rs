#[cfg(windows)]
mod platform {
    use std::{
        ffi::OsString,
        fs::OpenOptions,
        io::Write,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };

    use anyhow::{anyhow, Context, Result};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    pub const SERVICE_NAME: &str = "badvpn-agent";
    pub const SERVICE_DISPLAY_NAME: &str = "BadVpn Agent";
    const SERVICE_DESCRIPTION: &str =
        "BadVpn privileged runtime agent for Mihomo, zapret/winws, WinDivert, and updates.";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct AgentServiceStatus {
        pub service_name: String,
        pub installed: bool,
        pub running: bool,
        pub state: Option<String>,
        pub message: String,
    }

    pub fn run_service_dispatcher() -> Result<()> {
        append_service_log("service dispatcher start requested");
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|error| anyhow!("failed to start Windows service dispatcher: {error}"))
    }

    fn service_main(_arguments: Vec<OsString>) {
        append_service_log("service_main entered");
        if let Err(error) = run_service_worker() {
            append_service_log(format!("service_main failed: {error}"));
            tracing::error!(%error, "BadVpn agent service failed");
        }
    }

    fn run_service_worker() -> Result<()> {
        append_service_log("run_service_worker starting");
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_handler = Arc::clone(&shutdown);

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    append_service_log("service stop requested");
                    shutdown_for_handler.store(true, Ordering::SeqCst);
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .context("failed to register BadVpn agent service control handler")?;
        append_service_log("service control handler registered");
        set_service_status(
            &status_handle,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
        )?;
        append_service_log("service status set to StartPending");
        set_service_status(
            &status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP,
        )?;
        append_service_log("service status set to Running");

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to create BadVpn agent service runtime")?;
        let shutdown_for_server = Arc::clone(&shutdown);
        let server = std::thread::spawn(move || {
            append_service_log("IPC server thread entered");
            let result = runtime.block_on(crate::ipc::serve_agent_ipc(shutdown_for_server));
            append_service_log(format!("IPC server thread exited: ok={}", result.is_ok()));
            result
        });
        append_service_log("IPC server thread spawned");

        let _ = shutdown_rx.recv();
        shutdown.store(true, Ordering::SeqCst);
        set_service_status(
            &status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
        )?;
        append_service_log("service status set to StopPending");
        match server.join() {
            Ok(result) => result?,
            Err(_) => return Err(anyhow!("BadVpn agent IPC thread panicked")),
        }
        set_service_status(
            &status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
        )?;
        append_service_log("service status set to Stopped");
        Ok(())
    }

    fn append_service_log(message: impl AsRef<str>) {
        let path = service_log_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let sanitized = message.as_ref().replace(['\r', '\n'], " ");
            let _ = writeln!(
                file,
                "{:?} [service] {sanitized}",
                std::time::SystemTime::now()
            );
        }
    }

    fn service_log_path() -> PathBuf {
        if let Ok(path) = std::env::var("BADVPN_AGENT_LOG") {
            return PathBuf::from(path);
        }
        if let Ok(path) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(path)
                .join("BadVpn")
                .join("logs")
                .join("badvpn-agent.log");
        }
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("runtime")
            .join("BadVpn")
            .join("logs")
            .join("badvpn-agent.log")
    }

    fn set_service_status(
        status_handle: &windows_service::service_control_handler::ServiceStatusHandle,
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
    ) -> windows_service::Result<()> {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    }

    pub fn install_service(executable_path: Option<PathBuf>) -> Result<AgentServiceStatus> {
        let executable_path = executable_path
            .unwrap_or(std::env::current_exe().context("failed to locate badvpn-agent.exe")?);
        let service_manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("failed to open Windows Service Control Manager")?;

        if let Ok(existing) = service_manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        ) {
            let _ = existing.stop();
            let _ = wait_until_stopped();
            existing
                .delete()
                .context("failed to remove stale BadVpn agent service")?;
            std::thread::sleep(Duration::from_millis(500));
        }

        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path,
            launch_arguments: vec![OsString::from("run-service")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service = service_manager
            .create_service(
                &service_info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .context("failed to create BadVpn agent service")?;
        service
            .set_description(SERVICE_DESCRIPTION)
            .context("failed to set BadVpn agent service description")?;
        let _ = service.start::<OsString>(&[]);
        wait_until_running()
    }

    pub fn uninstall_service() -> Result<AgentServiceStatus> {
        let service_manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("failed to open Windows Service Control Manager")?;
        match service_manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        ) {
            Ok(service) => {
                let _ = service.stop();
                let _ = wait_until_stopped();
                service
                    .delete()
                    .context("failed to remove BadVpn agent service")?;
                Ok(AgentServiceStatus {
                    service_name: SERVICE_NAME.to_string(),
                    installed: false,
                    running: false,
                    state: None,
                    message: "BadVpn agent service removed.".to_string(),
                })
            }
            Err(_) => Ok(status()),
        }
    }

    pub fn start_service() -> Result<AgentServiceStatus> {
        let service = open_service(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        match service.query_status() {
            Ok(current) if current.current_state == ServiceState::Running => return Ok(status()),
            _ => {}
        }
        service
            .start::<OsString>(&[])
            .context("failed to start BadVpn agent service")?;
        wait_until_running()
    }

    pub fn stop_service() -> Result<AgentServiceStatus> {
        let service = open_service(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        match service.query_status() {
            Ok(current) if current.current_state == ServiceState::Stopped => return Ok(status()),
            _ => {}
        }
        service
            .stop()
            .context("failed to stop BadVpn agent service")?;
        wait_until_stopped()
    }

    pub fn status() -> AgentServiceStatus {
        match query_state() {
            Ok(state) => AgentServiceStatus {
                service_name: SERVICE_NAME.to_string(),
                installed: true,
                running: state == ServiceState::Running,
                state: Some(format_service_state(state).to_string()),
                message: format!("BadVpn agent service: {}.", format_service_state(state)),
            },
            Err(_) => AgentServiceStatus {
                service_name: SERVICE_NAME.to_string(),
                installed: false,
                running: false,
                state: None,
                message: "BadVpn agent service is not installed.".to_string(),
            },
        }
    }

    fn wait_until_running() -> Result<AgentServiceStatus> {
        wait_for_state(ServiceState::Running, Duration::from_secs(8))
    }

    fn wait_until_stopped() -> Result<AgentServiceStatus> {
        wait_for_state(ServiceState::Stopped, Duration::from_secs(8))
    }

    fn wait_for_state(target: ServiceState, timeout: Duration) -> Result<AgentServiceStatus> {
        let started = std::time::Instant::now();
        loop {
            let current = status();
            if target == ServiceState::Stopped && !current.installed {
                return Ok(current);
            }
            if current.state.as_deref() == Some(format_service_state(target)) {
                return Ok(current);
            }
            if started.elapsed() >= timeout {
                return Ok(current);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn query_state() -> windows_service::Result<ServiceState> {
        let service = open_service(ServiceAccess::QUERY_STATUS)?;
        service.query_status().map(|status| status.current_state)
    }

    fn open_service(
        access: ServiceAccess,
    ) -> windows_service::Result<windows_service::service::Service> {
        let service_manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        service_manager.open_service(SERVICE_NAME, access)
    }

    fn format_service_state(state: ServiceState) -> &'static str {
        match state {
            ServiceState::Stopped => "Stopped",
            ServiceState::StartPending => "StartPending",
            ServiceState::StopPending => "StopPending",
            ServiceState::Running => "Running",
            ServiceState::ContinuePending => "ContinuePending",
            ServiceState::PausePending => "PausePending",
            ServiceState::Paused => "Paused",
        }
    }
}

#[cfg(windows)]
pub use platform::*;

#[cfg(not(windows))]
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentServiceStatus {
    pub service_name: String,
    pub installed: bool,
    pub running: bool,
    pub state: Option<String>,
    pub message: String,
}

#[cfg(not(windows))]
pub const SERVICE_NAME: &str = "badvpn-agent";

#[cfg(not(windows))]
pub fn run_service_dispatcher() -> anyhow::Result<()> {
    anyhow::bail!("BadVpn agent service is only available on Windows")
}

#[cfg(not(windows))]
pub fn install_service(
    _executable_path: Option<std::path::PathBuf>,
) -> anyhow::Result<AgentServiceStatus> {
    anyhow::bail!("BadVpn agent service install is only available on Windows")
}

#[cfg(not(windows))]
pub fn uninstall_service() -> anyhow::Result<AgentServiceStatus> {
    anyhow::bail!("BadVpn agent service removal is only available on Windows")
}

#[cfg(not(windows))]
pub fn start_service() -> anyhow::Result<AgentServiceStatus> {
    anyhow::bail!("BadVpn agent service start is only available on Windows")
}

#[cfg(not(windows))]
pub fn stop_service() -> anyhow::Result<AgentServiceStatus> {
    anyhow::bail!("BadVpn agent service stop is only available on Windows")
}

#[cfg(not(windows))]
pub fn status() -> AgentServiceStatus {
    AgentServiceStatus {
        service_name: SERVICE_NAME.to_string(),
        installed: false,
        running: false,
        state: None,
        message: "BadVpn agent service is only available on Windows.".to_string(),
    }
}
