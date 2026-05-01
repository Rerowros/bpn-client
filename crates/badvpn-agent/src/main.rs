use anyhow::Context;
use badvpn_agent::{
    command::AgentController,
    ipc::{serve_agent_ipc, PIPE_NAME},
    service,
};
use badvpn_common::AgentCommand;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    append_boot_log("badvpn-agent process entered main");
    let log_filter = std::env::var("BADVPN_AGENT_LOG_FILTER")
        .unwrap_or_else(|_| "badvpn_agent=debug,badvpn_common=debug,info".into());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_filter))
        .with_writer(AgentLogWriter::default())
        .init();

    tracing::debug!(pipe = PIPE_NAME, "agent IPC endpoint reserved");
    if let Some(command) = std::env::args().nth(1) {
        tracing::debug!(%command, "agent command dispatch");
        append_boot_log(format!("badvpn-agent command dispatch: {command}"));
        match command.as_str() {
            "serve" => return serve_agent_ipc(Arc::new(AtomicBool::new(false))).await,
            "run-service" => return service::run_service_dispatcher(),
            "install-service" => {
                let status = service::install_service(None)?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            "uninstall-service" => {
                let status = service::uninstall_service()?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            "start-service" => {
                let status = service::start_service()?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            "stop-service" => {
                let status = service::stop_service()?;
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            "service-status" => {
                let status = service::status();
                println!("{}", serde_json::to_string_pretty(&status)?);
                return Ok(());
            }
            _ => {}
        }
    }

    let mut controller = AgentController::default();
    let command = parse_command().context("failed to parse agent command")?;
    let state = controller.handle(command).await?;

    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}

#[derive(Debug, Clone)]
struct AgentLogWriter {
    path: PathBuf,
}

impl Default for AgentLogWriter {
    fn default() -> Self {
        Self {
            path: agent_log_path(),
        }
    }
}

impl<'a> MakeWriter<'a> for AgentLogWriter {
    type Writer = AgentLogFile;

    fn make_writer(&'a self) -> Self::Writer {
        AgentLogFile {
            file: self
                .path
                .parent()
                .and_then(|parent| std::fs::create_dir_all(parent).ok().map(|_| parent))
                .and_then(|_| {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)
                        .ok()
                }),
        }
    }
}

struct AgentLogFile {
    file: Option<std::fs::File>,
}

impl Write for AgentLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(file) = &mut self.file {
            file.write(buf)
        } else {
            io::sink().write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()
        } else {
            Ok(())
        }
    }
}

fn agent_log_path() -> PathBuf {
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

pub fn append_boot_log(message: impl AsRef<str>) {
    let path = agent_log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let sanitized = message.as_ref().replace(['\r', '\n'], " ");
        let _ = writeln!(
            file,
            "{:?} [boot] {sanitized}",
            std::time::SystemTime::now()
        );
    }
}

fn parse_command() -> anyhow::Result<AgentCommand> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Ok(AgentCommand::Status);
    };

    match command.as_str() {
        "status" => Ok(AgentCommand::Status),
        "runtime-status" => Ok(AgentCommand::RuntimeStatus),
        "connect" => {
            let path = args
                .next()
                .context("connect requires a JSON ConnectRequest file path")?;
            let content =
                std::fs::read_to_string(path).context("failed to read ConnectRequest JSON file")?;
            let request =
                serde_json::from_str(&content).context("failed to parse ConnectRequest JSON")?;
            Ok(AgentCommand::Connect {
                request: Box::new(request),
            })
        }
        "start" => Ok(AgentCommand::Start),
        "stop" => Ok(AgentCommand::Stop),
        "restart" => Ok(AgentCommand::Restart),
        "set-subscription" => {
            let url = args.next().unwrap_or_default();
            Ok(AgentCommand::SetSubscription { url })
        }
        "refresh-subscription" => Ok(AgentCommand::RefreshSubscription),
        "diagnostics" => Ok(AgentCommand::RunDiagnostics),
        "cleanup-legacy-zapret" => Ok(AgentCommand::CleanupLegacyZapret),
        "verify-installed-agent" => Ok(AgentCommand::VerifyInstalledAgent),
        other => anyhow::bail!("unknown command: {other}"),
    }
}
