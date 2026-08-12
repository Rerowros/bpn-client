use std::{
    io::{BufRead, BufReader, Write},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use badvpn_common::{AgentCommand, AgentState, AGENT_LOCAL_ADDR, AGENT_PIPE_NAME};
use serde::Serialize;

use crate::command::AgentController;

pub const PIPE_NAME: &str = AGENT_PIPE_NAME;
const IPC_IDLE_READ_TIMEOUT: Duration = Duration::from_secs(5);
static CACHED_ALLOWED_USER_SID: OnceLock<Option<String>> = OnceLock::new();

#[derive(Debug, Serialize)]
struct AgentWireResponse {
    ok: bool,
    state: Option<AgentState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_summary: Option<badvpn_common::ipc::PolicySummaryResponse>,
    error: Option<String>,
}

pub async fn serve_agent_ipc(shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if std::env::var("BADVPN_AGENT_TCP_FALLBACK").ok().as_deref() == Some("1") {
            tracing::warn!("BADVPN_AGENT_TCP_FALLBACK=1; serving agent IPC over localhost TCP");
            return serve_agent_tcp_ipc(shutdown).await;
        }
        return serve_agent_named_pipe_ipc(shutdown).await;
    }

    #[cfg(not(windows))]
    {
        serve_agent_tcp_ipc(shutdown).await
    }
}

async fn serve_agent_tcp_ipc(shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
    let listener = std::net::TcpListener::bind(AGENT_LOCAL_ADDR)
        .with_context(|| format!("failed to bind BadVpn agent IPC at {AGENT_LOCAL_ADDR}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to switch BadVpn agent IPC listener to non-blocking mode")?;
    let mut controller = AgentController::default();
    controller.start_background_watchdog();
    tracing::info!(addr = AGENT_LOCAL_ADDR, "BadVpn agent IPC server started");

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                let _ = stream.set_read_timeout(Some(IPC_IDLE_READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IPC_IDLE_READ_TIMEOUT));
                let mut line = String::new();
                {
                    let mut reader = BufReader::new(&mut stream);
                    if let Err(error) = reader.read_line(&mut line) {
                        let _ = write_agent_response(
                            &mut stream,
                            AgentWireResponse {
                                ok: false,
                                state: None,
                                policy_summary: None,
                                error: Some(format!("failed to read command: {error}")),
                            },
                        );
                        continue;
                    }
                }

                let response = match serde_json::from_str::<AgentCommand>(&line) {
                    Ok(AgentCommand::PolicySummary) => match controller.policy_summary() {
                        Ok(summary) => AgentWireResponse {
                            ok: true,
                            state: None,
                            policy_summary: Some(summary),
                            error: None,
                        },
                        Err(error) => AgentWireResponse {
                            ok: false,
                            state: None,
                            policy_summary: None,
                            error: Some(error.to_string()),
                        },
                    },
                    Ok(command) => match controller.handle(command).await {
                        Ok(state) => AgentWireResponse {
                            ok: true,
                            state: Some(state),
                            policy_summary: None,
                            error: None,
                        },
                        Err(error) => AgentWireResponse {
                            ok: false,
                            state: None,
                            policy_summary: None,
                            error: Some(error.to_string()),
                        },
                    },
                    Err(error) => AgentWireResponse {
                        ok: false,
                        state: None,
                        policy_summary: None,
                        error: Some(format!("failed to parse command: {error}")),
                    },
                };
                let _ = write_agent_response(&mut stream, response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            }
            Err(error) => {
                tracing::warn!(%error, "failed to accept agent IPC client");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    }

    if let Err(error) = controller.shutdown_cleanup().await {
        tracing::warn!(%error, "failed to clean up runtime processes during IPC shutdown");
    }
    tracing::info!("BadVpn agent IPC server stopped");
    Ok(())
}

#[cfg(windows)]
async fn serve_agent_named_pipe_ipc(shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
            ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_NOWAIT,
            PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        },
    };

    const BUFFER_SIZE: u32 = 64 * 1024;
    let mut controller = AgentController::default();
    controller.start_background_watchdog();
    tracing::info!(
        pipe = PIPE_NAME,
        "BadVpn agent named pipe IPC server started"
    );

    while !shutdown.load(Ordering::SeqCst) {
        let pipe_name = wide_null(PIPE_NAME);
        let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let sddl_string = agent_pipe_sddl();
        let sddl = wide_null(&sddl_string);
        let security_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut security_descriptor,
                std::ptr::null_mut(),
            )
        } != 0;
        if !security_ok {
            tracing::warn!(
                error = std::io::Error::last_os_error().to_string(),
                "failed to create named pipe security descriptor; using default DACL"
            );
        }
        let mut security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.cast(),
            bInheritHandle: 0,
        };
        let attributes_ptr = if security_ok {
            &mut security_attributes as *mut SECURITY_ATTRIBUTES
        } else {
            std::ptr::null_mut()
        };

        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                500,
                attributes_ptr,
            )
        };
        if !security_descriptor.is_null() {
            unsafe {
                let _ = LocalFree(security_descriptor.cast());
            }
        }
        if handle == INVALID_HANDLE_VALUE {
            tracing::warn!(
                error = std::io::Error::last_os_error().to_string(),
                "failed to create BadVpn agent named pipe"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }
        tracing::debug!(pipe = PIPE_NAME, "BadVpn agent named pipe instance created");

        let connected = loop {
            if shutdown.load(Ordering::SeqCst) {
                unsafe {
                    CloseHandle(handle);
                }
                break false;
            }

            if unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0 {
                break true;
            }

            let error = unsafe { GetLastError() };
            if error == ERROR_PIPE_CONNECTED {
                break true;
            }
            if error == ERROR_PIPE_LISTENING {
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                continue;
            }
            unsafe {
                CloseHandle(handle);
            }
            if error == ERROR_NO_DATA {
                tracing::debug!("BadVpn agent named pipe client disconnected before command");
            } else {
                tracing::warn!(error, "failed to connect BadVpn agent named pipe client");
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            break false;
        };
        if !connected {
            continue;
        }
        tracing::debug!(pipe = PIPE_NAME, "BadVpn agent named pipe client connected");

        let line = match read_pipe_line(handle) {
            Ok(line) => line,
            Err(error) => {
                let _ = write_pipe_response(
                    handle,
                    AgentWireResponse {
                        ok: false,
                        state: None,
                        policy_summary: None,
                        error: Some(format!("failed to read command: {error}")),
                    },
                );
                unsafe {
                    let _ = FlushFileBuffers(handle);
                    let _ = DisconnectNamedPipe(handle);
                    CloseHandle(handle);
                }
                continue;
            }
        };

        let response = match serde_json::from_str::<AgentCommand>(&line) {
            Ok(AgentCommand::PolicySummary) => match controller.policy_summary() {
                Ok(summary) => AgentWireResponse {
                    ok: true,
                    state: None,
                    policy_summary: Some(summary),
                    error: None,
                },
                Err(error) => AgentWireResponse {
                    ok: false,
                    state: None,
                    policy_summary: None,
                    error: Some(error.to_string()),
                },
            },
            Ok(command) => match controller.handle(command).await {
                Ok(state) => AgentWireResponse {
                    ok: true,
                    state: Some(state),
                    policy_summary: None,
                    error: None,
                },
                Err(error) => AgentWireResponse {
                    ok: false,
                    state: None,
                    policy_summary: None,
                    error: Some(error.to_string()),
                },
            },
            Err(error) => AgentWireResponse {
                ok: false,
                state: None,
                policy_summary: None,
                error: Some(format!("failed to parse command: {error}")),
            },
        };
        let _ = write_pipe_response(handle, response);
        tracing::debug!("BadVpn agent named pipe command handled");
        unsafe {
            let _ = FlushFileBuffers(handle);
            let _ = DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }
    }

    if let Err(error) = controller.shutdown_cleanup().await {
        tracing::warn!(%error, "failed to clean up runtime processes during IPC shutdown");
    }
    tracing::info!("BadVpn agent named pipe IPC server stopped");
    Ok(())
}

fn write_agent_response<W: Write>(
    writer: &mut W,
    response: AgentWireResponse,
) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *writer, &response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn agent_pipe_sddl() -> String {
    let sid = configured_allowed_user_sid()
        .or_else(persisted_allowed_user_sid)
        .or_else(active_console_user_sid);
    if let Some(sid) = sid.as_deref() {
        persist_allowed_user_sid(sid);
    }
    agent_pipe_sddl_for_user_sid(sid.as_deref())
}

fn agent_pipe_sddl_for_user_sid(user_sid: Option<&str>) -> String {
    let mut sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string();
    if let Some(user_sid) = user_sid.filter(|sid| sid.starts_with("S-1-")) {
        sddl.push_str(&format!("(A;;GRGW;;;{user_sid})"));
    }
    sddl
}

fn configured_allowed_user_sid() -> Option<String> {
    std::env::var("BADVPN_AGENT_ALLOWED_USER_SID")
        .ok()
        .map(|sid| sid.trim().to_string())
        .filter(|sid| sid.starts_with("S-1-"))
}

fn allowed_user_sid_path() -> Option<std::path::PathBuf> {
    let root = std::env::var("BADVPN_AGENT_DATA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("PROGRAMDATA")
                .ok()
                .map(|path| std::path::PathBuf::from(path).join("BadVpn"))
        })?;
    Some(root.join("agent").join("allowed-user.sid"))
}

fn persisted_allowed_user_sid() -> Option<String> {
    if let Some(cached) = CACHED_ALLOWED_USER_SID.get() {
        return cached.clone();
    }
    let path = allowed_user_sid_path()?;
    let sid = std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|sid| sid.starts_with("S-1-"));
    let _ = CACHED_ALLOWED_USER_SID.set(sid.clone());
    sid
}

fn persist_allowed_user_sid(sid: &str) {
    if !sid.starts_with("S-1-") {
        return;
    }
    let _ = CACHED_ALLOWED_USER_SID.set(Some(sid.to_string()));
    let Some(path) = allowed_user_sid_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, sid);
}

fn active_console_user_sid() -> Option<String> {
    #[cfg(windows)]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "$u=(Get-CimInstance Win32_ComputerSystem).UserName; if (-not $u) { exit 1 }; ([System.Security.Principal.NTAccount]$u).Translate([System.Security.Principal.SecurityIdentifier]).Value",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout)
            .ok()
            .map(|sid| sid.trim().to_string())
            .filter(|sid| sid.starts_with("S-1-"))
    }

    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_sddl_does_not_grant_interactive_users() {
        let sddl = agent_pipe_sddl_for_user_sid(Some("S-1-5-21-1-2-3-1001"));

        assert!(sddl.contains("SY"));
        assert!(sddl.contains("BA"));
        assert!(sddl.contains("S-1-5-21-1-2-3-1001"));
        assert!(!sddl.contains(";;;IU"));
    }

    #[test]
    fn pipe_sddl_without_user_sid_is_system_and_admins_only() {
        let sddl = agent_pipe_sddl_for_user_sid(None);
        assert!(sddl.contains("SY"));
        assert!(sddl.contains("BA"));
        assert!(!sddl.contains(";;;IU"));
        assert!(!sddl.contains("S-1-5-21"));
    }
}

#[cfg(windows)]
fn read_pipe_line(handle: windows_sys::Win32::Foundation::HANDLE) -> anyhow::Result<String> {
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_BROKEN_PIPE, ERROR_NO_DATA},
        Storage::FileSystem::ReadFile,
    };

    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];
    let started = Instant::now();
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
                if started.elapsed() >= IPC_IDLE_READ_TIMEOUT {
                    anyhow::bail!("timed out waiting for agent command on named pipe");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            if error == ERROR_BROKEN_PIPE && !data.is_empty() {
                break;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read as usize]);
        if data.contains(&b'\n') {
            break;
        }
        if data.len() > 1024 * 1024 {
            anyhow::bail!("agent command exceeded maximum IPC frame size");
        }
        if started.elapsed() >= IPC_IDLE_READ_TIMEOUT {
            anyhow::bail!("timed out reading agent command frame");
        }
    }
    Ok(String::from_utf8(data)?
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

#[cfg(windows)]
fn write_pipe_response(
    handle: windows_sys::Win32::Foundation::HANDLE,
    response: AgentWireResponse,
) -> anyhow::Result<()> {
    let mut data = serde_json::to_vec(&response)?;
    data.push(b'\n');
    write_pipe_all(handle, &data)
}

#[cfg(windows)]
fn write_pipe_all(
    handle: windows_sys::Win32::Foundation::HANDLE,
    mut data: &[u8],
) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    while !data.is_empty() {
        let mut written = 0_u32;
        let chunk_len = data.len().min(u32::MAX as usize) as u32;
        let ok = unsafe {
            WriteFile(
                handle,
                data.as_ptr().cast(),
                chunk_len,
                &mut written,
                std::ptr::null_mut(),
            )
        } != 0;
        if !ok {
            return Err(std::io::Error::last_os_error().into());
        }
        data = &data[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
