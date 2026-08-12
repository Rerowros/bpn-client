//! Windows Job Object helpers so owned Mihomo/winws children die with the agent.

#[cfg(windows)]
mod windows_impl {
    use std::{
        mem,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::Child,
        ptr,
    };

    use anyhow::{Context, Result};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };

    #[derive(Debug)]
    pub struct ProcessJob {
        _handle: OwnedHandle,
    }

    impl ProcessJob {
        pub fn create_kill_on_close() -> Result<Self> {
            let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if raw.is_null() {
                return Err(std::io::Error::last_os_error())
                    .context("CreateJobObjectW failed for BadVpn process job");
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = unsafe {
                SetInformationJobObject(
                    handle.as_raw_handle() as HANDLE,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    mem::size_of_val(&info) as u32,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("SetInformationJobObject(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) failed");
            }
            Ok(Self { _handle: handle })
        }

        pub fn assign_child(&self, child: &Child) -> Result<()> {
            let process = child.as_raw_handle() as HANDLE;
            let ok = unsafe {
                AssignProcessToJobObject(self._handle.as_raw_handle() as HANDLE, process)
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("AssignProcessToJobObject failed for owned child");
            }
            Ok(())
        }
    }

    /// Best-effort: create a kill-on-close job and assign `child`.
    pub fn bind_child_to_kill_on_close_job(child: &Child) -> Option<ProcessJob> {
        match ProcessJob::create_kill_on_close() {
            Ok(job) => {
                if let Err(error) = job.assign_child(child) {
                    tracing::warn!(%error, "failed to assign child to Job Object");
                    None
                } else {
                    Some(job)
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed to create Job Object for owned child");
                None
            }
        }
    }
}

#[cfg(windows)]
pub use windows_impl::{bind_child_to_kill_on_close_job, ProcessJob};

#[cfg(not(windows))]
#[derive(Debug)]
pub struct ProcessJob;

#[cfg(not(windows))]
pub fn bind_child_to_kill_on_close_job(_child: &std::process::Child) -> Option<ProcessJob> {
    None
}
