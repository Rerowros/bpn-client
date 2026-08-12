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

    /// Create a kill-on-close job and assign `child`. Callers must treat failure as
    /// a startup failure because an unbound networking child can outlive the agent.
    pub fn bind_child_to_kill_on_close_job(child: &Child) -> Result<ProcessJob> {
        let job = ProcessJob::create_kill_on_close()?;
        job.assign_child(child)?;
        Ok(job)
    }
}

#[cfg(windows)]
pub use windows_impl::{bind_child_to_kill_on_close_job, ProcessJob};

#[cfg(not(windows))]
#[derive(Debug)]
pub struct ProcessJob;

#[cfg(not(windows))]
pub fn bind_child_to_kill_on_close_job(_child: &std::process::Child) -> anyhow::Result<ProcessJob> {
    // Job Objects are Windows-specific. Keep non-Windows development builds usable;
    // platform-specific child containment must be added before a non-Windows release.
    Ok(ProcessJob)
}
