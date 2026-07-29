//! Race-free Windows Job Object containment.
//!
//! This is the workspace's only Win32 FFI capsule. Callers create a child with
//! [`CREATE_SUSPENDED`], then call [`Job::attach`], durably record the process,
//! and call [`Job::resume`]. The process cannot create descendants before the
//! Job Object owns it or before the durable spawn record exists.

#![cfg(windows)]

use std::fmt;
use std::mem::{size_of, zeroed};
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr::null;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

/// Win32 process-creation flag required before attaching a child.
pub const CREATE_SUSPENDED: u32 = 0x0000_0004;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobError {
    operation: &'static str,
    code: u32,
}

impl JobError {
    fn last(operation: &'static str) -> Self {
        // SAFETY: GetLastError has no preconditions and reads thread-local
        // Win32 state immediately after the failed call.
        let code = unsafe { GetLastError() };
        Self { operation, code }
    }
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} failed with Win32 error {}",
            self.operation, self.code
        )
    }
}

impl std::error::Error for JobError {}

/// Owns an anonymous kill-on-close Job Object.
pub struct Job {
    handle: HANDLE,
    initial_thread: ThreadHandle,
}

impl Job {
    /// Creates a kill-on-close job and assigns a suspended child.
    pub fn attach(child: &Child) -> Result<Self, JobError> {
        let process_id = child.id();
        let process_handle = child.as_raw_handle().cast();

        // SAFETY: null security/name pointers request an anonymous job with
        // default security. The returned handle is checked and owned by Job.
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(JobError::last("CreateJobObjectW"));
        }
        let initial_thread = initial_thread(process_id)?;
        let job = Self {
            handle,
            initial_thread,
        };

        // SAFETY: zero is the documented initial state for this POD Win32
        // structure; its size and information class match.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: handle is live, pointer references the correctly sized
        // structure for JobObjectExtendedLimitInformation for this call.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .expect("Win32 structure size fits u32"),
            )
        };
        if configured == 0 {
            return Err(JobError::last("SetInformationJobObject"));
        }

        // SAFETY: both handles are live. The child is still suspended, so it
        // cannot create a descendant in the assignment window.
        if unsafe { AssignProcessToJobObject(job.handle, process_handle) } == 0 {
            return Err(JobError::last("AssignProcessToJobObject"));
        }

        Ok(job)
    }

    /// Resumes the initial thread after the caller has durably recorded the
    /// contained process identity.
    pub fn resume(&self) -> Result<(), JobError> {
        // SAFETY: thread was opened with THREAD_SUSPEND_RESUME and belongs to
        // the newly created suspended process.
        let previous = unsafe { ResumeThread(self.initial_thread.handle) };
        if previous == u32::MAX {
            return Err(JobError::last("ResumeThread"));
        }
        Ok(())
    }

    /// Atomically terminates every process in the job.
    pub fn terminate(&self, exit_code: u32) -> Result<(), JobError> {
        // SAFETY: handle remains live for self's lifetime.
        if unsafe { TerminateJobObject(self.handle, exit_code) } == 0 {
            Err(JobError::last("TerminateJobObject"))
        } else {
            Ok(())
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: Job uniquely owns this non-null handle. Kill-on-close makes
        // this the final no-orphan backstop on normal exit and service crash.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

struct ThreadHandle {
    handle: HANDLE,
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // SAFETY: ThreadHandle uniquely owns this non-null handle.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn initial_thread(process_id: u32) -> Result<ThreadHandle, JobError> {
    // SAFETY: documented snapshot call with no pointer arguments.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(JobError::last("CreateToolhelp32Snapshot"));
    }
    let snapshot = SnapshotHandle { handle: snapshot };

    // SAFETY: zero is the documented initial state; dwSize is set before use.
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize =
        u32::try_from(size_of::<THREADENTRY32>()).expect("Win32 structure size fits u32");
    // SAFETY: snapshot and entry are valid for the duration of the call.
    if unsafe { Thread32First(snapshot.handle, &raw mut entry) } == 0 {
        return Err(JobError::last("Thread32First"));
    }

    loop {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: thread ID came from the live snapshot; no inheritable
            // handle is requested.
            let handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if handle.is_null() {
                return Err(JobError::last("OpenThread"));
            }
            return Ok(ThreadHandle { handle });
        }
        // SAFETY: snapshot and entry remain valid.
        if unsafe { Thread32Next(snapshot.handle, &raw mut entry) } == 0 {
            return Err(JobError::last("Thread32Next"));
        }
    }
}

struct SnapshotHandle {
    handle: HANDLE,
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        // SAFETY: SnapshotHandle uniquely owns the ToolHelp snapshot.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
