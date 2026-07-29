//! Atomic Windows Job Object process creation.
//!
//! This is the workspace's only Win32 FFI capsule. A workload is created
//! suspended with `PROC_THREAD_ATTRIBUTE_JOB_LIST`, so the kernel places it in
//! the kill-on-close Job Object as part of `CreateProcessW`. There is no
//! child-bearing interval between process creation and containment. Callers
//! durably record the returned process ID and only then call
//! [`JobProcess::resume`].

#![cfg(windows)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_PARAMETER: u32 = 87;

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

    fn invalid(operation: &'static str) -> Self {
        Self {
            operation,
            code: ERROR_INVALID_PARAMETER,
        }
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

/// Complete creation specification for one atomically contained child.
pub struct SpawnSpec<'a> {
    pub program: &'a OsStr,
    pub arguments: &'a [OsString],
    /// Validated suffix appended without C-argv quoting (used by `cmd.exe`).
    pub raw_argument_suffix: Option<&'a OsStr>,
    pub environment: &'a BTreeMap<OsString, OsString>,
    pub current_directory: &'a Path,
    pub stdin: &'a File,
    pub stdout: &'a File,
    pub stderr: &'a File,
}

/// Owns a process created suspended and atomically inside a kill-on-close Job.
pub struct JobProcess {
    job: OwnedHandle,
    process: OwnedHandle,
    initial_thread: Option<OwnedHandle>,
    process_id: u32,
}

// SAFETY: Windows kernel handles are process-wide synchronized references.
// This type owns every handle and exposes no pointee memory.
unsafe impl Send for JobProcess {}
// SAFETY: Shared methods invoke only thread-safe query operations. Resume
// requires unique access and Drop retains unique ownership.
unsafe impl Sync for JobProcess {}

impl JobProcess {
    /// Creates a suspended workload with atomic Job-list membership.
    pub fn spawn_suspended(spec: &SpawnSpec<'_>) -> Result<Self, JobError> {
        let job = create_kill_on_close_job()?;
        let stdin = duplicate_inheritable(spec.stdin)?;
        let stdout = duplicate_inheritable(spec.stdout)?;
        let stderr = duplicate_inheritable(spec.stderr)?;
        let inherited = [stdin.handle, stdout.handle, stderr.handle];

        let mut attributes = AttributeList::new(2)?;
        attributes.set(
            usize::try_from(PROC_THREAD_ATTRIBUTE_JOB_LIST)
                .expect("Win32 attribute identifier fits usize"),
            (&raw const job.handle).cast(),
            size_of::<HANDLE>(),
            "UpdateProcThreadAttribute(JOB_LIST)",
        )?;
        attributes.set(
            usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                .expect("Win32 attribute identifier fits usize"),
            inherited.as_ptr().cast(),
            size_of_val(&inherited),
            "UpdateProcThreadAttribute(HANDLE_LIST)",
        )?;

        let resolved_program = resolve_program(spec)?;
        let application = wide_nul(&resolved_program, "program contains NUL")?;
        let mut command_line = command_line(spec)?;
        let current_directory = wide_nul(
            spec.current_directory.as_os_str(),
            "working directory contains NUL",
        )?;
        let environment = environment_block(spec.environment)?;

        // SAFETY: zero is the documented initial state for both POD Win32
        // structures. Every pointer below remains live through CreateProcessW.
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).expect("STARTUPINFOEXW size fits u32");
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin.handle;
        startup.StartupInfo.hStdOutput = stdout.handle;
        startup.StartupInfo.hStdError = stderr.handle;
        startup.lpAttributeList = attributes.pointer();
        // SAFETY: zero is the documented initial state. Successful creation
        // returns four owned scalar/handle values in this structure.
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };

        // SAFETY: application/current-directory/environment are terminated
        // UTF-16 buffers; command_line is mutable as required by CreateProcessW;
        // the startup pointer is layout-compatible because cb names the
        // extended structure; inherited handles are explicitly restricted by
        // HANDLE_LIST; JOB_LIST makes containment part of process creation.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                current_directory.as_ptr(),
                (&raw const startup.StartupInfo).cast(),
                &raw mut information,
            )
        };
        if created == 0 {
            return Err(JobError::last("CreateProcessW(JOB_LIST)"));
        }
        let process = OwnedHandle::new(information.hProcess, "CreateProcessW process handle")?;
        let initial_thread = OwnedHandle::new(information.hThread, "CreateProcessW thread handle")?;
        Ok(Self {
            job,
            process,
            initial_thread: Some(initial_thread),
            process_id: information.dwProcessId,
        })
    }

    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Resumes the exact initial thread after durable spawn recording.
    pub fn resume(&mut self) -> Result<(), JobError> {
        let thread = self
            .initial_thread
            .take()
            .ok_or_else(|| JobError::invalid("ResumeThread called more than once"))?;
        // SAFETY: the handle is the exact suspended initial thread returned by
        // CreateProcessW and has not previously been resumed.
        let previous = unsafe { ResumeThread(thread.handle) };
        if previous == u32::MAX {
            return Err(JobError::last("ResumeThread"));
        }
        Ok(())
    }

    /// Atomically terminates every process in the job.
    pub fn terminate(&self, exit_code: u32) -> Result<(), JobError> {
        // SAFETY: the Job handle remains live for self's lifetime.
        if unsafe { TerminateJobObject(self.job.handle, exit_code) } == 0 {
            Err(JobError::last("TerminateJobObject"))
        } else {
            Ok(())
        }
    }

    /// Returns the leader exit status when it is waitable.
    pub fn try_wait(&self) -> Result<Option<ExitStatus>, JobError> {
        // SAFETY: process handle is live; a zero timeout only observes state.
        match unsafe { WaitForSingleObject(self.process.handle, 0) } {
            WAIT_TIMEOUT => return Ok(None),
            WAIT_OBJECT_0 => {}
            WAIT_FAILED => return Err(JobError::last("WaitForSingleObject")),
            _ => return Err(JobError::invalid("WaitForSingleObject result")),
        }
        let mut code = 0;
        // SAFETY: process handle is live and code points to writable storage.
        if unsafe { GetExitCodeProcess(self.process.handle, &raw mut code) } == 0 {
            return Err(JobError::last("GetExitCodeProcess"));
        }
        Ok(Some(ExitStatus::from_raw(code)))
    }

    /// Returns the number of processes that remain members of the job.
    pub fn active_processes(&self) -> Result<u32, JobError> {
        // SAFETY: zero is the documented initial state for this POD structure.
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        // SAFETY: the Job handle is live and the information class, pointer,
        // and size all describe the accounting structure.
        let queried = unsafe {
            QueryInformationJobObject(
                self.job.handle,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
                    .expect("Win32 structure size fits u32"),
                null_mut(),
            )
        };
        if queried == 0 {
            Err(JobError::last("QueryInformationJobObject"))
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }
}

fn create_kill_on_close_job() -> Result<OwnedHandle, JobError> {
    // SAFETY: null security/name pointers request an anonymous Job with default
    // security. The checked result is immediately RAII-owned.
    let handle = unsafe { CreateJobObjectW(null(), null()) };
    let job = OwnedHandle::new(handle, "CreateJobObjectW")?;
    // SAFETY: zero is the documented initial state for this POD structure.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: Job handle and correctly sized limits structure are live.
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
        Err(JobError::last("SetInformationJobObject"))
    } else {
        Ok(job)
    }
}

fn resolve_program(spec: &SpawnSpec<'_>) -> Result<OsString, JobError> {
    let program = Path::new(spec.program);
    if program.is_absolute() {
        return Ok(program.as_os_str().to_owned());
    }
    if program.components().count() > 1 {
        return Ok(spec.current_directory.join(program).into_os_string());
    }

    let path = spec
        .environment
        .iter()
        .find(|(key, _)| normalized_environment_key(key) == "PATH")
        .map(|(_, value)| value.clone())
        .or_else(|| std::env::var_os("PATH"))
        .ok_or(JobError {
            operation: "resolve program from PATH",
            code: ERROR_FILE_NOT_FOUND,
        })?;
    let extensions: &[&str] = if program.extension().is_some() {
        &[""]
    } else {
        &["", ".exe", ".com"]
    };
    for directory in std::env::split_paths(&path) {
        for extension in extensions {
            let mut candidate = directory.join(program);
            if !extension.is_empty() {
                candidate.set_extension(extension.trim_start_matches('.'));
            }
            if candidate.is_file() {
                return Ok(candidate.into_os_string());
            }
        }
    }
    Err(JobError {
        operation: "resolve program from PATH",
        code: ERROR_FILE_NOT_FOUND,
    })
}

fn duplicate_inheritable(file: &File) -> Result<OwnedHandle, JobError> {
    let source: HANDLE = file.as_raw_handle().cast();
    let mut duplicated = null_mut();
    // SAFETY: current-process pseudo handles are valid; source comes from a
    // live File; target points to writable handle storage; same-access and
    // inherit=true are documented DuplicateHandle options.
    let current = unsafe { GetCurrentProcess() };
    let copied = unsafe {
        DuplicateHandle(
            current,
            source,
            current,
            &raw mut duplicated,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if copied == 0 {
        Err(JobError::last("DuplicateHandle"))
    } else {
        OwnedHandle::new(duplicated, "DuplicateHandle")
    }
}

fn command_line(spec: &SpawnSpec<'_>) -> Result<Vec<u16>, JobError> {
    let mut command = OsString::new();
    append_quoted_argument(&mut command, spec.program)?;
    for argument in spec.arguments {
        command.push(" ");
        append_quoted_argument(&mut command, argument)?;
    }
    if let Some(raw) = spec.raw_argument_suffix {
        if raw.encode_wide().any(|unit| unit == 0) {
            return Err(JobError::invalid("raw command suffix contains NUL"));
        }
        command.push(" ");
        command.push(raw);
    }
    wide_nul(&command, "command line contains NUL")
}

fn append_quoted_argument(command: &mut OsString, value: &OsStr) -> Result<(), JobError> {
    let units = value.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(JobError::invalid("command argument contains NUL"));
    }
    command.push("\"");
    let mut backslashes = 0;
    for unit in units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        if unit == u16::from(b'"') {
            push_backslashes(command, backslashes * 2 + 1);
            command.push(OsString::from_wide(&[unit]));
        } else {
            push_backslashes(command, backslashes);
            command.push(OsString::from_wide(&[unit]));
        }
        backslashes = 0;
    }
    push_backslashes(command, backslashes * 2);
    command.push("\"");
    Ok(())
}

fn push_backslashes(command: &mut OsString, count: usize) {
    if count > 0 {
        command.push(OsString::from_wide(&vec![u16::from(b'\\'); count]));
    }
}

fn environment_block(overrides: &BTreeMap<OsString, OsString>) -> Result<Vec<u16>, JobError> {
    let mut entries = BTreeMap::<String, (OsString, OsString)>::new();
    for (key, value) in std::env::vars_os() {
        entries.insert(normalized_environment_key(&key), (key, value));
    }
    for (key, value) in overrides {
        if key.is_empty()
            || key
                .encode_wide()
                .any(|unit| unit == 0 || unit == u16::from(b'='))
            || value.encode_wide().any(|unit| unit == 0)
        {
            return Err(JobError::invalid("environment contains invalid UTF-16"));
        }
        entries.insert(
            normalized_environment_key(key),
            (key.clone(), value.clone()),
        );
    }

    let mut block = Vec::new();
    for (_, (key, value)) in entries {
        block.extend(key.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn normalized_environment_key(key: &OsStr) -> String {
    key.to_string_lossy().to_uppercase()
}

fn wide_nul(value: &OsStr, operation: &'static str) -> Result<Vec<u16>, JobError> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(JobError::invalid(operation));
    }
    wide.push(0);
    Ok(wide)
}

struct AttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self, JobError> {
        let mut bytes = 0;
        // SAFETY: documented sizing call; null list is required and bytes
        // points to writable storage.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &raw mut bytes);
        }
        if bytes == 0 {
            return Err(JobError::last("InitializeProcThreadAttributeList(size)"));
        }
        let mut list = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        // SAFETY: storage is usize-aligned and at least the requested byte
        // length; pointer remains stable because the vector is never resized.
        if unsafe { InitializeProcThreadAttributeList(list.pointer(), count, 0, &raw mut bytes) }
            == 0
        {
            return Err(JobError::last("InitializeProcThreadAttributeList"));
        }
        list.initialized = true;
        Ok(list)
    }

    fn pointer(&mut self) -> *mut core::ffi::c_void {
        self.storage.as_mut_ptr().cast()
    }

    fn set(
        &mut self,
        attribute: usize,
        value: *const core::ffi::c_void,
        bytes: usize,
        operation: &'static str,
    ) -> Result<(), JobError> {
        // SAFETY: list was initialized for two attributes; caller-owned value
        // remains live through process creation; no previous value is needed.
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute,
                value,
                bytes,
                null_mut(),
                null(),
            )
        } == 0
        {
            Err(JobError::last(operation))
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was successfully initialized and its storage
        // remains allocated until this call returns.
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

struct OwnedHandle {
    handle: HANDLE,
}

impl OwnedHandle {
    fn new(handle: HANDLE, operation: &'static str) -> Result<Self, JobError> {
        if handle.is_null() {
            Err(JobError::last(operation))
        } else {
            Ok(Self { handle })
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OwnedHandle uniquely owns this non-null kernel handle.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
