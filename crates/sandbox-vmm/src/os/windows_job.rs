//! Windows process confinement: RAII Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`),
//! atomic `CreateProcessW` attachment (`PROC_THREAD_ATTRIBUTE_JOB_LIST` +
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), `GetProcessTimes` start tokens, and verified orphan
//! termination.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use sandbox_core::SandboxError;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
    FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW,
};

use crate::accel::classify_launch_error;
use crate::os::windows::{to_wide_null, win32_error, OwnedHandle};
use crate::process::{
    ProcessExitStatus, ProcessLaunchSpec, ProcessStartIdentity, ProcessStdio,
};

pub use crate::process::quote_windows_command_line;

pub(crate) type PlatformConfinedProcess = WindowsConfinedProcess;

const ORPHAN_TERMINATE_WAIT_MS: u32 = 10_000;

/// RAII Win32 Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
///
/// Dropping this handle instructs the Windows kernel to terminate all processes (including any
/// spawned descendants) assigned to the job.
pub struct WindowsJobObject {
    handle: OwnedHandle,
}

// SAFETY: Win32 Job Object kernel handles are safe to transfer and reference across threads;
// handle closing happens once in `Drop` with exclusive `&mut self` access.
unsafe impl Send for WindowsJobObject {}
// SAFETY: Shared references only expose the raw kernel handle value; mutations/destruction
// require ownership or `&mut self`.
unsafe impl Sync for WindowsJobObject {}

impl WindowsJobObject {
    /// Creates an anonymous Win32 Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` set.
    pub fn new_kill_on_close() -> Result<Self, SandboxError> {
        // SAFETY: Null security attributes and null name create a private anonymous Job Object.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        let handle = OwnedHandle::from_raw(raw).map_err(|err| {
            SandboxError::Internal(format!("CreateJobObjectW failed: {err}"))
        })?;

        // SAFETY: `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` is POD; zeroing initializes reserved fields.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // SAFETY: `handle` is an open Job Object; `info` matches `JobObjectExtendedLimitInformation`.
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(win32_error("SetInformationJobObject(KILL_ON_JOB_CLOSE)"));
        }

        Ok(Self { handle })
    }

    /// Returns the underlying Win32 Job Object `HANDLE`.
    pub fn as_raw_handle(&self) -> HANDLE {
        self.handle.as_raw()
    }
}

struct ProcThreadAttrList {
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
    _backing: Vec<usize>,
}

impl ProcThreadAttrList {
    fn new(attribute_count: u32) -> Result<Self, SandboxError> {
        let mut size: usize = 0;
        // SAFETY: Probing required buffer byte size with null list pointer.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), attribute_count, 0, &mut size);
        }
        if size == 0 {
            return Err(win32_error("InitializeProcThreadAttributeList(size probe)"));
        }

        // Align backing storage to pointer width as required for `LPPROC_THREAD_ATTRIBUTE_LIST`.
        let words = size.div_ceil(size_of::<usize>());
        let mut backing = vec![0usize; words];
        let list_ptr = backing.as_mut_ptr().cast::<c_void>() as LPPROC_THREAD_ATTRIBUTE_LIST;

        // SAFETY: `backing` provides `size` aligned bytes for `attribute_count` attributes.
        let ok = unsafe {
            InitializeProcThreadAttributeList(list_ptr, attribute_count, 0, &mut size)
        };
        if ok == 0 {
            return Err(win32_error("InitializeProcThreadAttributeList"));
        }

        Ok(Self {
            ptr: list_ptr,
            _backing: backing,
        })
    }

    fn update_job_list(&mut self, job_handles: &mut [HANDLE]) -> Result<(), SandboxError> {
        // SAFETY: `self.ptr` is initialized; caller keeps `job_handles` alive until after `Drop`.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                job_handles.as_ptr().cast(),
                size_of_val(job_handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(win32_error(
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_JOB_LIST)",
            ));
        }
        Ok(())
    }

    fn update_handle_list(&mut self, handles: &mut [HANDLE]) -> Result<(), SandboxError> {
        debug_assert!(!handles.is_empty());
        // SAFETY: `self.ptr` is initialized; `handles` is non-empty and outlives `self`.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(win32_error(
                "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)",
            ));
        }
        Ok(())
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.ptr
    }
}

impl Drop for ProcThreadAttrList {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `self.ptr` was initialized by `InitializeProcThreadAttributeList` and `_backing` is still live.
            unsafe {
                DeleteProcThreadAttributeList(self.ptr);
            }
        }
    }
}

/// Low-level Win32 process launch configuration for [`spawn_in_job_with_handle_whitelist`].
#[derive(Debug)]
pub struct WindowsSpawnSpec<'a> {
    pub program: &'a Path,
    pub args: &'a [OsString],
    pub current_dir: Option<&'a Path>,
    pub stdin: Option<HANDLE>,
    pub stdout: Option<HANDLE>,
    pub stderr: Option<HANDLE>,
    pub inherited_handles: &'a [HANDLE],
    pub create_no_window: bool,
}

/// Windows child process confined inside an owned [`WindowsJobObject`].
pub struct WindowsConfinedProcess {
    job: Option<WindowsJobObject>,
    process: OwnedHandle,
    identity: ProcessStartIdentity,
    exited: Option<ProcessExitStatus>,
}

// SAFETY: `WindowsJobObject` and `OwnedHandle` wrap thread-safe Win32 kernel handles; all state
// transitions require `&mut self` or exclusive ownership in `Drop`.
unsafe impl Send for WindowsConfinedProcess {}
// SAFETY: Shared references only inspect immutable `ProcessStartIdentity` (`Copy` values).
unsafe impl Sync for WindowsConfinedProcess {}

impl WindowsConfinedProcess {
    /// Returns the Win32 process ID (`dwProcessId`).
    pub fn id(&self) -> u32 {
        self.identity.pid
    }

    /// Returns the PID and `GetProcessTimes` creation timestamp token.
    pub fn start_identity(&self) -> ProcessStartIdentity {
        self.identity
    }

    /// Non-blocking check for process exit.
    pub fn try_wait(&mut self) -> Result<Option<ProcessExitStatus>, SandboxError> {
        if let Some(status) = self.exited {
            return Ok(Some(status));
        }
        self.wait_timeout(Duration::ZERO)
    }

    /// Waits up to `timeout` in the kernel via `WaitForSingleObject` for process exit.
    pub fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProcessExitStatus>, SandboxError> {
        if let Some(status) = self.exited {
            return Ok(Some(status));
        }
        let timeout_ms = duration_to_wait_ms(timeout);
        // SAFETY: `self.process.as_raw()` is an open Win32 process handle with `SYNCHRONIZE`.
        let wait = unsafe { WaitForSingleObject(self.process.as_raw(), timeout_ms) };
        match wait {
            WAIT_OBJECT_0 => self.read_exit_status().map(Some),
            WAIT_TIMEOUT => Ok(None),
            _ => Err(win32_error("WaitForSingleObject(process)")),
        }
    }

    /// Terminates the entire Job Object tree and waits for the primary process handle to exit.
    pub fn kill_and_wait(&mut self) -> Result<(), SandboxError> {
        if let Some(job) = self.job.as_ref() {
            // SAFETY: `job.as_raw_handle()` is an open Job Object handle.
            let ok = unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if self.try_wait()?.is_none() {
                    return Err(SandboxError::Internal(format!(
                        "TerminateJobObject failed: {err}"
                    )));
                }
            }
        }
        if self.exited.is_none() {
            // SAFETY: `self.process.as_raw()` is an open process handle with `SYNCHRONIZE`.
            let wait = unsafe { WaitForSingleObject(self.process.as_raw(), INFINITE) };
            if wait != WAIT_OBJECT_0 {
                return Err(win32_error("WaitForSingleObject(kill_and_wait)"));
            }
            let _ = self.read_exit_status()?;
        }
        Ok(())
    }

    fn read_exit_status(&mut self) -> Result<ProcessExitStatus, SandboxError> {
        let mut code: u32 = 0;
        // SAFETY: `self.process.as_raw()` already signaled in `WaitForSingleObject`, so `code` is final.
        let ok = unsafe { GetExitCodeProcess(self.process.as_raw(), &mut code) };
        if ok == 0 {
            return Err(win32_error("GetExitCodeProcess"));
        }
        let status = ProcessExitStatus::Exited(code as i32);
        self.exited = Some(status);
        Ok(status)
    }
}

impl Drop for WindowsConfinedProcess {
    fn drop(&mut self) {
        if self.exited.is_none() {
            let _ = self.kill_and_wait();
        } else if let Some(job) = self.job.as_ref() {
            // Terminate any lingering descendant inside the job before closing the handle.
            // SAFETY: `job.as_raw_handle()` is an open Job Object handle.
            unsafe {
                TerminateJobObject(job.as_raw_handle(), 1);
            }
        }
        self.job.take();
    }
}

/// Spawns a Windows child process atomically attached to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
/// Job Object and restricted to inherit ONLY the explicit `handle_list` (if non-empty).
///
/// When no stdio or extra handles are provided, passes `bInheritHandles = FALSE` and omits
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (Win32 rejects a zero-length handle list).
pub fn spawn_in_job_with_handle_whitelist(
    spec: &WindowsSpawnSpec<'_>,
) -> Result<WindowsConfinedProcess, SandboxError> {
    spawn_in_job_internal(spec, None)
}

pub(crate) fn spawn_in_job_internal(
    spec: &WindowsSpawnSpec<'_>,
    unicode_env_block: Option<&[u16]>,
) -> Result<WindowsConfinedProcess, SandboxError> {
    let wide_program = to_wide_null(spec.program.as_os_str())?;
    let mut wide_cmdline = quote_windows_command_line(spec.program, spec.args)?;
    let wide_cwd = spec
        .current_dir
        .map(|dir| to_wide_null(dir.as_os_str()))
        .transpose()?;

    let mut handle_list = collect_whitelisted_handles(spec)?;
    let job = WindowsJobObject::new_kill_on_close()?;
    // `job_handles` and `handle_list` MUST outlive `attr_list` (DeleteProcThreadAttributeList).
    let mut job_handles = [job.as_raw_handle()];

    let attr_count = if handle_list.is_empty() { 1 } else { 2 };
    let mut attr_list = ProcThreadAttrList::new(attr_count)?;
    attr_list.update_job_list(&mut job_handles)?;
    if !handle_list.is_empty() {
        attr_list.update_handle_list(&mut handle_list)?;
    }

    // SAFETY: `STARTUPINFOEXW` is POD; `cb` is set to its exact byte size.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attr_list.as_ptr();

    if spec.stdin.is_some() || spec.stdout.is_some() || spec.stderr.is_some() {
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = spec.stdin.unwrap_or(INVALID_HANDLE_VALUE);
        startup.StartupInfo.hStdOutput = spec.stdout.unwrap_or(INVALID_HANDLE_VALUE);
        startup.StartupInfo.hStdError = spec.stderr.unwrap_or(INVALID_HANDLE_VALUE);
    }

    let b_inherit_handles = if handle_list.is_empty() { 0 } else { 1 };
    let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if spec.create_no_window {
        creation_flags |= CREATE_NO_WINDOW;
    }
    let env_ptr = match unicode_env_block {
        Some(block) => {
            creation_flags |= CREATE_UNICODE_ENVIRONMENT;
            block.as_ptr().cast::<c_void>()
        }
        None => ptr::null(),
    };
    let cwd_ptr = wide_cwd.as_ref().map_or(ptr::null(), |v| v.as_ptr());

    // SAFETY: `PROCESS_INFORMATION` is POD written by `CreateProcessW`.
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: All wide pointers are NUL-terminated and live through `CreateProcessW`; `startup`
    // begins with `STARTUPINFOW` (`cb = size_of::<STARTUPINFOEXW>()`), paired with
    // `EXTENDED_STARTUPINFO_PRESENT`, and `job_handles`/`handle_list` outlive `attr_list`.
    let ok = unsafe {
        CreateProcessW(
            wide_program.as_ptr(),
            wide_cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            b_inherit_handles,
            creation_flags,
            env_ptr,
            cwd_ptr,
            &startup.StartupInfo as *const STARTUPINFOW,
            &mut pi,
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        return Err(classify_launch_error(spec.program, &err));
    }

    let _thread_handle = OwnedHandle::from_raw(pi.hThread)?;
    let process_handle = OwnedHandle::from_raw(pi.hProcess)?;
    let start_token = query_process_creation_time(process_handle.as_raw())?;

    Ok(WindowsConfinedProcess {
        job: Some(job),
        process: process_handle,
        identity: ProcessStartIdentity {
            pid: pi.dwProcessId,
            start_token,
        },
        exited: None,
    })
}

pub(crate) fn spawn_confined(spec: ProcessLaunchSpec) -> Result<WindowsConfinedProcess, SandboxError> {
    let redirect_stdio = !matches!(
        (&spec.stdin, &spec.stdout, &spec.stderr),
        (ProcessStdio::Null, ProcessStdio::Null, ProcessStdio::Null)
    );

    let mut owned_stdio_handles: Vec<OwnedHandle> = Vec::new();
    let (stdin_h, stdout_h, stderr_h) = if redirect_stdio {
        let stdin_owned = resolve_stdio_handle(&spec.stdin, true)?;
        let stdout_owned = resolve_stdio_handle(&spec.stdout, false)?;
        let stderr_owned = resolve_stdio_handle(&spec.stderr, false)?;
        let handles = (
            Some(stdin_owned.as_raw()),
            Some(stdout_owned.as_raw()),
            Some(stderr_owned.as_raw()),
        );
        owned_stdio_handles.push(stdin_owned);
        owned_stdio_handles.push(stdout_owned);
        owned_stdio_handles.push(stderr_owned);
        handles
    } else {
        (None, None, None)
    };

    let win_spec = WindowsSpawnSpec {
        program: &spec.program,
        args: &spec.args,
        current_dir: spec.current_dir.as_deref(),
        stdin: stdin_h,
        stdout: stdout_h,
        stderr: stderr_h,
        inherited_handles: &[],
        create_no_window: true,
    };
    spawn_in_job_with_handle_whitelist(&win_spec)
}

/// Verifies `GetProcessTimes` `ftCreationTime` matches `expected_start_token` before calling
/// `TerminateProcess` + `WaitForSingleObject` on an orphaned Windows process.
pub fn kill_verified_orphan_process(
    pid: u32,
    expected_start_token: u64,
) -> Result<bool, SandboxError> {
    if pid == 0 || expected_start_token == 0 || pid == std::process::id() {
        return Ok(false);
    }

    // SAFETY: Requests query + terminate + wait rights on target PID.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code == ERROR_INVALID_PARAMETER as i32 => Ok(false),
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => {
                // Distinguish PID reuse by a protected/system process from true same-process denial.
                // SAFETY: Probes read-only limited query access on `pid`.
                let probe_raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                if probe_raw.is_null() {
                    return Ok(false);
                }
                let probe = OwnedHandle::from_raw(probe_raw)?;
                let actual = query_process_creation_time(probe.as_raw())?;
                if actual != expected_start_token {
                    Ok(false)
                } else {
                    Err(SandboxError::Internal(format!(
                        "OpenProcess({pid}) denied PROCESS_TERMINATE on matching start token: {err}"
                    )))
                }
            }
            _ => Err(SandboxError::Internal(format!(
                "OpenProcess({pid}) failed: {err}"
            ))),
        };
    }

    let handle = OwnedHandle::from_raw(raw)?;
    // SAFETY: `handle` is open with `PROCESS_SYNCHRONIZE`.
    if unsafe { WaitForSingleObject(handle.as_raw(), 0) } == WAIT_OBJECT_0 {
        return Ok(false);
    }

    let actual_start_token = query_process_creation_time(handle.as_raw())?;
    if actual_start_token != expected_start_token {
        return Ok(false);
    }

    // SAFETY: `handle` is verified against `expected_start_token` and opened with `PROCESS_TERMINATE`.
    let terminated = unsafe { TerminateProcess(handle.as_raw(), 1) };
    if terminated == 0 {
        let err = io::Error::last_os_error();
        // SAFETY: On Windows, `TerminateProcess` returns `ERROR_ACCESS_DENIED` if the target just exited.
        if err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
            && unsafe { WaitForSingleObject(handle.as_raw(), 0) } == WAIT_OBJECT_0
        {
            return Ok(false);
        }
        return Err(SandboxError::Internal(format!(
            "TerminateProcess({pid}) failed: {err}"
        )));
    }

    // SAFETY: `handle` is open with `PROCESS_SYNCHRONIZE`.
    let wait = unsafe { WaitForSingleObject(handle.as_raw(), ORPHAN_TERMINATE_WAIT_MS) };
    if wait != WAIT_OBJECT_0 {
        return Err(SandboxError::Internal(format!(
            "WaitForSingleObject({pid}) after TerminateProcess returned status {wait}"
        )));
    }

    Ok(true)
}

fn collect_whitelisted_handles(spec: &WindowsSpawnSpec<'_>) -> Result<Vec<HANDLE>, SandboxError> {
    let mut list: Vec<HANDLE> = Vec::with_capacity(3 + spec.inherited_handles.len());
    for maybe_h in [spec.stdin, spec.stdout, spec.stderr] {
        if let Some(h) = maybe_h {
            validate_inheritable_handle(h)?;
            push_unique_handle(&mut list, h);
        }
    }
    for &h in spec.inherited_handles {
        validate_inheritable_handle(h)?;
        push_unique_handle(&mut list, h);
    }
    Ok(list)
}

fn validate_inheritable_handle(handle: HANDLE) -> Result<(), SandboxError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(SandboxError::InvalidSpec(
            "whitelisted Windows handle must not be null or INVALID_HANDLE_VALUE".to_owned(),
        ));
    }
    Ok(())
}

fn push_unique_handle(list: &mut Vec<HANDLE>, handle: HANDLE) {
    if !list.contains(&handle) {
        list.push(handle);
    }
}

fn resolve_stdio_handle(stdio: &ProcessStdio, is_stdin: bool) -> Result<OwnedHandle, SandboxError> {
    match stdio {
        ProcessStdio::Null => open_inheritable_nul(is_stdin),
        ProcessStdio::File(file) => duplicate_inheritable_handle(file),
    }
}

fn duplicate_inheritable_handle(file: &File) -> Result<OwnedHandle, SandboxError> {
    let mut dup: HANDLE = ptr::null_mut();
    let src = file.as_raw_handle() as HANDLE;
    // SAFETY: `GetCurrentProcess()` is a pseudo-handle; `src` is a live open handle borrowed from `file`.
    let ok = unsafe {
        let cur = GetCurrentProcess();
        DuplicateHandle(cur, src, cur, &mut dup, 0, 1, DUPLICATE_SAME_ACCESS)
    };
    if ok == 0 {
        return Err(win32_error("DuplicateHandle(inheritable stdio)"));
    }
    OwnedHandle::from_raw(dup)
}

fn open_inheritable_nul(for_read: bool) -> Result<OwnedHandle, SandboxError> {
    let wide_nul = to_wide_null(OsStr::new(r"\\.\NUL"))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let access = if for_read { GENERIC_READ } else { GENERIC_WRITE };
    // SAFETY: `wide_nul` is NUL-terminated and `sa` lives through `CreateFileW`.
    let raw = unsafe {
        CreateFileW(
            wide_nul.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    OwnedHandle::from_raw(raw).map_err(|err| {
        SandboxError::Transport(format!("CreateFileW(\\\\.\\NUL) failed: {err}"))
    })
}

fn query_process_creation_time(handle: HANDLE) -> Result<u64, SandboxError> {
    // SAFETY: `FILETIME` is POD output storage for `GetProcessTimes`.
    let (mut creation, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    // SAFETY: `handle` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`.
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if ok == 0 {
        return Err(win32_error("GetProcessTimes"));
    }
    Ok(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
}

fn duration_to_wait_ms(timeout: Duration) -> u32 {
    timeout.as_millis().min((INFINITE - 1) as u128) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;
    use std::os::windows::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, ERROR_INVALID_HANDLE,
    };
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    const ROLE_ENV: &str = "MINIPOD_PROCESS_TEST_ROLE";
    const HANDLE_PROBE_ENV: &str = "MINIPOD_TEST_HANDLE_PROBE";
    const HELPER_TEST_NAME: &str = "os::windows_job::tests::__confined_process_test_helper";

    struct CleanupDir(std::path::PathBuf);

    impl CleanupDir {
        fn new(prefix: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "mp-winjob-{prefix}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }
    }

    impl Drop for CleanupDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn build_unicode_env_block(overrides: &[(&str, &str)]) -> Vec<u16> {
        let mut pairs: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| {
                !overrides
                    .iter()
                    .any(|(ok, _)| k.to_string_lossy().eq_ignore_ascii_case(ok))
            })
            .collect();
        for (k, v) in overrides {
            pairs.push((OsString::from(k), OsString::from(v)));
        }
        pairs.sort_by(|(a, _), (b, _)| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));

        let mut block = Vec::new();
        for (k, v) in pairs {
            block.extend(k.encode_wide());
            block.push(b'=' as u16);
            block.extend(v.encode_wide());
            block.push(0);
        }
        block.push(0);
        block
    }

    fn helper_args() -> Vec<OsString> {
        vec![
            OsString::from("--exact"),
            OsString::from(HELPER_TEST_NAME),
            OsString::from("--nocapture"),
        ]
    }

    fn create_inheritable_pipe() -> (OwnedHandle, OwnedHandle) {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut read_h: HANDLE = ptr::null_mut();
        let mut write_h: HANDLE = ptr::null_mut();
        // SAFETY: Valid pointers and inheritable `SECURITY_ATTRIBUTES`.
        let ok = unsafe { CreatePipe(&mut read_h, &mut write_h, &sa, 4096) };
        assert_ne!(ok, 0, "CreatePipe failed: {}", io::Error::last_os_error());
        (
            OwnedHandle::from_raw(read_h).expect("pipe read handle"),
            OwnedHandle::from_raw(write_h).expect("pipe write handle"),
        )
    }

    fn read_file_handle_to_end(handle: &OwnedHandle) -> Vec<u8> {
        use windows_sys::Win32::Storage::FileSystem::ReadFile;
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let mut n: u32 = 0;
            // SAFETY: `handle` is an open readable pipe handle and `buf` is valid stack storage.
            let ok = unsafe {
                ReadFile(
                    handle.as_raw(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut n,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        out
    }

    fn is_pid_alive(pid: u32) -> bool {
        // SAFETY: Queries existence/status of `pid`.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            return false;
        }
        let handle = match OwnedHandle::from_raw(raw) {
            Ok(h) => h,
            Err(_) => return false,
        };
        // SAFETY: `handle` is valid with `PROCESS_SYNCHRONIZE`.
        unsafe { WaitForSingleObject(handle.as_raw(), 0) == WAIT_TIMEOUT }
    }

    #[test]
    fn __confined_process_test_helper() {
        let Ok(role) = std::env::var(ROLE_ENV) else {
            return;
        };
        match role.as_str() {
            "sleep" => {
                std::thread::sleep(Duration::from_secs(20));
            }
            "sleep_with_grandchild" => {
                let exe = std::env::current_exe().expect("current_exe");
                let mut child = Command::new(&exe)
                    .args(["--exact", HELPER_TEST_NAME, "--nocapture"])
                    .env(ROLE_ENV, "sleep")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn grandchild sleeper");
                println!("GRANDCHILD_PID={}", child.id());
                let _ = io::stdout().flush();
                std::thread::sleep(Duration::from_secs(20));
                let _ = child.kill();
                let _ = child.wait();
            }
            "probe_handles" => {
                let spec = std::env::var(HANDLE_PROBE_ENV).expect("HANDLE_PROBE_ENV set");
                let mut parts = spec.split(',');
                let allowed_raw: usize = parts.next().unwrap().parse().unwrap();
                let denied_raw: usize = parts.next().unwrap().parse().unwrap();
                let allowed = allowed_raw as HANDLE;
                let denied = denied_raw as HANDLE;

                let mut flags: u32 = 0;
                // SAFETY: Checking whether kernel inherited `allowed` into child handle table.
                let allowed_ok = unsafe { GetHandleInformation(allowed, &mut flags) };
                assert_ne!(allowed_ok, 0, "whitelisted handle must exist in child");

                let mut written: u32 = 0;
                let msg_a = b"PASS_A";
                // SAFETY: Writing to verified whitelisted pipe handle.
                let write_a = unsafe {
                    WriteFile(
                        allowed,
                        msg_a.as_ptr(),
                        msg_a.len() as u32,
                        &mut written,
                        ptr::null_mut(),
                    )
                };
                assert_ne!(write_a, 0, "WriteFile to whitelisted handle must succeed");
                assert_eq!(written as usize, msg_a.len());

                // SAFETY: Probing non-whitelisted handle MUST fail with ERROR_INVALID_HANDLE.
                let denied_ok = unsafe { GetHandleInformation(denied, &mut flags) };
                let denied_info_err = io::Error::last_os_error().raw_os_error();
                assert_eq!(denied_ok, 0, "non-whitelisted handle must NOT be inherited");
                assert_eq!(denied_info_err, Some(ERROR_INVALID_HANDLE as i32));

                let msg_b = b"FAIL_B";
                // SAFETY: Probing WriteFile on non-whitelisted handle MUST fail with ERROR_INVALID_HANDLE.
                let write_b = unsafe {
                    WriteFile(
                        denied,
                        msg_b.as_ptr(),
                        msg_b.len() as u32,
                        &mut written,
                        ptr::null_mut(),
                    )
                };
                let write_b_err = io::Error::last_os_error().raw_os_error();
                assert_eq!(write_b, 0);
                assert_eq!(write_b_err, Some(ERROR_INVALID_HANDLE as i32));

                let ack = b"|B_DENIED";
                // SAFETY: Reporting denied verification back through whitelisted pipe A.
                let ack_ok = unsafe {
                    WriteFile(
                        allowed,
                        ack.as_ptr(),
                        ack.len() as u32,
                        &mut written,
                        ptr::null_mut(),
                    )
                };
                assert_ne!(ack_ok, 0);
            }
            other => panic!("unexpected {ROLE_ENV} value: {other}"),
        }
    }

    #[test]
    fn proc_thread_attribute_handle_list_blocks_non_whitelisted_handles_in_kernel() {
        let exe = std::env::current_exe().expect("current_exe");
        let args = helper_args();

        let (read_a, write_a) = create_inheritable_pipe();
        let (read_b, write_b) = create_inheritable_pipe();

        let probe_val = format!(
            "{},{}",
            write_a.as_raw() as usize,
            write_b.as_raw() as usize
        );
        let env_block = build_unicode_env_block(&[
            (ROLE_ENV, "probe_handles"),
            (HANDLE_PROBE_ENV, &probe_val),
        ]);

        let inherited = [write_a.as_raw()];
        let spec = WindowsSpawnSpec {
            program: &exe,
            args: &args,
            current_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            inherited_handles: &inherited,
            create_no_window: true,
        };
        let mut child =
            spawn_in_job_internal(&spec, Some(&env_block)).expect("spawn probe child");

        // Drop parent write ends so pipe reads observe EOF once child finishes.
        drop(write_a);
        drop(write_b);

        let status = child
            .wait_timeout(Duration::from_secs(10))
            .expect("wait for handle probe child")
            .expect("handle probe child should exit within 10s");
        assert!(status.success(), "child probe failed with {status}");

        let got_a = read_file_handle_to_end(&read_a);
        let got_b = read_file_handle_to_end(&read_b);
        assert_eq!(got_a, b"PASS_A|B_DENIED");
        assert!(got_b.is_empty(), "non-whitelisted pipe B received unexpected bytes: {got_b:?}");
    }

    #[test]
    fn dropping_confined_process_kills_child_and_grandchild_via_job_object() {
        let dir = CleanupDir::new("jobdrop");
        let out_path = dir.0.join("grandchild-pid.txt");
        let out_file = File::create(&out_path).expect("create stdout redirect file");
        let out_dup = duplicate_inheritable_handle(&out_file).expect("dup stdout file");
        let nul_in = open_inheritable_nul(true).expect("open NUL stdin");
        let nul_err = open_inheritable_nul(false).expect("open NUL stderr");
        drop(out_file);

        let exe = std::env::current_exe().expect("current_exe");
        let args = helper_args();
        let env_block = build_unicode_env_block(&[(ROLE_ENV, "sleep_with_grandchild")]);

        let spec = WindowsSpawnSpec {
            program: &exe,
            args: &args,
            current_dir: None,
            stdin: Some(nul_in.as_raw()),
            stdout: Some(out_dup.as_raw()),
            stderr: Some(nul_err.as_raw()),
            inherited_handles: &[],
            create_no_window: true,
        };
        let confined = spawn_in_job_internal(&spec, Some(&env_block))
            .expect("spawn confined sleep_with_grandchild");
        drop(out_dup);
        drop(nul_in);
        drop(nul_err);

        let child_pid = confined.id();
        assert_ne!(confined.start_identity().start_token, 0);

        let mut grandchild_pid: Option<u32> = None;
        for _ in 0..100 {
            if let Ok(text) = fs::read_to_string(&out_path) {
                if let Some(pid) = text
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("GRANDCHILD_PID="))
                    .and_then(|s| s.parse::<u32>().ok())
                {
                    grandchild_pid = Some(pid);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let grandchild_pid = grandchild_pid.unwrap_or_else(|| {
            let content = fs::read_to_string(&out_path).unwrap_or_default();
            panic!("child should report grandchild PID; stdout file contents: {content:?}");
        });
        assert!(is_pid_alive(child_pid), "child PID {child_pid} must be alive");
        assert!(
            is_pid_alive(grandchild_pid),
            "grandchild PID {grandchild_pid} must be alive"
        );

        // Dropping ConfinedProcess must kill BOTH child and grandchild via Job Object + wait.
        drop(confined);

        assert!(
            !is_pid_alive(child_pid),
            "child PID {child_pid} must be terminated on Drop"
        );
        // Wait briefly for OS handle teardown of grandchild if async within Job Object close.
        for _ in 0..40 {
            if !is_pid_alive(grandchild_pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(
            !is_pid_alive(grandchild_pid),
            "grandchild PID {grandchild_pid} must be terminated by Job Object on Drop"
        );
    }

    #[test]
    fn kill_verified_orphan_process_enforces_start_token_match() {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(&exe)
            .args(["--exact", HELPER_TEST_NAME, "--nocapture"])
            .env(ROLE_ENV, "sleep")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn standalone sleeper for orphan kill test");
        let pid = child.id();

        // SAFETY: Query-only open to capture real `GetProcessTimes` creation token.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let handle = OwnedHandle::from_raw(raw).expect("open spawned sleeper");
        let real_token = query_process_creation_time(handle.as_raw()).expect("read creation time");
        drop(handle);

        // Mismatched start token or zero token MUST refuse to kill and leave process running.
        assert_eq!(kill_verified_orphan_process(pid, real_token ^ 1), Ok(false));
        assert_eq!(kill_verified_orphan_process(pid, 0), Ok(false));
        assert_eq!(kill_verified_orphan_process(0, real_token), Ok(false));
        assert_eq!(
            kill_verified_orphan_process(std::process::id(), real_token),
            Ok(false)
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "mismatched start token must leave child running"
        );

        // Matching start token MUST kill and wait cleanly.
        assert_eq!(kill_verified_orphan_process(pid, real_token), Ok(true));
        let status = child.wait().expect("reap killed child");
        assert!(!status.success());

        // Calling again after process exited and was reaped returns Ok(false).
        assert_eq!(kill_verified_orphan_process(pid, real_token), Ok(false));
    }

    #[test]
    fn confined_process_invalid_whitelisted_handle_is_rejected() {
        let exe = std::env::current_exe().expect("current_exe");
        let args = helper_args();
        let bad = [INVALID_HANDLE_VALUE];
        let spec = WindowsSpawnSpec {
            program: &exe,
            args: &args,
            current_dir: None,
            stdin: None,
            stdout: None,
            stderr: None,
            inherited_handles: &bad,
            create_no_window: true,
        };
        assert!(matches!(
            spawn_in_job_with_handle_whitelist(&spec),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn confined_process_spawn_handles_null_and_redirected_stderr_and_exit_codes() {
        let comspec = std::env::var_os("COMSPEC")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\System32\cmd.exe"));

        // 1. All Null stdio -> omits PROC_THREAD_ATTRIBUTE_HANDLE_LIST, captures non-zero exit code.
        let mut null_proc = crate::process::ConfinedProcess::spawn(ProcessLaunchSpec::new(
            &comspec,
            vec!["/D".into(), "/C".into(), "exit".into(), "42".into()],
        ))
        .expect("spawn cmd.exe with Null stdio");
        assert_ne!(null_proc.id(), 0);
        assert_ne!(null_proc.start_identity().start_token, 0);
        let status = null_proc
            .wait_timeout(Duration::from_secs(5))
            .expect("wait for cmd exit 42");
        assert_eq!(status, Some(ProcessExitStatus::Exited(42)));
        // Idempotent try_wait returns cached exit status.
        assert_eq!(
            null_proc.try_wait().expect("idempotent try_wait"),
            Some(ProcessExitStatus::Exited(42))
        );

        // 2. Redirected stderr file -> duplicates inheritable handle + NUL handles into HANDLE_LIST.
        let dir = CleanupDir::new("stdio");
        let stderr_path = dir.0.join("child-stderr.log");
        let stderr_file = File::create(&stderr_path).expect("create stderr log");
        let mut spec = ProcessLaunchSpec::new(
            &comspec,
            vec!["/D".into(), "/C".into(), "echo confined-stderr-ok 1>&2".into()],
        );
        spec.stderr = ProcessStdio::File(stderr_file);

        let mut stderr_proc =
            crate::process::ConfinedProcess::spawn(spec).expect("spawn cmd.exe with stderr File");
        let status = stderr_proc
            .wait_timeout(Duration::from_secs(5))
            .expect("wait for stderr cmd");
        assert_eq!(status, Some(ProcessExitStatus::Exited(0)));
        drop(stderr_proc);

        let captured = fs::read_to_string(&stderr_path).expect("read captured stderr log");
        assert!(
            captured.contains("confined-stderr-ok"),
            "expected captured stderr to contain 'confined-stderr-ok', got {captured:?}"
        );
    }
}
