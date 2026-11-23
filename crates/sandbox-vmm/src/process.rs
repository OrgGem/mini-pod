//! Cross-platform confined child process launching, identity tracking, and verified orphan cleanup.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sandbox_core::{EnforcementLevel, SandboxError};

#[cfg(unix)]
use crate::os::unix as platform;
#[cfg(windows)]
use crate::os::windows_job as platform;

/// OS-level process identifier paired with a start-time identity token to defeat PID reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessStartIdentity {
    pub pid: u32,
    /// Platform start token (`FILETIME` 64-bit creation time on Windows; Linux `/proc/<pid>/stat`
    /// field 22 `starttime`; `0` only on Unix platforms lacking procfs start-time lookup).
    pub start_token: u64,
}

/// Normalized exit status for a confined child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessExitStatus {
    /// Process terminated normally or via Win32 `TerminateProcess` with the given raw exit code.
    Exited(i32),
    /// Process was terminated by a POSIX signal (Unix only).
    Signaled(i32),
}

impl ProcessExitStatus {
    /// Returns `true` when the process exited cleanly with exit code `0`.
    pub fn success(self) -> bool {
        matches!(self, Self::Exited(0))
    }

    /// Returns the numeric exit code when terminated via normal exit (or Windows termination).
    pub fn code(self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(code),
            Self::Signaled(_) => None,
        }
    }

    /// Returns the terminating POSIX signal number when killed by a signal.
    pub fn signal(self) -> Option<i32> {
        match self {
            Self::Exited(_) => None,
            Self::Signaled(sig) => Some(sig),
        }
    }
}

impl fmt::Display for ProcessExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exit code {code}"),
            Self::Signaled(sig) => write!(f, "signal {sig}"),
        }
    }
}

/// Standard I/O stream configuration for a confined child process.
#[derive(Debug, Default)]
pub enum ProcessStdio {
    /// No custom handle inherited (`Stdio::null()` on Unix; unredirected or `\\.\NUL` on Windows).
    #[default]
    Null,
    /// Redirects the stream to an already-opened host file.
    File(File),
    /// Redirects the stream to the write end of an anonymous OS pipe.
    PipeWriter(PipeWriter),
}

/// Captured exit status and bounded `stdout`/`stderr` buffers from [`run_confined_command_bounded`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfinedCommandOutput {
    pub status: ProcessExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Host OS enforcement levels actually achieved for a spawned [`ConfinedProcess`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessResourceCapabilities {
    pub cpu_quota: EnforcementLevel,
    pub host_rss: EnforcementLevel,
}

/// Launch specification for spawning a confined host child process (such as QEMU).
#[derive(Debug)]
pub struct ProcessLaunchSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub current_dir: Option<PathBuf>,
    pub stdin: ProcessStdio,
    pub stdout: ProcessStdio,
    pub stderr: ProcessStdio,
    pub cpu_quota_millicores: Option<u32>,
    pub memory_limit_bytes: Option<u64>,
}

impl ProcessLaunchSpec {
    /// Creates a [`ProcessLaunchSpec`] with all stdio streams defaulted to [`ProcessStdio::Null`]
    /// and no explicit CPU/memory limits.
    pub fn new(program: impl Into<PathBuf>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            current_dir: None,
            stdin: ProcessStdio::Null,
            stdout: ProcessStdio::Null,
            stderr: ProcessStdio::Null,
            cpu_quota_millicores: None,
            memory_limit_bytes: None,
        }
    }
}

/// Confined host child process that terminates its entire child process tree on `Drop`.
///
/// - **Windows:** Atomically attached to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job Object inside
///   `CreateProcessW` via `PROC_THREAD_ATTRIBUTE_JOB_LIST` and strict `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
///   whitelisting.
/// - **Unix:** Placed into its own process group (`setpgid(0, 0)`) with `CLOEXEC` preservation.
pub struct ConfinedProcess {
    inner: platform::PlatformConfinedProcess,
}

impl ConfinedProcess {
    /// Spawns a confined child process according to `spec`.
    pub fn spawn(spec: ProcessLaunchSpec) -> Result<Self, SandboxError> {
        if spec.program.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "confined process program path must not be empty".to_owned(),
            ));
        }
        if spec.cpu_quota_millicores == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "confined process cpu_quota_millicores must be >= 1".to_owned(),
            ));
        }
        if spec.memory_limit_bytes == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "confined process memory_limit_bytes must be >= 1".to_owned(),
            ));
        }
        platform::spawn_confined(spec).map(|inner| Self { inner })
    }

    /// Returns the OS process ID (`pid`).
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Returns the captured PID + creation-time token for journaled orphan verification.
    pub fn start_identity(&self) -> ProcessStartIdentity {
        self.inner.start_identity()
    }

    /// Returns the honest host OS CPU and memory enforcement capabilities applied to this process.
    pub fn resource_capabilities(&self) -> ProcessResourceCapabilities {
        self.inner.resource_capabilities()
    }

    /// Samples the live resident set size (`RSS` / working set) in bytes for this process, or
    /// `None` if the process has exited or the host OS does not report it.
    pub fn current_rss_bytes(&self) -> Option<u64> {
        self.inner.current_rss_bytes()
    }

    /// Non-blocking poll for child termination.
    pub fn try_wait(&mut self) -> Result<Option<ProcessExitStatus>, SandboxError> {
        self.inner.try_wait()
    }

    /// Waits up to `timeout` for the child process to exit, returning `Ok(None)` on timeout.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<ProcessExitStatus>, SandboxError> {
        self.inner.wait_timeout(timeout)
    }

    /// Forcefully terminates the confined process tree and waits until the child handle/PID is reaped.
    pub fn kill_and_wait(&mut self) -> Result<(), SandboxError> {
        self.inner.kill_and_wait()
    }
}

/// Spawns `program` with `args` inside a [`ConfinedProcess`] (Windows Job Object with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; Unix dedicated
/// process group), captures up to `max_output_bytes` per stream while draining excess output so
/// pipes never deadlock, and kills the entire process tree if `timeout` elapses.
pub fn run_confined_command_bounded(
    program: &Path,
    args: &[OsString],
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ConfinedCommandOutput, SandboxError> {
    if timeout.is_zero() {
        return Err(SandboxError::InvalidSpec(
            "confined command timeout must be greater than zero".to_owned(),
        ));
    }
    let (stdout_rx, stdout_tx) = io::pipe().map_err(|err| {
        SandboxError::Transport(format!("failed to create confined stdout pipe: {err}"))
    })?;
    let (stderr_rx, stderr_tx) = io::pipe().map_err(|err| {
        SandboxError::Transport(format!("failed to create confined stderr pipe: {err}"))
    })?;

    let mut spec = ProcessLaunchSpec::new(program, args.to_vec());
    spec.stdout = ProcessStdio::PipeWriter(stdout_tx);
    spec.stderr = ProcessStdio::PipeWriter(stderr_tx);
    let mut proc = ConfinedProcess::spawn(spec)?;

    thread::scope(|s| {
        let out_handle = s.spawn(move || read_pipe_bounded(stdout_rx, max_output_bytes));
        let err_handle = s.spawn(move || read_pipe_bounded(stderr_rx, max_output_bytes));

        match proc.wait_timeout(timeout) {
            Ok(Some(status)) => {
                let stdout = out_handle.join().unwrap_or_default();
                let stderr = err_handle.join().unwrap_or_default();
                Ok(ConfinedCommandOutput {
                    status,
                    stdout,
                    stderr,
                })
            }
            Ok(None) => {
                let _ = proc.kill_and_wait();
                let _ = out_handle.join();
                let _ = err_handle.join();
                Err(SandboxError::Transport(format!(
                    "confined helper command '{}' timed out after {}ms",
                    program.display(),
                    timeout.as_millis()
                )))
            }
            Err(err) => {
                let _ = proc.kill_and_wait();
                let _ = out_handle.join();
                let _ = err_handle.join();
                Err(err)
            }
        }
    })
}

/// Spawns a detached background thread that copies at most `max_bytes` from `reader` into `file`
/// and discards any subsequent bytes until pipe EOF so the child process never stalls on writes
/// while host disk usage stays strictly bounded.
pub(crate) fn spawn_bounded_pipe_file_sink(reader: PipeReader, mut file: File, max_bytes: u64) {
    let _ = thread::Builder::new()
        .name("minipod-log-sink".to_owned())
        .spawn(move || {
            let mut reader = reader;
            let mut written: u64 = 0;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let rem = max_bytes.saturating_sub(written);
                        if rem > 0 {
                            let to_write = (n as u64).min(rem) as usize;
                            if file.write_all(&buf[..to_write]).is_ok() {
                                written += to_write as u64;
                            } else {
                                written = max_bytes;
                            }
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = file.flush();
        });
}

fn read_pipe_bounded(mut reader: PipeReader, max_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let rem = max_bytes.saturating_sub(out.len());
                if rem > 0 {
                    let take = n.min(rem);
                    out.extend_from_slice(&buf[..take]);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

/// Verifies `pid` against `expected_start_token` before killing an orphaned process tree.
///
/// Returns `Ok(true)` if a live matching process was terminated, or `Ok(false)` safely without
/// sending a signal when the process already exited or `expected_start_token` does not match
/// (defeating PID-reuse races).
pub fn kill_verified_orphan_process(
    pid: u32,
    expected_start_token: u64,
) -> Result<bool, SandboxError> {
    platform::kill_verified_orphan_process(pid, expected_start_token)
}

#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn wait_for_verified_orphan_exit<F>(
    pid: u32,
    expected_start_token: u64,
    timeout: Duration,
    poll_interval: Duration,
    mut is_still_alive: F,
) -> Result<(), SandboxError>
where
    F: FnMut() -> Result<bool, SandboxError>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if !is_still_alive()? {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep(deadline.saturating_duration_since(now).min(poll_interval));
    }
    if !is_still_alive()? {
        return Ok(());
    }
    Err(SandboxError::Internal(format!(
        "orphan process {pid} (start_token={expected_start_token}) is still alive after SIGKILL wait timeout"
    )))
}

/// Encodes `program` and `args` into a NUL-terminated UTF-16 Windows command line following
/// standard `CommandLineToArgvW` / MSVCRT backslash-and-quote escaping rules.
pub fn quote_windows_command_line(
    program: &Path,
    args: &[OsString],
) -> Result<Vec<u16>, SandboxError> {
    let prog_units = os_str_to_utf16(program.as_os_str())?;
    if prog_units.contains(&(b'"' as u16)) {
        return Err(SandboxError::InvalidSpec(
            "Windows program path must not contain '\"'".to_owned(),
        ));
    }

    let mut out = Vec::with_capacity(prog_units.len() + args.len() * 16 + 4);
    let quote_prog = prog_units.is_empty()
        || prog_units
            .iter()
            .any(|&u| u == b' ' as u16 || u == b'\t' as u16);
    if quote_prog {
        out.push(b'"' as u16);
        out.extend_from_slice(&prog_units);
        out.push(b'"' as u16);
    } else {
        out.extend_from_slice(&prog_units);
    }

    for arg in args {
        out.push(b' ' as u16);
        let units = os_str_to_utf16(arg.as_os_str())?;
        push_windows_arg(&mut out, &units);
    }
    out.push(0);
    Ok(out)
}

fn push_windows_arg(out: &mut Vec<u16>, units: &[u16]) {
    let needs_quotes = units.is_empty()
        || units.iter().any(|&u| {
            u == b' ' as u16
                || u == b'\t' as u16
                || u == b'\n' as u16
                || u == 0x0B
                || u == b'"' as u16
        });
    if !needs_quotes {
        out.extend_from_slice(units);
        return;
    }

    out.push(b'"' as u16);
    let mut backslashes = 0usize;
    for &u in units {
        if u == b'\\' as u16 {
            backslashes += 1;
        } else if u == b'"' as u16 {
            // Double preceding backslashes and escape the quote itself (`2n + 1`).
            out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            out.push(b'"' as u16);
            backslashes = 0;
        } else {
            out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            backslashes = 0;
            out.push(u);
        }
    }
    // Double any trailing backslashes so they do not escape the closing quote.
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    out.push(b'"' as u16);
}

fn os_str_to_utf16(s: &OsStr) -> Result<Vec<u16>, SandboxError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<u16> = s.encode_wide().collect();
        if units.contains(&0) {
            return Err(SandboxError::InvalidSpec(
                "Windows command-line argument contains an interior NUL character".to_owned(),
            ));
        }
        Ok(units)
    }
    #[cfg(not(windows))]
    {
        let text = s.to_str().ok_or_else(|| {
            SandboxError::InvalidSpec(
                "command-line argument is not valid UTF-8 for Windows UTF-16 quoting".to_owned(),
            )
        })?;
        if text.contains('\0') {
            return Err(SandboxError::InvalidSpec(
                "Windows command-line argument contains an interior NUL character".to_owned(),
            ));
        }
        Ok(text.encode_utf16().collect())
    }
}

/// Parses Linux `/proc/<pid>/stat` and returns `(state, starttime)` (field 3 and field 22).
///
/// Anchors past the LAST `)` so executable names containing spaces, newlines, or nested
/// parentheses never shift subsequent field indices.
pub(crate) fn parse_proc_stat_state_and_starttime(stat: &str) -> Option<(char, u64)> {
    let open_paren = stat.find('(')?;
    let close_paren = stat.rfind(')')?;
    if open_paren >= close_paren {
        return None;
    }
    if stat[..open_paren].trim().parse::<u32>().is_err() {
        return None;
    }
    let mut fields = stat.get(close_paren + 1..)?.split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    // `state` is field 3 (consumed above); field 22 (`starttime`) is 18 fields ahead.
    let starttime = fields.nth(18)?.parse::<u64>().ok()?;
    Some((state, starttime))
}

/// Parses Linux `/proc/<pid>/stat` field 22 (`starttime`), extracting past the LAST `)` cleanly
/// so executable names with spaces or parentheses never misparse.
pub fn parse_proc_stat_starttime(stat: &str) -> Option<u64> {
    parse_proc_stat_state_and_starttime(stat).map(|(_, starttime)| starttime)
}

/// Converts a host CPU quota in millicores (`1000` = 1 logical CPU) into a Windows Job Object
/// `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::CpuRate` value (`1..=10_000` in `0.01%` units of
/// total host logical CPUs).
///
/// Formula: `((u64::from(millicores) * 10_000) / (logical_cpus.max(1) as u64 * 1000)).clamp(1, 10_000)`.
pub fn millicores_to_windows_cpu_rate(millicores: u32, logical_cpus: usize) -> u32 {
    let total_millicores = (logical_cpus.max(1) as u64).saturating_mul(1000);
    let rate = (u64::from(millicores) * 10_000) / total_millicores;
    rate.clamp(1, 10_000) as u32
}

/// Converts a host CPU quota in millicores (`1000` = 1 CPU core) into a Linux cgroup v2 `cpu.max`
/// microsecond quota over a `100_000` us (`100 ms`) period, clamping to the kernel minimum `1000` us.
pub fn millicores_to_cgroup_quota_us(millicores: u32) -> u64 {
    (u64::from(millicores) * 100).max(1000)
}

/// Extracts the cgroup v2 unified hierarchy path (`0::<path>`) from `/proc/self/cgroup`.
///
/// Rejects malformed lines, relative paths, NUL bytes, and `..` path traversal components.
pub fn parse_proc_self_cgroup_v2(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_end_matches('\r');
        let mut parts = trimmed.splitn(3, ':');
        let Some(hier_id) = parts.next() else {
            continue;
        };
        let Some(controllers) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            continue;
        };
        if hier_id != "0" || !controllers.is_empty() {
            continue;
        }
        if !path.starts_with('/')
            || path.contains('\0')
            || path.split('/').any(|seg| seg == "..")
        {
            return None;
        }
        return Some(path.to_owned());
    }
    None
}

/// Parses Linux `/proc/<pid>/statm` and returns resident set size in bytes (`resident_pages * page_size`).
pub fn parse_proc_statm_rss_bytes(statm: &str, page_size: u64) -> Option<u64> {
    if page_size == 0 {
        return None;
    }
    let mut fields = statm.split_ascii_whitespace();
    let _total_pages = fields.next()?.parse::<u64>().ok()?;
    let resident_pages = fields.next()?.parse::<u64>().ok()?;
    resident_pages.checked_mul(page_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_wide_null(wide: &[u16]) -> String {
        assert_eq!(wide.last(), Some(&0), "wide command line must end with NUL");
        String::from_utf16(&wide[..wide.len() - 1]).expect("valid UTF-16 output")
    }

    #[test]
    fn quote_windows_command_line_handles_spaces_quotes_backslashes_and_rejects_nul() {
        let plain = quote_windows_command_line(
            Path::new("qemu-system-x86_64.exe"),
            &[OsString::from("-accel"), OsString::from("whpx")],
        )
        .expect("plain command line");
        assert_eq!(decode_wide_null(&plain), "qemu-system-x86_64.exe -accel whpx");

        let complex = quote_windows_command_line(
            Path::new(r"C:\Program Files\qemu\qemu-system-x86_64.exe"),
            &[
                OsString::from(""),
                OsString::from("hello world"),
                OsString::from("tab\targ"),
                OsString::from(r#"a"b"c"#),
                OsString::from(r#"a\"b"#),
                OsString::from(r"C:\dir with space\"),
                OsString::from(r"C:\nospace\dir\"),
                OsString::from("việt-nam"),
            ],
        )
        .expect("complex quoting");
        assert_eq!(
            decode_wide_null(&complex),
            concat!(
                r#""C:\Program Files\qemu\qemu-system-x86_64.exe" "#,
                r#""" "#,
                r#""hello world" "#,
                "\"tab\targ\" ",
                r#""a\"b\"c" "#,
                r#""a\\\"b" "#,
                r#""C:\dir with space\\" "#,
                r"C:\nospace\dir\ ",
                "việt-nam"
            )
        );

        let quote_prog = quote_windows_command_line(Path::new(r#"C:\bad"exe"#), &[]);
        assert!(matches!(quote_prog, Err(SandboxError::InvalidSpec(_))));

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let bad_arg = OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]);
            let res = quote_windows_command_line(Path::new("prog.exe"), &[bad_arg]);
            assert!(matches!(res, Err(SandboxError::InvalidSpec(_))));
        }
        #[cfg(not(windows))]
        {
            let bad_arg = OsString::from("a\0b");
            let res = quote_windows_command_line(Path::new("prog"), &[bad_arg]);
            assert!(matches!(res, Err(SandboxError::InvalidSpec(_))));
        }
    }

    #[test]
    fn parse_proc_stat_starttime_handles_spaces_nested_parens_and_malformed_lines() {
        // Exact 22-field record stopping at starttime.
        let standard = "4210 (qemu-system-x86) S 1 4210 4210 0 -1 4194304 100 0 0 0 12 3 0 0 20 0 1 0 987654321\n";
        assert_eq!(parse_proc_stat_starttime(standard), Some(987654321));

        // Executable name containing spaces, nested parens, and extra trailing fields.
        let weird_comm = "777 (my (weird ) proc) name) Z 1 777 777 0 -1 0 1 2 3 4 5 6 7 8 20 0 1 0 18446744073709551615 4096 12\n";
        assert_eq!(
            parse_proc_stat_state_and_starttime(weird_comm),
            Some(('Z', u64::MAX))
        );
        assert_eq!(parse_proc_stat_starttime(weird_comm), Some(u64::MAX));

        // Executable name containing a newline inside parens.
        let newline_comm = "88 (line\nbreak) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 555666 0\n";
        assert_eq!(parse_proc_stat_starttime(newline_comm), Some(555666));

        for malformed in [
            "",
            "no-parens S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20",
            "abc (non-numeric-pid) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20",
            "123 )reversed( S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20",
            "123 (too-short) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18",
            "123 (bad-start) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 not_u64",
        ] {
            assert_eq!(
                parse_proc_stat_starttime(malformed),
                None,
                "expected None for malformed /proc/<pid>/stat: {malformed:?}"
            );
        }
    }

    #[test]
    fn confined_process_rejects_empty_missing_program_and_zero_limits() {
        let empty = ConfinedProcess::spawn(ProcessLaunchSpec::new("", vec![]));
        assert!(matches!(empty, Err(SandboxError::InvalidSpec(_))));

        let mut zero_cpu = ProcessLaunchSpec::new("qemu-system-x86_64", vec![]);
        zero_cpu.cpu_quota_millicores = Some(0);
        assert!(matches!(
            ConfinedProcess::spawn(zero_cpu),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut zero_mem = ProcessLaunchSpec::new("qemu-system-x86_64", vec![]);
        zero_mem.memory_limit_bytes = Some(0);
        assert!(matches!(
            ConfinedProcess::spawn(zero_mem),
            Err(SandboxError::InvalidSpec(_))
        ));

        let missing = ConfinedProcess::spawn(ProcessLaunchSpec::new(
            PathBuf::from("nonexistent-minipod-binary-xyz-98765"),
            vec![],
        ));
        assert!(matches!(missing, Err(SandboxError::NotFound(_))));
    }

    #[test]
    fn millicores_to_windows_cpu_rate_scales_and_clamps_correctly() {
        // 1000 millicores on 4 logical CPUs = 25.00% -> 2500.
        assert_eq!(millicores_to_windows_cpu_rate(1000, 4), 2500);
        // 500 millicores on 4 logical CPUs = 12.50% -> 1250.
        assert_eq!(millicores_to_windows_cpu_rate(500, 4), 1250);
        // 1000 millicores on 1 logical CPU = 100.00% -> 10_000.
        assert_eq!(millicores_to_windows_cpu_rate(1000, 1), 10_000);
        // Sub-0.01% positive quota clamps cleanly to minimum 1 instead of 0.
        assert_eq!(millicores_to_windows_cpu_rate(1, 16), 1);
        // Over-provisioned quota clamps cleanly to 10_000 (100%).
        assert_eq!(millicores_to_windows_cpu_rate(8000, 4), 10_000);
        // Zero logical CPUs degrades safely to 1 without dividing by zero.
        assert_eq!(millicores_to_windows_cpu_rate(500, 0), 5000);
        // Huge logical CPU count never overflows multiplication.
        assert_eq!(millicores_to_windows_cpu_rate(500, usize::MAX), 1);
    }

    #[test]
    fn millicores_to_cgroup_quota_us_converts_and_enforces_kernel_minimum() {
        assert_eq!(millicores_to_cgroup_quota_us(1000), 100_000);
        assert_eq!(millicores_to_cgroup_quota_us(500), 50_000);
        assert_eq!(millicores_to_cgroup_quota_us(2500), 250_000);
        assert_eq!(millicores_to_cgroup_quota_us(10), 1_000);
        assert_eq!(millicores_to_cgroup_quota_us(1), 1_000);
    }

    #[test]
    fn parse_proc_self_cgroup_v2_extracts_unified_path_and_rejects_malformed() {
        assert_eq!(
            parse_proc_self_cgroup_v2("0::/\n"),
            Some("/".to_owned())
        );
        assert_eq!(
            parse_proc_self_cgroup_v2(
                "12:pids:/user.slice\n11:memory:/user.slice\n0::/user.slice/user-1000.slice/session-2.scope\n"
            ),
            Some("/user.slice/user-1000.slice/session-2.scope".to_owned())
        );
        assert_eq!(
            parse_proc_self_cgroup_v2("0::/path:with:colons\r\n"),
            Some("/path:with:colons".to_owned())
        );

        for invalid in [
            "",
            "12:memory:/\n11:cpu:/\n",
            "0:cpu:/user.slice\n",
            "0::relative/path\n",
            "0::\n",
            "0::/user.slice/../escape\n",
            "0::/bad\0path\n",
        ] {
            assert_eq!(
                parse_proc_self_cgroup_v2(invalid),
                None,
                "expected None for cgroup input {invalid:?}"
            );
        }
    }

    #[test]
    fn parse_proc_statm_rss_bytes_computes_rss_and_rejects_malformed() {
        assert_eq!(
            parse_proc_statm_rss_bytes("125432 45120 12000 100 0 38000 0\n", 4096),
            Some(45120 * 4096)
        );
        assert_eq!(
            parse_proc_statm_rss_bytes("100 25", 16_384),
            Some(25 * 16_384)
        );
        assert_eq!(
            parse_proc_statm_rss_bytes("0 0 0 0 0 0 0\n", 4096),
            Some(0)
        );

        for bad in ["", "1234\n", "abc 100 0\n", "100 xyz 0\n"] {
            assert_eq!(
                parse_proc_statm_rss_bytes(bad, 4096),
                None,
                "expected None for statm {bad:?}"
            );
        }
        assert_eq!(parse_proc_statm_rss_bytes("100 25", 0), None);
        assert_eq!(
            parse_proc_statm_rss_bytes(&format!("100 {} 0", u64::MAX), 4096),
            None
        );
    }

    #[test]
    fn run_confined_command_bounded_captures_output_truncates_and_enforces_timeout() {
        #[cfg(windows)]
        let (prog, ok_args, slow_args) = (
            Path::new("cmd.exe"),
            vec![
                OsString::from("/C"),
                OsString::from("echo hello-confined && echo err-line 1>&2"),
            ],
            vec![
                OsString::from("/C"),
                OsString::from("ping -n 10 127.0.0.1 >NUL"),
            ],
        );
        #[cfg(unix)]
        let (prog, ok_args, slow_args) = (
            Path::new("/bin/sh"),
            vec![
                OsString::from("-c"),
                OsString::from("printf 'hello-confined\\n'; printf 'err-line\\n' >&2"),
            ],
            vec![OsString::from("-c"), OsString::from("sleep 10")],
        );

        let out = run_confined_command_bounded(prog, &ok_args, Duration::from_secs(5), 6)
            .expect("confined command succeeds");
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello-");
        assert_eq!(out.stderr, b"err-li");

        let timed_out = run_confined_command_bounded(prog, &slow_args, Duration::from_millis(80), 64);
        assert!(
            matches!(timed_out, Err(SandboxError::Transport(_))),
            "expected Transport timeout error, got {timed_out:?}"
        );
    }

    #[test]
    fn wait_for_verified_orphan_exit_succeeds_on_exit_and_errors_when_still_alive() {
        let mut checks = 0u32;
        wait_for_verified_orphan_exit(
            4242,
            99,
            Duration::from_millis(100),
            Duration::from_millis(2),
            || {
                checks += 1;
                Ok(checks < 3)
            },
        )
        .expect("should return Ok once process stops matching");
        assert_eq!(checks, 3);

        let err = wait_for_verified_orphan_exit(
            4242,
            99,
            Duration::from_millis(15),
            Duration::from_millis(2),
            || Ok(true),
        )
        .unwrap_err();
        assert!(matches!(err, SandboxError::Internal(_)), "got {err:?}");

        let probe_err = wait_for_verified_orphan_exit(
            4242,
            99,
            Duration::from_millis(50),
            Duration::from_millis(2),
            || Err(SandboxError::Internal("proc read denied".to_owned())),
        )
        .unwrap_err();
        assert!(matches!(probe_err, SandboxError::Internal(_)));
    }
}
