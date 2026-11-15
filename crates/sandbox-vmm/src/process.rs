//! Cross-platform confined child process launching, identity tracking, and verified orphan cleanup.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_core::SandboxError;

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
}

impl ProcessLaunchSpec {
    /// Creates a [`ProcessLaunchSpec`] with all stdio streams defaulted to [`ProcessStdio::Null`].
    pub fn new(program: impl Into<PathBuf>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            current_dir: None,
            stdin: ProcessStdio::Null,
            stdout: ProcessStdio::Null,
            stderr: ProcessStdio::Null,
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
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2 + 1));
            out.push(b'"' as u16);
            backslashes = 0;
        } else {
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes));
            backslashes = 0;
            out.push(u);
        }
    }
    // Double any trailing backslashes so they do not escape the closing quote.
    out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2));
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
    fn confined_process_rejects_empty_and_missing_program() {
        let empty = ConfinedProcess::spawn(ProcessLaunchSpec::new("", vec![]));
        assert!(matches!(empty, Err(SandboxError::InvalidSpec(_))));

        let missing = ConfinedProcess::spawn(ProcessLaunchSpec::new(
            PathBuf::from("nonexistent-minipod-binary-xyz-98765"),
            vec![],
        ));
        assert!(matches!(missing, Err(SandboxError::NotFound(_))));
    }
}
