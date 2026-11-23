//! Native `Dockerfile` / `Containerfile` image builder inside a sandbox VM (`podman build`).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sandbox_client::{pack_path_to_tar_bytes, ClientOutputKind, SandboxClient};
use sandbox_core::safe_tar::{apply_open_no_follow, ensure_safe_dir_path, reject_symlink_or_reparse};
use sandbox_core::{ExecExitStatus, ExecRequest, ExecTarget, SandboxError, SandboxId};
use tokio::io::AsyncWriteExt;

/// Maximum safe tar archive size for local build contexts streamed into a sandbox (128 MiB).
pub const MAX_BUILD_CONTEXT_BYTES: u64 = 128 * 1024 * 1024;
const STREAM_STDIN_CHUNK_BYTES: usize = 64 * 1024;
const BUILD_LOG_BUDGET_BYTES: u64 = 8 * 1024 * 1024;
const SAVE_STDERR_BUDGET_BYTES: u64 = 512 * 1024;
/// Large stdout budget (2 GiB) so `podman save` can stream multi-hundred-MiB OCI archives.
const SAVE_STDOUT_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

static BUILD_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageBuildSpec {
    pub context_dir: PathBuf,
    pub dockerfile: Option<String>,
    pub tags: Vec<String>,
    pub build_args: Vec<(String, String)>,
    pub target: Option<String>,
    pub no_cache: bool,
    pub output_tar: Option<PathBuf>,
    pub deadline: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageBuildResult {
    pub tags: Vec<String>,
    pub exit: ExecExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub exported_tar_bytes: Option<u64>,
}

impl ImageBuildSpec {
    /// Validates all build parameters and normalizes any relative `dockerfile` path for Linux guest Podman.
    pub fn validate_and_normalize(&mut self) -> Result<(), SandboxError> {
        if self.context_dir.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "build context directory must not be empty".to_owned(),
            ));
        }
        if self.tags.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "'build' requires at least one '-t/--tag <image[:tag]>'".to_owned(),
            ));
        }
        for tag in &self.tags {
            validate_image_tag(tag)?;
        }
        if let Some(raw_df) = &self.dockerfile {
            self.dockerfile = Some(normalize_relative_dockerfile(raw_df)?);
        }
        for (k, v) in &self.build_args {
            validate_build_arg_key(k)?;
            if v.contains('\0') {
                return Err(SandboxError::InvalidSpec(format!(
                    "build-arg '{k}' value cannot contain NUL bytes"
                )));
            }
        }
        if let Some(target) = &self.target {
            if target.is_empty() || target.starts_with('-') || target.contains('\0') {
                return Err(SandboxError::InvalidSpec(format!(
                    "invalid --target stage '{target}'"
                )));
            }
        }
        if self.deadline.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "--deadline-secs must be greater than zero".to_owned(),
            ));
        }
        if let Some(out) = &self.output_tar {
            if out.as_os_str().is_empty() {
                return Err(SandboxError::InvalidSpec(
                    "--output-tar path must not be empty".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Builds the `podman build` argv list executed inside the staged guest context directory.
    pub fn to_podman_build_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "/usr/bin/podman".to_owned(),
            "build".to_owned(),
            "--pull=missing".to_owned(),
        ];
        if self.no_cache {
            argv.push("--no-cache".to_owned());
        }
        if let Some(df) = &self.dockerfile {
            argv.push("--file".to_owned());
            argv.push(df.clone());
        }
        if let Some(target) = &self.target {
            argv.push("--target".to_owned());
            argv.push(target.clone());
        }
        for (k, v) in &self.build_args {
            argv.push("--build-arg".to_owned());
            argv.push(format!("{k}={v}"));
        }
        for tag in &self.tags {
            argv.push("--tag".to_owned());
            argv.push(tag.clone());
        }
        argv.push(".".to_owned());
        argv
    }
}

pub fn validate_image_tag(tag: &str) -> Result<(), SandboxError> {
    let trimmed = tag.trim();
    if trimmed.is_empty()
        || trimmed != tag
        || tag.starts_with('-')
        || tag.contains('\0')
        || tag.chars().any(char::is_whitespace)
    {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid image tag '{tag}'"
        )));
    }
    Ok(())
}

pub(crate) fn normalize_relative_dockerfile(raw: &str) -> Result<String, SandboxError> {
    let unified = raw.trim().replace('\\', "/");
    let stripped = unified.strip_prefix("./").unwrap_or(&unified);
    if stripped.is_empty()
        || stripped.starts_with('/')
        || stripped.starts_with('-')
        || stripped.contains('\0')
    {
        return Err(SandboxError::InvalidSpec(format!(
            "dockerfile path '{raw}' must be a safe relative path inside the build context"
        )));
    }
    for seg in stripped.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(SandboxError::InvalidSpec(format!(
                "dockerfile path '{raw}' must not contain '..' or empty path segments"
            )));
        }
    }
    Ok(stripped.to_owned())
}

fn validate_build_arg_key(key: &str) -> Result<(), SandboxError> {
    if key.is_empty()
        || key.starts_with('-')
        || key.contains('=')
        || key.contains('\0')
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid --build-arg key '{key}'"
        )));
    }
    Ok(())
}

/// Packs `spec.context_dir` safely, streams it into a temporary guest folder, runs `podman build`,
/// cleans up the temporary folder unconditionally, and optionally exports `--output-tar`.
pub async fn build_image_in_sandbox(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    mut spec: ImageBuildSpec,
    stream_to_stdio: bool,
) -> Result<ImageBuildResult, SandboxError> {
    spec.validate_and_normalize()?;

    let ctx_meta = fs::symlink_metadata(&spec.context_dir).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "cannot access build context '{}': {err}",
            spec.context_dir.display()
        ))
    })?;
    if sandbox_core::safe_tar::is_symlink_or_reparse(&ctx_meta) || !ctx_meta.is_dir() {
        return Err(SandboxError::PolicyViolation(format!(
            "build context '{}' must be a regular non-symlink directory",
            spec.context_dir.display()
        )));
    }

    let ctx_path = spec.context_dir.clone();
    let tar_bytes =
        tokio::task::spawn_blocking(move || pack_path_to_tar_bytes(&ctx_path, MAX_BUILD_CONTEXT_BYTES))
            .await
            .map_err(|err| SandboxError::Internal(format!("build context pack task failed: {err}")))??;

    let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
    let guest_ctx_dir = format!("/tmp/.mp-build-{}-{seq}", std::process::id());

    if let Err(stage_err) = stage_context_tar_in_guest(client, sandbox_id, &guest_ctx_dir, &tar_bytes).await {
        let _ = cleanup_guest_dir(client, sandbox_id, &guest_ctx_dir).await;
        return Err(stage_err);
    }

    let build_outcome = run_podman_build(
        client,
        sandbox_id,
        &guest_ctx_dir,
        &spec,
        stream_to_stdio,
    )
    .await;

    // Always clean up staged build context inside the guest VM, regardless of build success/failure.
    let _ = cleanup_guest_dir(client, sandbox_id, &guest_ctx_dir).await;

    let (exit, stdout, stderr) = build_outcome?;

    let mut exported_tar_bytes = None;
    if exit.code == Some(0) && !exit.timed_out {
        if let Some(ref out_tar) = spec.output_tar {
            let bytes = export_image_to_host_tar(client, sandbox_id, &spec.tags[0], out_tar, spec.deadline).await?;
            exported_tar_bytes = Some(bytes);
        }
    }

    Ok(ImageBuildResult {
        tags: spec.tags,
        exit,
        stdout,
        stderr,
        exported_tar_bytes,
    })
}

async fn stage_context_tar_in_guest(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    guest_ctx_dir: &str,
    tar_bytes: &[u8],
) -> Result<(), SandboxError> {
    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/bin/sh".to_owned(),
            "-euc".to_owned(),
            "(grep -q ' /var/cache ' /proc/mounts 2>/dev/null || (mkdir -p /var/tmp/var-cache && mount --bind /var/tmp/var-cache /var/cache 2>/dev/null || true)) && rm -rf -- \"$1\" && mkdir -p -- \"$1\" && tar -xf - -C \"$1\"".to_owned(),
            "sh".to_owned(),
            guest_ctx_dir.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline: Duration::from_secs(120),
        stdout_budget_bytes: 64 * 1024,
        stderr_budget_bytes: 256 * 1024,
    };

    let mut stream = client.exec_stream(sandbox_id, req).await?;
    for chunk in tar_bytes.chunks(STREAM_STDIN_CHUNK_BYTES) {
        stream.write_stdin(chunk.to_vec()).await?;
    }
    stream.close_stdin();

    let collected = stream.collect().await?;
    if collected.exit.code != Some(0) {
        let stderr = String::from_utf8_lossy(&collected.stderr).trim().to_owned();
        return Err(SandboxError::Internal(format!(
            "failed staging build context into '{guest_ctx_dir}' (exit={:?}): {stderr}",
            collected.exit.code
        )));
    }
    Ok(())
}

async fn run_podman_build(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    guest_ctx_dir: &str,
    spec: &ImageBuildSpec,
    stream_to_stdio: bool,
) -> Result<(ExecExitStatus, String, String), SandboxError> {
    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: spec.to_podman_build_argv(),
        env: BTreeMap::new(),
        cwd: Some(guest_ctx_dir.to_owned()),
        user: None,
        deadline: spec.deadline,
        stdout_budget_bytes: BUILD_LOG_BUDGET_BYTES,
        stderr_budget_bytes: BUILD_LOG_BUDGET_BYTES,
    };

    let mut stream = client.exec_stream(sandbox_id, req).await?;
    stream.close_stdin();

    if !stream_to_stdio {
        let collected = stream.collect().await?;
        return Ok((
            collected.exit,
            String::from_utf8_lossy(&collected.stdout).into_owned(),
            String::from_utf8_lossy(&collected.stderr).into_owned(),
        ));
    }

    let mut stdout_io = tokio::io::stdout();
    let mut stderr_io = tokio::io::stderr();
    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();

    while let Some(chunk) = stream.next_output().await {
        match chunk.stream {
            ClientOutputKind::Stdout => {
                out_buf.extend_from_slice(&chunk.data);
                let _ = stdout_io.write_all(&chunk.data).await;
                let _ = stdout_io.flush().await;
            }
            ClientOutputKind::Stderr => {
                err_buf.extend_from_slice(&chunk.data);
                let _ = stderr_io.write_all(&chunk.data).await;
                let _ = stderr_io.flush().await;
            }
        }
    }
    let exit = stream.wait_exit().await?;
    Ok((
        exit,
        String::from_utf8_lossy(&out_buf).into_owned(),
        String::from_utf8_lossy(&err_buf).into_owned(),
    ))
}

async fn cleanup_guest_dir(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    guest_ctx_dir: &str,
) -> Result<(), SandboxError> {
    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/bin/rm".to_owned(),
            "-rf".to_owned(),
            "--".to_owned(),
            guest_ctx_dir.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline: Duration::from_secs(15),
        stdout_budget_bytes: 16 * 1024,
        stderr_budget_bytes: 16 * 1024,
    };
    let _ = client.exec_collect(sandbox_id, req).await?;
    Ok(())
}

async fn export_image_to_host_tar(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    image_tag: &str,
    output_tar: &Path,
    deadline: Duration,
) -> Result<u64, SandboxError> {
    struct TempFileGuard(Option<PathBuf>);
    impl TempFileGuard {
        fn disarm(&mut self) {
            self.0 = None;
        }
    }
    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            if let Some(p) = &self.0 {
                let _ = fs::remove_file(p);
            }
        }
    }

    if let Ok(meta) = fs::symlink_metadata(output_tar) {
        reject_symlink_or_reparse(output_tar, &meta)?;
        if meta.is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "--output-tar '{}' must not be a directory or symlink",
                output_tar.display()
            )));
        }
    }
    let parent = output_tar
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_safe_dir_path(parent, true)?;

    let file_name = output_tar
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "--output-tar '{}' must have a valid UTF-8 file name",
                output_tar.display()
            ))
        })?;
    let mut tmp_opts = OpenOptions::new();
    tmp_opts.write(true).create_new(true);
    apply_open_no_follow(&mut tmp_opts);
    let mut tmp_guard = TempFileGuard(None);
    let (mut tmp_file, tmp_path) = {
        let mut created = None;
        for _ in 0..16 {
            let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));
            match tmp_opts.open(&candidate) {
                Ok(file) => {
                    tmp_guard.0 = Some(candidate.clone());
                    created = Some((file, candidate));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(SandboxError::Transport(format!(
                        "failed creating temporary archive '{}': {err}",
                        candidate.display()
                    )));
                }
            }
        }
        created.ok_or_else(|| {
            SandboxError::Transport(format!(
                "exhausted temporary archive filenames for '{}'",
                output_tar.display()
            ))
        })?
    };
    let open_meta = tmp_file.metadata().map_err(|err| {
        SandboxError::Transport(format!(
            "failed inspecting temporary archive '{}': {err}",
            tmp_path.display()
        ))
    })?;
    reject_symlink_or_reparse(&tmp_path, &open_meta)?;

    let req = ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/usr/bin/podman".to_owned(),
            "save".to_owned(),
            "--".to_owned(),
            image_tag.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline,
        stdout_budget_bytes: SAVE_STDOUT_BUDGET_BYTES,
        stderr_budget_bytes: SAVE_STDERR_BUDGET_BYTES,
    };

    let mut stream = match client.exec_stream(sandbox_id, req).await {
        Ok(s) => s,
        Err(err) => {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    stream.close_stdin();

    let mut total_bytes: u64 = 0;
    let mut stderr_bytes = Vec::new();
    while let Some(chunk) = stream.next_output().await {
        match chunk.stream {
            ClientOutputKind::Stdout => {
                if let Err(err) = tmp_file.write_all(&chunk.data) {
                    drop(tmp_file);
                    let _ = fs::remove_file(&tmp_path);
                    return Err(SandboxError::Transport(format!(
                        "failed writing '--output-tar' '{}': {err}",
                        tmp_path.display()
                    )));
                }
                total_bytes = total_bytes.saturating_add(chunk.data.len() as u64);
            }
            ClientOutputKind::Stderr => {
                stderr_bytes.extend_from_slice(&chunk.data);
            }
        }
    }

    let exit = match stream.wait_exit().await {
        Ok(e) => e,
        Err(err) => {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    if exit.code != Some(0) || exit.timed_out || exit.stdout_truncated {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        let stderr_msg = String::from_utf8_lossy(&stderr_bytes).trim().to_owned();
        return Err(SandboxError::Internal(format!(
            "podman save '{image_tag}' failed (exit={:?}, timed_out={}, truncated={}): {stderr_msg}",
            exit.code, exit.timed_out, exit.stdout_truncated
        )));
    }

    if let Err(err) = tmp_file.sync_all() {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(SandboxError::Transport(format!(
            "failed syncing temporary archive '{}': {err}",
            tmp_path.display()
        )));
    }
    drop(tmp_file);

    if let Ok(meta) = fs::symlink_metadata(output_tar) {
        reject_symlink_or_reparse(output_tar, &meta)?;
        if meta.is_dir() {
            let _ = fs::remove_file(&tmp_path);
            return Err(SandboxError::PolicyViolation(format!(
                "'--output-tar' target '{}' is a directory",
                output_tar.display()
            )));
        }
    }

    fs::rename(&tmp_path, output_tar).map_err(|err| {
        SandboxError::Transport(format!(
            "failed renaming '{}' -> '{}': {err}",
            tmp_path.display(),
            output_tar.display()
        ))
    })?;
    tmp_guard.disarm();

    Ok(total_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_dockerfile_tags_and_builds_safe_podman_argv() {
        let mut spec = ImageBuildSpec {
            context_dir: PathBuf::from("."),
            dockerfile: Some(r".\docker\Dockerfile.api".to_owned()),
            tags: vec!["my-app:latest".to_owned(), "my-app:1.0".to_owned()],
            build_args: vec![("NODE_ENV".to_owned(), "production".to_owned())],
            target: Some("runner".to_owned()),
            no_cache: true,
            output_tar: None,
            deadline: Duration::from_secs(120),
        };
        spec.validate_and_normalize().unwrap();
        assert_eq!(spec.dockerfile.as_deref(), Some("docker/Dockerfile.api"));
        assert_eq!(
            spec.to_podman_build_argv(),
            vec![
                "/usr/bin/podman",
                "build",
                "--pull=missing",
                "--no-cache",
                "--file",
                "docker/Dockerfile.api",
                "--target",
                "runner",
                "--build-arg",
                "NODE_ENV=production",
                "--tag",
                "my-app:latest",
                "--tag",
                "my-app:1.0",
                ".",
            ]
        );

        // Reject traversal, absolute dockerfile, or flag-injection tags.
        let mut bad_df = spec.clone();
        bad_df.dockerfile = Some("../Dockerfile".to_owned());
        assert!(matches!(
            bad_df.validate_and_normalize(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut bad_tag = spec.clone();
        bad_tag.tags = vec!["--privileged".to_owned()];
        assert!(matches!(
            bad_tag.validate_and_normalize(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn export_image_to_host_tar_rejects_directory_and_symlink_targets() {
        let dir = std::env::temp_dir().join(format!(
            "mp-img-export-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let ep = if cfg!(windows) {
            sandbox_client::ControlEndpoint::NamedPipe(r"\\.\pipe\img-export-test".to_owned())
        } else {
            sandbox_client::ControlEndpoint::UnixSocket(PathBuf::from("/tmp/img-export-test.sock"))
        };
        let client = SandboxClient::new(ep);

        let sub_dir = dir.join("dir-target");
        fs::create_dir_all(&sub_dir).unwrap();
        assert!(matches!(
            export_image_to_host_tar(
                &client,
                &SandboxId::new("sb-1"),
                "demo:1",
                &sub_dir,
                Duration::from_secs(5),
            )
            .await,
            Err(SandboxError::PolicyViolation(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = dir.join("real.tar");
            fs::write(&real, b"tar").unwrap();
            let sym = dir.join("sym.tar");
            symlink(&real, &sym).unwrap();
            assert!(matches!(
                export_image_to_host_tar(
                    &client,
                    &SandboxId::new("sb-1"),
                    "demo:1",
                    &sym,
                    Duration::from_secs(5),
                )
                .await,
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn export_image_to_host_tar_preserves_preexisting_temp_files_on_collision() {
        let dir = std::env::temp_dir().join(format!(
            "mp-img-export-collide-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let client = SandboxClient::with_connector(
            sandbox_client::ControlEndpoint::NamedPipe("unused".to_owned()),
            |_| async { Err::<tokio::io::DuplexStream, _>(SandboxError::Transport("stub".to_owned())) },
        );

        // 1. Single collision skips the pre-existing file without deleting it and uses the next seq.
        let collide_tar = dir.join("collide.tar");
        let next_seq = BUILD_SEQ.load(Ordering::Acquire);
        let existing_tmp = dir.join(format!(".collide.tar.tmp.{}.{next_seq}", std::process::id()));
        fs::write(&existing_tmp, b"keep-me-1").unwrap();
        let err = export_image_to_host_tar(
            &client,
            &SandboxId::new("sb-1"),
            "demo:1",
            &collide_tar,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SandboxError::Transport(_)), "got {err:?}");
        assert_eq!(fs::read(&existing_tmp).unwrap(), b"keep-me-1");

        // 2. Exhausting all 16 candidates leaves every pre-existing temp file untouched.
        let exhaust_tar = dir.join("exhaust.tar");
        let base_seq = BUILD_SEQ.load(Ordering::Acquire);
        let mut pre_existing = Vec::new();
        for offset in 0..16u64 {
            let p = dir.join(format!(
                ".exhaust.tar.tmp.{}.{}",
                std::process::id(),
                base_seq + offset
            ));
            fs::write(&p, format!("pre-{offset}").as_bytes()).unwrap();
            pre_existing.push((offset, p));
        }
        let err = export_image_to_host_tar(
            &client,
            &SandboxId::new("sb-1"),
            "demo:1",
            &exhaust_tar,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SandboxError::Transport(_)), "got {err:?}");
        for (offset, p) in pre_existing {
            assert_eq!(fs::read(&p).unwrap(), format!("pre-{offset}").as_bytes());
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
