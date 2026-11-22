//! Durable operation identities for retryable sandbox creation.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sandbox_client::{ControlRequest, ControlResponse};
use sandbox_core::safe_tar::{ensure_safe_dir_path, map_fs_error, reject_symlink_or_reparse};
use sandbox_core::{DestroyStatus, SandboxError, SandboxLease, SandboxSpec};
use sandbox_runtime::{LocalRuntimeManager, RuntimeManager};
use tokio::sync::Mutex as AsyncMutex;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_CACHED_OPERATIONS: usize = 4096;

#[derive(Default)]
struct Operation {
    lease: Option<SandboxLease>,
}

pub(crate) struct SpawnRegistry {
    runtime: Arc<LocalRuntimeManager>,
    operations: Mutex<HashMap<String, Arc<AsyncMutex<Operation>>>>,
    recovery_checked: AsyncMutex<bool>,
    incarnation: Option<String>,
}

impl SpawnRegistry {
    pub(crate) fn new(runtime: Arc<LocalRuntimeManager>) -> Self {
        let mut nonce = [0u8; 16];
        let incarnation = getrandom::getrandom(&mut nonce)
            .ok()
            .map(|()| nonce.iter().map(|byte| format!("{byte:02x}")).collect());
        Self {
            runtime,
            operations: Mutex::new(HashMap::new()),
            recovery_checked: AsyncMutex::new(false),
            incarnation,
        }
    }

    pub(crate) async fn spawn(
        &self,
        operation_id: String,
        spec: SandboxSpec,
    ) -> Result<SandboxLease, SandboxError> {
        validate_operation_id(&operation_id)?;
        spec.validate_for_host_os(std::env::consts::OS)?;
        let incarnation = self
            .incarnation
            .as_ref()
            .ok_or_else(|| {
                SandboxError::Internal("could not initialize daemon incarnation".to_owned())
            })?
            .clone();

        let slot = self.get_or_insert_slot(&operation_id);
        let mut operation = slot.lock().await;

        let directory = self.runtime.config().state_dir.join("spawn-operations");
        let spec_path = directory.join(format!("{operation_id}.spec"));
        let pending_path = directory.join(format!("{operation_id}.pending"));
        let result_path = directory.join(format!("{operation_id}.result"));
        let expected = ControlRequest::Spawn { spec: spec.clone() }.to_json_bytes()?;

        let dir_for_prep = directory.clone();
        let spec_path_for_prep = spec_path.clone();
        let pending_path_for_prep = pending_path.clone();
        let result_path_for_prep = result_path.clone();
        let incarnation_for_prep = incarnation.clone();
        let prepared_state = tokio::task::spawn_blocking(move || {
            ensure_operation_dir(&dir_for_prep)?;
            match read_record(&spec_path_for_prep)? {
                Some(existing) if existing != expected => {
                    return Err(SandboxError::PolicyViolation(
                        "operation UUID is associated with a different sandbox spec".to_owned(),
                    ));
                }
                Some(_) => {}
                None => write_record(&dir_for_prep, &spec_path_for_prep, &expected)?,
            }
            let result_bytes = read_record(&result_path_for_prep)?;
            let pending_bytes = if result_bytes.is_none() {
                read_record(&pending_path_for_prep)?
            } else {
                None
            };
            Ok((result_bytes, pending_bytes))
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("keyed spawn disk task failed: {err}")))??;

        let (result_bytes, pending_bytes) = prepared_state;
        if operation.lease.is_none() {
            if let Some(result) = result_bytes {
                let record: serde_json::Value = serde_json::from_slice(&result)
                    .map_err(|_| SandboxError::Internal("invalid keyed spawn result".to_owned()))?;
                let stored_incarnation = record
                    .get("incarnation")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        SandboxError::Internal("invalid keyed spawn result".to_owned())
                    })?;
                if stored_incarnation != incarnation {
                    return Err(SandboxError::LeaseExpired(
                        "keyed spawn belongs to a previous daemon incarnation".to_owned(),
                    ));
                }
                let response = record.get("response").ok_or_else(|| {
                    SandboxError::Internal("invalid keyed spawn result".to_owned())
                })?;
                match ControlResponse::from_json_value(response)? {
                    ControlResponse::Spawned(lease) => operation.lease = Some(lease),
                    _ => {
                        return Err(SandboxError::Internal(
                            "invalid keyed spawn result".to_owned(),
                        ));
                    }
                }
            }
        }

        if operation.lease.is_none() {
            if let Some(pending) = pending_bytes {
                let record: serde_json::Value = serde_json::from_slice(&pending).map_err(|_| {
                    SandboxError::Internal("invalid keyed spawn pending record".to_owned())
                })?;
                let stored_incarnation = record
                    .get("incarnation")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        SandboxError::Internal("invalid keyed spawn pending record".to_owned())
                    })?;
                if stored_incarnation != incarnation {
                    self.ensure_startup_recovered().await?;
                    return Err(SandboxError::LeaseExpired(
                        "keyed spawn belongs to a previous interrupted daemon incarnation"
                            .to_owned(),
                    ));
                }
            }

            // A prior daemon may have died after spawn and before writing its result.
            // Reconcile all old journals once at startup before allowing new creations.
            self.ensure_startup_recovered().await?;

            let dir_for_pending = directory.clone();
            let pending_path_for_write = pending_path.clone();
            let pending_payload = serde_json::to_vec(&serde_json::json!({
                "incarnation": incarnation_for_prep,
            }))
            .map_err(|_| SandboxError::Internal("cannot encode keyed spawn pending record".to_owned()))?;
            tokio::task::spawn_blocking(move || {
                write_record(&dir_for_pending, &pending_path_for_write, &pending_payload)
            })
            .await
            .map_err(|err| SandboxError::Internal(format!("pending write task failed: {err}")))??;

            match self.runtime.spawn(spec).await {
                Ok(lease) => operation.lease = Some(lease),
                Err(error) => {
                    let pending_for_cleanup = pending_path.clone();
                    let _ = tokio::task::spawn_blocking(move || remove_file_if_present(&pending_for_cleanup)).await;
                    return Err(error);
                }
            }
        }

        let lease = operation.lease.as_ref().expect("lease set after spawn").clone();
        let result_path_for_commit = result_path.clone();
        let pending_path_for_commit = pending_path.clone();
        let dir_for_commit = directory.clone();
        let record_bytes = serde_json::to_vec(&serde_json::json!({
            "incarnation": incarnation,
            "response": ControlResponse::Spawned(lease.clone()).to_json_value(),
        }))
        .map_err(|_| SandboxError::Internal("cannot encode keyed spawn result".to_owned()))?;
        tokio::task::spawn_blocking(move || {
            if read_record(&result_path_for_commit)?.is_none() {
                write_record(&dir_for_commit, &result_path_for_commit, &record_bytes)?;
            }
            let _ = remove_file_if_present(&pending_path_for_commit);
            Ok::<(), SandboxError>(())
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("result write task failed: {err}")))??;

        match self.runtime.active_sandbox_network(&lease.id) {
            Ok(_) => {}
            Err(error @ SandboxError::Transport(_)) => {
                if !self.runtime.sandbox_process_exited(&lease.id)? {
                    return Err(error);
                }
                return match self.runtime.destroy(&lease.id).await? {
                    DestroyStatus::AllResourcesCleaned => Err(SandboxError::LeaseExpired(
                        "keyed spawn's sandbox has exited".to_owned(),
                    )),
                    DestroyStatus::ProcessExited { .. } => Err(SandboxError::AdmissionRejected(
                        "keyed sandbox cleanup is still in progress".to_owned(),
                    )),
                };
            }
            Err(SandboxError::NotFound(_) | SandboxError::LeaseExpired(_)) => {
                let id = lease.id.as_str();
                if id.is_empty()
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                {
                    return Err(SandboxError::PolicyViolation(
                        "invalid keyed sandbox ID".to_owned(),
                    ));
                }
                let still_active = self
                    .runtime
                    .list_active_sandboxes()
                    .iter()
                    .any(|item| item.id == lease.id);
                let journal_path = self
                    .runtime
                    .config()
                    .state_dir
                    .join("journals")
                    .join(format!("{id}.journal"));
                if still_active {
                    return Err(SandboxError::AdmissionRejected(
                        "keyed sandbox cleanup is still in progress".to_owned(),
                    ));
                }
                let has_journal = tokio::task::spawn_blocking(move || read_record(&journal_path))
                    .await
                    .map_err(|err| {
                        SandboxError::Internal(format!("journal probe task failed: {err}"))
                    })??
                    .is_some();
                if has_journal
                    && matches!(
                        self.runtime.destroy(&lease.id).await?,
                        DestroyStatus::ProcessExited { .. }
                    )
                {
                    return Err(SandboxError::AdmissionRejected(
                        "keyed sandbox cleanup is still in progress".to_owned(),
                    ));
                }
                return Err(SandboxError::LeaseExpired(
                    "keyed spawn's sandbox is no longer active".to_owned(),
                ));
            }
            Err(error) => return Err(error),
        }
        Ok(lease)
    }

    fn get_or_insert_slot(&self, operation_id: &str) -> Arc<AsyncMutex<Operation>> {
        let mut operations = self
            .operations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = operations.get(operation_id) {
            return Arc::clone(existing);
        }
        if operations.len() >= MAX_CACHED_OPERATIONS {
            operations.retain(|_, arc| {
                if Arc::strong_count(arc) > 1 {
                    return true;
                }
                let Ok(guard) = arc.try_lock() else {
                    return true;
                };
                guard
                    .lease
                    .as_ref()
                    .is_some_and(|lease| self.runtime.active_sandbox_network(&lease.id).is_ok())
            });
        }
        Arc::clone(operations.entry(operation_id.to_owned()).or_default())
    }

    async fn ensure_startup_recovered(&self) -> Result<(), SandboxError> {
        let mut recovered = self.recovery_checked.lock().await;
        if !*recovered {
            let report = self.runtime.reconcile_startup().await?;
            if report.remaining != 0 {
                return Err(SandboxError::Internal(
                    "keyed spawn is waiting for sandbox recovery".to_owned(),
                ));
            }
            *recovered = true;
        }
        Ok(())
    }
}

fn ensure_operation_dir(directory: &Path) -> Result<(), SandboxError> {
    #[cfg(windows)]
    {
        if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
            ensure_safe_dir_path(parent, true)?;
        }
        sandbox_vmm::os::windows::create_owner_only_dir(directory)?;
    }
    ensure_safe_dir_path(directory, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| map_fs_error(directory, "secure operation directory", error))?;
    }
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<(), SandboxError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_fs_error(path, "remove operation record", error)),
    }
}

fn validate_operation_id(id: &str) -> Result<(), SandboxError> {
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(SandboxError::InvalidSpec(
            "operation ID must be a lowercase UUID".to_owned(),
        ));
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<Option<Vec<u8>>, SandboxError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_fs_error(path, "open operation record", error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| map_fs_error(path, "inspect operation record", error))?;
    reject_symlink_or_reparse(path, &metadata)?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(SandboxError::PolicyViolation(
            "invalid keyed spawn record".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| map_fs_error(path, "read operation record", error))?;
    if bytes.len() > 65536 {
        return Err(SandboxError::PolicyViolation(
            "invalid keyed spawn record".to_owned(),
        ));
    }
    Ok(Some(bytes))
}

fn write_record(directory: &Path, path: &Path, data: &[u8]) -> Result<(), SandboxError> {
    let temp: PathBuf = directory.join(format!(
        ".spawn-{}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| map_fs_error(&temp, "create operation record", error))?;
    let result = (|| {
        file.write_all(data)
            .map_err(|error| map_fs_error(&temp, "write operation record", error))?;
        file.sync_all()
            .map_err(|error| map_fs_error(&temp, "sync operation record", error))?;
        drop(file);
        fs::rename(&temp, path)
            .map_err(|error| map_fs_error(path, "commit operation record", error))?;
        #[cfg(unix)]
        fs::File::open(directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| map_fs_error(directory, "sync operation directory", error))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
