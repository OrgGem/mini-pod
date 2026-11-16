//! Layer 2 `RuntimeManager` implementation: sandbox lifecycle orchestration,
//! durable crash journaling, TTL lease enforcement, and safe workspace copy I/O.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::{
    CapabilityReport, DestroyStatus, EnforcementLevel, ExecRequest, ExecTarget, IsolationMode,
    NetworkPolicy, SandboxError, SandboxId, SandboxLease, SandboxSpec,
};
use sandbox_protocol::StreamTargetWire;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::admission::{AdmissionController, AdmissionLimits, AdmissionPermit, AdmissionUsage};
use crate::egress::{
    HostDnsResolver, HostEgressProxy, SystemDnsResolver, TcpUpstreamDialer, UpstreamDialer,
};
use crate::exec_stream::ExecStream;
use crate::journal::{
    cleanup_artifacts_with_backoff, JournalLifecycleState, JournalRecord, JournalStore,
};
use crate::ports::{
    DiskOverlayPort, PreparedOverlay, SandboxTunnelPort, VmBootConfig, VmRuntimePort,
    VmSessionPort,
};
use crate::safe_tar::{
    ensure_safe_dir_path, extract_tar_safely, measure_dir_bytes, pack_host_path_to_tar,
};
use crate::tunnel::TunnelStream;
use crate::RuntimeManager;

const MAX_GUEST_PATH_BYTES: usize = 4096;
const QCOW2_STORAGE_HEADROOM_MB: u64 = 16;

/// Configuration for [`LocalRuntimeManager`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeManagerConfig {
    pub state_dir: PathBuf,
    pub sweep_interval: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub max_copy_bytes: u64,
    pub max_copy_entries: usize,
    pub cleanup_max_attempts: usize,
    pub cleanup_initial_delay: Duration,
    pub admission: AdmissionLimits,
}

impl Default for RuntimeManagerConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("minipod-state"),
            sweep_interval: Duration::from_secs(5),
            graceful_shutdown_timeout: Duration::from_secs(5),
            max_copy_bytes: 64 * 1024 * 1024,
            max_copy_entries: 16_384,
            cleanup_max_attempts: 8,
            cleanup_initial_delay: Duration::from_millis(50),
            admission: AdmissionLimits::default(),
        }
    }
}

impl RuntimeManagerConfig {
    /// Validates nonzero bounds and paths required for safe runtime execution.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.state_dir.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "state_dir cannot be empty".to_owned(),
            ));
        }
        if self.sweep_interval.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "sweep_interval must be greater than zero".to_owned(),
            ));
        }
        if self.graceful_shutdown_timeout.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "graceful_shutdown_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.max_copy_bytes == 0 {
            return Err(SandboxError::InvalidSpec(
                "max_copy_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_copy_entries == 0 {
            return Err(SandboxError::InvalidSpec(
                "max_copy_entries must be greater than zero".to_owned(),
            ));
        }
        if self.cleanup_max_attempts == 0 {
            return Err(SandboxError::InvalidSpec(
                "cleanup_max_attempts must be greater than zero".to_owned(),
            ));
        }
        if self.cleanup_initial_delay.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "cleanup_initial_delay must be greater than zero".to_owned(),
            ));
        }
        self.admission.validate()?;
        Ok(())
    }
}

/// Summary returned by [`LocalRuntimeManager::reconcile_startup`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub records_seen: usize,
    pub orphans_killed: usize,
    pub cleaned: usize,
    pub remaining: usize,
}

struct EgressProxyHandle {
    shutdown_tx: watch::Sender<bool>,
    acceptor: Option<JoinHandle<()>>,
}

impl EgressProxyHandle {
    async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.acceptor.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for EgressProxyHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.acceptor.take() {
            handle.abort();
        }
    }
}

fn spawn_egress_acceptor(
    proxy: Arc<HostEgressProxy>,
    mut rx: tokio::sync::mpsc::Receiver<TunnelStream>,
) -> EgressProxyHandle {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let acceptor = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                maybe_stream = rx.recv() => {
                    match maybe_stream {
                        Some(stream) => {
                            let proxy = Arc::clone(&proxy);
                            tasks.spawn(async move {
                                proxy.handle_stream(stream).await;
                            });
                        }
                        None => break,
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });

    EgressProxyHandle {
        shutdown_tx,
        acceptor: Some(acceptor),
    }
}

struct ActiveSandbox {
    session: Arc<dyn VmSessionPort>,
    work_dir: PathBuf,
    overlay_path: PathBuf,
    artifact_paths: Vec<PathBuf>,
    expires_at: Instant,
    reserved_rss_mb: u64,
    host_rss_budget_mb: Option<u32>,
    host_storage_budget_mb: u32,
    egress_proxy: Option<EgressProxyHandle>,
    // Drop `permit` last so session/proxy tasks tear down before admission capacity re-opens.
    permit: AdmissionPermit,
}

struct DestroySlotGuard<'a> {
    map: &'a Mutex<HashMap<SandboxId, watch::Sender<bool>>>,
    id: SandboxId,
    notify_done: watch::Sender<bool>,
}

impl Drop for DestroySlotGuard<'_> {
    fn drop(&mut self) {
        {
            let mut guard = lock_unpoisoned(self.map);
            guard.remove(&self.id);
        }
        let _ = self.notify_done.send(true);
    }
}

/// Layer 2 `RuntimeManager` orchestrating VMs, disk overlays, leases, and crash recovery.
pub struct LocalRuntimeManager {
    config: RuntimeManagerConfig,
    journal: JournalStore,
    sandboxes_dir: PathBuf,
    overlay: Arc<dyn DiskOverlayPort>,
    vm_runtime: Arc<dyn VmRuntimePort>,
    dns_resolver: Arc<dyn HostDnsResolver>,
    dialer: Arc<dyn UpstreamDialer>,
    admission: AdmissionController,
    active: Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    in_flight_destroys: Mutex<HashMap<SandboxId, watch::Sender<bool>>>,
    sweeper_abort: Mutex<Option<tokio::task::AbortHandle>>,
    next_seq: AtomicU64,
}

impl Drop for LocalRuntimeManager {
    fn drop(&mut self) {
        let mut guard = lock_unpoisoned(&self.sweeper_abort);
        if let Some(handle) = guard.take() {
            handle.abort();
        }
    }
}

impl LocalRuntimeManager {
    /// Initializes durable state directories (`journals/`, `sandboxes/`) and constructs a manager
    /// with default [`SystemDnsResolver`] and [`TcpUpstreamDialer`] egress hooks.
    pub fn new(
        config: RuntimeManagerConfig,
        overlay: Arc<dyn DiskOverlayPort>,
        vm_runtime: Arc<dyn VmRuntimePort>,
    ) -> Result<Self, SandboxError> {
        Self::with_egress_hooks(
            config,
            overlay,
            vm_runtime,
            Arc::new(SystemDnsResolver),
            Arc::new(TcpUpstreamDialer),
        )
    }

    /// Initializes durable state directories (`journals/`, `sandboxes/`) with explicit egress hooks.
    pub fn with_egress_hooks(
        config: RuntimeManagerConfig,
        overlay: Arc<dyn DiskOverlayPort>,
        vm_runtime: Arc<dyn VmRuntimePort>,
        dns_resolver: Arc<dyn HostDnsResolver>,
        dialer: Arc<dyn UpstreamDialer>,
    ) -> Result<Self, SandboxError> {
        config.validate()?;
        ensure_safe_dir_path(&config.state_dir, true)?;
        let journal = JournalStore::new(config.state_dir.join("journals"))?;
        let sandboxes_dir = config.state_dir.join("sandboxes");
        ensure_safe_dir_path(&sandboxes_dir, true)?;

        let active = Arc::new(Mutex::new(HashMap::<SandboxId, ActiveSandbox>::new()));
        let active_for_rss = Arc::clone(&active);
        let observed_rss_fn = Arc::new(move || -> u64 {
            let entries: Vec<(Arc<dyn VmSessionPort>, u64)> = {
                let guard = lock_unpoisoned(&active_for_rss);
                guard
                    .values()
                    .map(|entry| (Arc::clone(&entry.session), entry.reserved_rss_mb))
                    .collect()
            };
            entries
                .into_iter()
                .map(|(session, reserved_mb)| {
                    let live_mb = session
                        .current_rss_bytes()
                        .map(bytes_to_mib_ceil)
                        .unwrap_or(0);
                    reserved_mb.max(live_mb)
                })
                .sum()
        });
        let admission = AdmissionController::new(config.admission.clone(), observed_rss_fn);

        Ok(Self {
            config,
            journal,
            sandboxes_dir,
            overlay,
            vm_runtime,
            dns_resolver,
            dialer,
            admission,
            active,
            in_flight_destroys: Mutex::new(HashMap::new()),
            sweeper_abort: Mutex::new(None),
            next_seq: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> &RuntimeManagerConfig {
        &self.config
    }

    /// Returns a snapshot of current host admission reservations and effective live RSS.
    pub fn current_admission_usage(&self) -> AdmissionUsage {
        self.admission.usage()
    }

    /// Samples the live host resident set size (`RSS` / working set) in bytes for an active sandbox.
    pub fn sandbox_current_rss_bytes(&self, id: &SandboxId) -> Option<u64> {
        let session = {
            let active = lock_unpoisoned(&self.active);
            active.get(id).map(|entry| Arc::clone(&entry.session))
        }?;
        session.current_rss_bytes()
    }

    /// Starts the background lease sweeper; aborted automatically when [`LocalRuntimeManager`] drops.
    pub fn spawn_lease_sweeper(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        let sweep_interval = self.config.sweep_interval;
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(sweep_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(mgr) = weak.upgrade() else {
                    break;
                };
                let _ = mgr.sweep_expired_leases().await;
                let _ = mgr.enforce_resource_budgets().await;
            }
        });

        let mut guard = lock_unpoisoned(&self.sweeper_abort);
        if let Some(prev) = guard.replace(handle.abort_handle()) {
            prev.abort();
        }
        handle
    }

    /// Reconciles persisted crash-recovery journals on daemon startup, killing verified orphans
    /// and cleaning remaining sandbox artifacts.
    pub async fn reconcile_startup(&self) -> Result<ReconciliationReport, SandboxError> {
        let records = self.load_records_async().await?;
        let mut report = ReconciliationReport::default();

        for record in records {
            let is_live = {
                let active = lock_unpoisoned(&self.active);
                active.contains_key(&record.sandbox_id)
            };
            if is_live {
                continue;
            }

            report.records_seen += 1;

            let mut kill_failed = false;
            if let (Some(pid), Some(start_token)) = (record.pid, record.start_token) {
                match self.vm_runtime.kill_orphan_process(pid, start_token).await {
                    Ok(true) => report.orphans_killed += 1,
                    Ok(false) | Err(SandboxError::NotFound(_)) => {}
                    Err(_) => {
                        kill_failed = true;
                    }
                }
            }

            if kill_failed {
                report.remaining += 1;
                continue;
            }

            self.remove_overlay_artifacts(&record.artifact_paths).await;

            match cleanup_artifacts_with_backoff(
                &record.artifact_paths,
                self.config.cleanup_max_attempts,
                self.config.cleanup_initial_delay,
            )
            .await
            {
                DestroyStatus::AllResourcesCleaned => {
                    self.remove_journal_async(record.sandbox_id).await?;
                    report.cleaned += 1;
                }
                DestroyStatus::ProcessExited {
                    remaining_artifacts,
                } => {
                    self.write_journal_async(JournalRecord {
                        sandbox_id: record.sandbox_id,
                        state: JournalLifecycleState::Destroying,
                        pid: None,
                        start_token: None,
                        artifact_paths: remaining_artifacts,
                        expires_at_unix_ms: record.expires_at_unix_ms,
                    })
                    .await?;
                    report.remaining += 1;
                }
            }
        }

        Ok(report)
    }

    /// Destroys all active sandboxes whose lease TTL has elapsed and returns the swept count.
    pub async fn sweep_expired_leases(&self) -> usize {
        let now = Instant::now();
        let expired_ids: Vec<SandboxId> = {
            let active = lock_unpoisoned(&self.active);
            active
                .iter()
                .filter_map(|(id, entry)| {
                    if now >= entry.expires_at {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        let mut swept = 0usize;
        for id in expired_ids {
            if self.destroy(&id).await.is_ok() {
                swept += 1;
            }
        }
        swept
    }

    /// Reaps active sandboxes whose physical host storage or live RSS exceeds their configured
    /// [`sandbox_core::ResourceBudget`] ceilings, returning the number destroyed.
    pub async fn enforce_resource_budgets(&self) -> usize {
        struct BudgetCandidate {
            id: SandboxId,
            work_dir: PathBuf,
            session: Arc<dyn VmSessionPort>,
            host_storage_budget_mb: u32,
            host_rss_budget_mb: Option<u32>,
        }

        let snapshot: Vec<BudgetCandidate> = {
            let active = lock_unpoisoned(&self.active);
            active
                .iter()
                .map(|(id, entry)| BudgetCandidate {
                    id: id.clone(),
                    work_dir: entry.work_dir.clone(),
                    session: Arc::clone(&entry.session),
                    host_storage_budget_mb: entry.host_storage_budget_mb,
                    host_rss_budget_mb: entry.host_rss_budget_mb,
                })
                .collect()
        };
        if snapshot.is_empty() {
            return 0;
        }

        let mut breached_ids = Vec::new();
        let mut storage_checks = Vec::new();
        for item in snapshot {
            let rss_breached = match (item.host_rss_budget_mb, item.session.current_rss_bytes()) {
                (Some(limit_mb), Some(rss_bytes)) => {
                    rss_bytes > u64::from(limit_mb).saturating_mul(1024 * 1024)
                }
                _ => false,
            };
            if rss_breached {
                breached_ids.push(item.id);
            } else {
                storage_checks.push((
                    item.id,
                    item.work_dir,
                    u64::from(item.host_storage_budget_mb).saturating_mul(1024 * 1024),
                ));
            }
        }

        if !storage_checks.is_empty() {
            let journal = self.journal.clone();
            if let Ok(over_storage) = tokio::task::spawn_blocking(move || {
                let mut exceeded = Vec::new();
                for (id, work_dir, storage_limit_bytes) in storage_checks {
                    let work_bytes = measure_dir_bytes(&work_dir).unwrap_or(0);
                    let journal_bytes = journal.record_disk_bytes(&id).unwrap_or(0);
                    if work_bytes.saturating_add(journal_bytes) > storage_limit_bytes {
                        exceeded.push(id);
                    }
                }
                exceeded
            })
            .await
            {
                breached_ids.extend(over_storage);
            }
        }

        let mut reaped = 0usize;
        for id in breached_ids {
            if self.destroy(&id).await.is_ok() {
                reaped += 1;
            }
        }
        reaped
    }

    async fn measure_sandbox_storage_bytes(
        &self,
        id: &SandboxId,
        work_dir: &Path,
    ) -> Result<u64, SandboxError> {
        let journal = self.journal.clone();
        let id = id.clone();
        let work_dir = work_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let work_bytes = measure_dir_bytes(&work_dir)?;
            let journal_bytes = journal.record_disk_bytes(&id)?;
            Ok(work_bytes.saturating_add(journal_bytes))
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("storage measurement task failed: {err}")))?
    }

    async fn acquire_destroy_slot(&self, id: &SandboxId) -> DestroySlotGuard<'_> {
        loop {
            let existing_rx = {
                let mut map = lock_unpoisoned(&self.in_flight_destroys);
                if let Some(tx) = map.get(id) {
                    Some(tx.subscribe())
                } else {
                    let (tx, _rx) = watch::channel(false);
                    map.insert(id.clone(), tx.clone());
                    return DestroySlotGuard {
                        map: &self.in_flight_destroys,
                        id: id.clone(),
                        notify_done: tx,
                    };
                }
            };

            if let Some(mut rx) = existing_rx {
                let _ = rx.wait_for(|done| *done).await;
            }
        }
    }

    fn get_active_op_target(
        &self,
        id: &SandboxId,
    ) -> Result<(Arc<dyn VmSessionPort>, PathBuf, u32), SandboxError> {
        let now = Instant::now();
        {
            let active = lock_unpoisoned(&self.active);
            if let Some(entry) = active.get(id) {
                if now >= entry.expires_at {
                    return Err(SandboxError::LeaseExpired(format!(
                        "sandbox '{id}' lease has expired"
                    )));
                }
                if !entry.session.is_alive() {
                    return Err(SandboxError::Transport(format!(
                        "sandbox '{id}' VM process is no longer alive"
                    )));
                }
                return Ok((
                    Arc::clone(&entry.session),
                    entry.work_dir.clone(),
                    entry.host_storage_budget_mb,
                ));
            }
        }

        let destroying = {
            let map = lock_unpoisoned(&self.in_flight_destroys);
            map.contains_key(id)
        };
        if destroying {
            return Err(SandboxError::LeaseExpired(format!(
                "sandbox '{id}' is being destroyed"
            )));
        }

        Err(SandboxError::NotFound(format!(
            "sandbox '{id}' does not exist"
        )))
    }

    fn get_active_session_for_op(
        &self,
        id: &SandboxId,
    ) -> Result<Arc<dyn VmSessionPort>, SandboxError> {
        self.get_active_op_target(id).map(|(session, _, _)| session)
    }

    async fn rollback_spawn(
        &self,
        sandbox_id: &SandboxId,
        overlay_path: Option<&Path>,
        artifacts: Vec<PathBuf>,
        expires_at_unix_ms: u64,
    ) {
        if let Some(path) = overlay_path {
            let _ = self.overlay.remove_overlay(path).await;
        }
        match cleanup_artifacts_with_backoff(
            &artifacts,
            self.config.cleanup_max_attempts,
            self.config.cleanup_initial_delay,
        )
        .await
        {
            DestroyStatus::AllResourcesCleaned => {
                let _ = self.remove_journal_async(sandbox_id.clone()).await;
            }
            DestroyStatus::ProcessExited {
                remaining_artifacts,
            } => {
                let _ = self
                    .write_journal_async(JournalRecord {
                        sandbox_id: sandbox_id.clone(),
                        state: JournalLifecycleState::Destroying,
                        pid: None,
                        start_token: None,
                        artifact_paths: remaining_artifacts,
                        expires_at_unix_ms,
                    })
                    .await;
            }
        }
    }

    async fn remove_overlay_artifacts(&self, paths: &[PathBuf]) {
        for path in paths {
            if is_overlay_artifact(path) {
                let _ = self.overlay.remove_overlay(path).await;
            }
        }
    }

    async fn write_journal_async(&self, record: JournalRecord) -> Result<(), SandboxError> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.write_record(&record))
            .await
            .map_err(|err| SandboxError::Internal(format!("journal write task failed: {err}")))?
    }

    async fn load_record_async(
        &self,
        id: SandboxId,
    ) -> Result<Option<JournalRecord>, SandboxError> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.load_record(&id))
            .await
            .map_err(|err| SandboxError::Internal(format!("journal load task failed: {err}")))?
    }

    async fn load_records_async(&self) -> Result<Vec<JournalRecord>, SandboxError> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.load_records())
            .await
            .map_err(|err| SandboxError::Internal(format!("journal scan task failed: {err}")))?
    }

    async fn remove_journal_async(&self, id: SandboxId) -> Result<(), SandboxError> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.remove_record(&id))
            .await
            .map_err(|err| SandboxError::Internal(format!("journal remove task failed: {err}")))?
    }
}

#[async_trait::async_trait]
impl RuntimeManager for LocalRuntimeManager {
    async fn spawn(&self, spec: SandboxSpec) -> Result<SandboxLease, SandboxError> {
        if spec.isolation == IsolationMode::SharedKernelAllowed {
            return Err(SandboxError::UnsupportedIsolationMode(
                "SharedKernelAllowed is not permitted when VmRequired runtime enforcement is active"
                    .to_owned(),
            ));
        }
        spec.validate_for_host_os(std::env::consts::OS)?;
        if spec.budget.virtual_disk_mb > spec.budget.host_storage_budget_mb {
            return Err(SandboxError::BudgetExceeded(format!(
                "requested virtual_disk_mb ({} MiB) exceeds host_storage_budget_mb ({} MiB)",
                spec.budget.virtual_disk_mb, spec.budget.host_storage_budget_mb
            )));
        }

        let permit = self.admission.acquire(&spec).await?;

        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let sandbox_id = SandboxId::new(format!("mp-{}-{seq}", std::process::id()));
        let work_dir = self.sandboxes_dir.join(sandbox_id.as_str());

        let work_dir_for_create = work_dir.clone();
        tokio::task::spawn_blocking(move || ensure_safe_dir_path(&work_dir_for_create, true))
            .await
            .map_err(|err| {
                SandboxError::Internal(format!("create sandbox work_dir task failed: {err}"))
            })??;

        let initial_expires_ms = expires_at_unix_ms(spec.lease_ttl);
        if let Err(err) = self
            .write_journal_async(JournalRecord {
                sandbox_id: sandbox_id.clone(),
                state: JournalLifecycleState::Spawning,
                pid: None,
                start_token: None,
                artifact_paths: vec![work_dir.clone()],
                expires_at_unix_ms: initial_expires_ms,
            })
            .await
        {
            let _ = cleanup_artifacts_with_backoff(
                std::slice::from_ref(&work_dir),
                self.config.cleanup_max_attempts,
                self.config.cleanup_initial_delay,
            )
            .await;
            return Err(err);
        }

        let prepared = match self
            .overlay
            .prepare_overlay(&sandbox_id, &spec, &work_dir)
            .await
        {
            Ok(overlay) => overlay,
            Err(err) => {
                self.rollback_spawn(&sandbox_id, None, vec![work_dir], initial_expires_ms)
                    .await;
                return Err(err);
            }
        };

        let spawn_artifacts = merge_artifact_paths(
            &[],
            std::slice::from_ref(&prepared.overlay_path),
            &work_dir,
        );
        if let Err(err) = self
            .write_journal_async(JournalRecord {
                sandbox_id: sandbox_id.clone(),
                state: JournalLifecycleState::Spawning,
                pid: None,
                start_token: None,
                artifact_paths: spawn_artifacts.clone(),
                expires_at_unix_ms: initial_expires_ms,
            })
            .await
        {
            self.rollback_spawn(
                &sandbox_id,
                Some(&prepared.overlay_path),
                spawn_artifacts,
                initial_expires_ms,
            )
            .await;
            return Err(err);
        }

        let boot_cfg = VmBootConfig {
            sandbox_id: sandbox_id.clone(),
            spec: spec.clone(),
            overlay: prepared.clone(),
            work_dir: work_dir.clone(),
        };
        let boot = match self.vm_runtime.boot_vm(boot_cfg).await {
            Ok(outcome) => outcome,
            Err(err) => {
                self.rollback_spawn(
                    &sandbox_id,
                    Some(&prepared.overlay_path),
                    spawn_artifacts,
                    initial_expires_ms,
                )
                .await;
                return Err(err);
            }
        };

        let session: Arc<dyn VmSessionPort> = Arc::from(boot.session);
        let all_artifacts = merge_artifact_paths(
            &boot.artifact_paths,
            std::slice::from_ref(&prepared.overlay_path),
            &work_dir,
        );
        let expires_at = Instant::now() + spec.lease_ttl;
        let active_expires_ms = expires_at_unix_ms(spec.lease_ttl);

        if let Err(err) = self
            .write_journal_async(JournalRecord {
                sandbox_id: sandbox_id.clone(),
                state: JournalLifecycleState::Active,
                pid: Some(boot.pid),
                start_token: Some(boot.start_token),
                artifact_paths: all_artifacts.clone(),
                expires_at_unix_ms: active_expires_ms,
            })
            .await
        {
            drop(boot.egress_rx);
            let graceful = session
                .graceful_shutdown(self.config.graceful_shutdown_timeout)
                .await
                .unwrap_or(false);
            if !graceful && session.is_alive() {
                let _ = session.force_kill().await;
            }
            drop(session);
            self.rollback_spawn(
                &sandbox_id,
                Some(&prepared.overlay_path),
                all_artifacts,
                active_expires_ms,
            )
            .await;
            return Err(err);
        }

        let egress_proxy = boot.egress_rx.map(|rx| {
            let proxy = Arc::new(HostEgressProxy::new(
                spec.network.clone(),
                Arc::clone(&self.dns_resolver),
                Arc::clone(&self.dialer),
            ));
            spawn_egress_acceptor(proxy, rx)
        });
        let capabilities = build_lease_capabilities(&spec, &prepared, boot.capabilities);
        let reserved_rss_mb = permit.demand().rss_mb;
        let replaced = {
            let mut active = lock_unpoisoned(&self.active);
            active.insert(
                sandbox_id.clone(),
                ActiveSandbox {
                    session,
                    work_dir,
                    overlay_path: prepared.overlay_path,
                    artifact_paths: all_artifacts,
                    expires_at,
                    reserved_rss_mb,
                    host_rss_budget_mb: spec.budget.host_rss_budget_mb,
                    host_storage_budget_mb: spec.budget.host_storage_budget_mb,
                    egress_proxy,
                    permit,
                },
            )
        };
        drop(replaced);

        Ok(SandboxLease {
            id: sandbox_id,
            ttl: spec.lease_ttl,
            capabilities,
        })
    }

    async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError> {
        if ttl.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "lease ttl must be greater than zero".to_owned(),
            ));
        }

        let new_expires_ms = expires_at_unix_ms(ttl);
        let updated_record = {
            let now = Instant::now();
            let destroying = {
                let map = lock_unpoisoned(&self.in_flight_destroys);
                map.contains_key(id)
            };
            if destroying {
                return Err(SandboxError::LeaseExpired(format!(
                    "sandbox '{id}' is being destroyed"
                )));
            }

            let mut active = lock_unpoisoned(&self.active);
            let Some(entry) = active.get_mut(id) else {
                return Err(SandboxError::NotFound(format!(
                    "sandbox '{id}' does not exist"
                )));
            };
            if now >= entry.expires_at {
                return Err(SandboxError::LeaseExpired(format!(
                    "sandbox '{id}' lease has expired"
                )));
            }
            if !entry.session.is_alive() {
                return Err(SandboxError::Transport(format!(
                    "sandbox '{id}' VM process is no longer alive"
                )));
            }
            entry.expires_at = now + ttl;
            JournalRecord {
                sandbox_id: id.clone(),
                state: JournalLifecycleState::Active,
                pid: Some(entry.session.pid()),
                start_token: Some(entry.session.start_token()),
                artifact_paths: entry.artifact_paths.clone(),
                expires_at_unix_ms: new_expires_ms,
            }
        };

        self.write_journal_async(updated_record).await?;

        let still_active = {
            let active = lock_unpoisoned(&self.active);
            active.contains_key(id)
        };
        if !still_active {
            return Err(SandboxError::LeaseExpired(format!(
                "sandbox '{id}' was destroyed while renewing lease"
            )));
        }
        Ok(())
    }

    async fn exec_stream(
        &self,
        id: &SandboxId,
        req: ExecRequest,
    ) -> Result<ExecStream, SandboxError> {
        validate_exec_request(&req)?;
        let session = self.get_active_session_for_op(id)?;
        session.exec_stream(req).await
    }

    async fn copy_in(
        &self,
        id: &SandboxId,
        src_host: PathBuf,
        dst_guest: String,
    ) -> Result<(), SandboxError> {
        validate_guest_path(&dst_guest, "dst_guest")?;
        let (session, work_dir, host_storage_budget_mb) = self.get_active_op_target(id)?;
        let storage_budget_bytes = u64::from(host_storage_budget_mb).saturating_mul(1024 * 1024);

        let pre_bytes = self.measure_sandbox_storage_bytes(id, &work_dir).await?;
        if pre_bytes > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "sandbox '{id}' physical storage ({pre_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)"
            )));
        }

        let max_copy_bytes = self.config.max_copy_bytes;
        let remaining_storage_bytes = storage_budget_bytes.saturating_sub(pre_bytes);
        let pack_budget = max_copy_bytes.min(remaining_storage_bytes);

        let tar_bytes =
            tokio::task::spawn_blocking(move || pack_host_path_to_tar(&src_host, pack_budget))
                .await
                .map_err(|err| {
                    SandboxError::Internal(format!("copy_in tar packing failed: {err}"))
                })??;

        if pre_bytes.saturating_add(tar_bytes.len() as u64) > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in archive ({} bytes) plus existing storage ({pre_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)",
                tar_bytes.len()
            )));
        }

        let _ = session
            .copy_in_tar(&dst_guest, tar_bytes, max_copy_bytes)
            .await?;

        let post_bytes = self.measure_sandbox_storage_bytes(id, &work_dir).await?;
        if post_bytes > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "sandbox '{id}' physical storage after copy_in ({post_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)"
            )));
        }

        Ok(())
    }

    async fn copy_out(
        &self,
        id: &SandboxId,
        src_guest: String,
        dst_host: PathBuf,
    ) -> Result<(), SandboxError> {
        validate_guest_path(&src_guest, "src_guest")?;
        let session = self.get_active_session_for_op(id)?;
        let max_bytes = self.config.max_copy_bytes;
        let max_entries = self.config.max_copy_entries;

        let tar_bytes = session.copy_out_tar(&src_guest, max_bytes).await?;

        tokio::task::spawn_blocking(move || {
            extract_tar_safely(&tar_bytes, &dst_host, max_bytes, max_entries)
        })
        .await
        .map_err(|err| {
            SandboxError::Internal(format!("copy_out tar extraction failed: {err}"))
        })??;
        Ok(())
    }

    async fn destroy(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError> {
        let _slot = self.acquire_destroy_slot(id).await;

        let removed_active = {
            let mut active = lock_unpoisoned(&self.active);
            active.remove(id)
        };
        let journal_rec = self.load_record_async(id.clone()).await?;

        if removed_active.is_none() && journal_rec.is_none() {
            return Ok(DestroyStatus::AllResourcesCleaned);
        }

        let expires_at_unix_ms = journal_rec
            .as_ref()
            .map(|rec| rec.expires_at_unix_ms)
            .unwrap_or_else(unix_now_ms);

        let (overlay_path_opt, artifacts, _permit_guard) = if let Some(entry) = removed_active {
            let ActiveSandbox {
                session,
                work_dir: _,
                overlay_path,
                artifact_paths: entry_artifacts,
                expires_at: _,
                reserved_rss_mb: _,
                host_rss_budget_mb: _,
                host_storage_budget_mb: _,
                egress_proxy,
                permit,
            } = entry;

            let journal_paths = journal_rec
                .as_ref()
                .map(|rec| rec.artifact_paths.as_slice())
                .unwrap_or(&[]);
            let mut merged = merge_artifact_paths(
                &entry_artifacts,
                journal_paths,
                &self.sandboxes_dir.join(id.as_str()),
            );
            push_unique_path(&mut merged, &overlay_path);

            self.write_journal_async(JournalRecord {
                sandbox_id: id.clone(),
                state: JournalLifecycleState::Destroying,
                pid: Some(session.pid()),
                start_token: Some(session.start_token()),
                artifact_paths: merged.clone(),
                expires_at_unix_ms,
            })
            .await?;

            let graceful_ok = session
                .graceful_shutdown(self.config.graceful_shutdown_timeout)
                .await
                .unwrap_or(false);
            if !graceful_ok && session.is_alive() {
                session.force_kill().await?;
            }
            // Drop session ownership before removing overlays/sockets so Windows releases all handles,
            // and shut down all proxy tasks before cleanup completes.
            drop(session);
            if let Some(proxy) = egress_proxy {
                proxy.shutdown().await;
            }
            (Some(overlay_path), merged, Some(permit))
        } else if let Some(rec) = journal_rec {
            if let (Some(pid), Some(start_token)) = (rec.pid, rec.start_token) {
                match self.vm_runtime.kill_orphan_process(pid, start_token).await {
                    Ok(_) | Err(SandboxError::NotFound(_)) => {}
                    Err(err) => return Err(err),
                }
            }
            (None, rec.artifact_paths, None)
        } else {
            return Ok(DestroyStatus::AllResourcesCleaned);
        };

        if let Some(overlay_path) = overlay_path_opt {
            let _ = self.overlay.remove_overlay(&overlay_path).await;
        }
        self.remove_overlay_artifacts(&artifacts).await;

        let result = match cleanup_artifacts_with_backoff(
            &artifacts,
            self.config.cleanup_max_attempts,
            self.config.cleanup_initial_delay,
        )
        .await
        {
            DestroyStatus::AllResourcesCleaned => {
                self.remove_journal_async(id.clone()).await?;
                Ok(DestroyStatus::AllResourcesCleaned)
            }
            DestroyStatus::ProcessExited {
                remaining_artifacts,
            } => {
                self.write_journal_async(JournalRecord {
                    sandbox_id: id.clone(),
                    state: JournalLifecycleState::Destroying,
                    pid: None,
                    start_token: None,
                    artifact_paths: remaining_artifacts.clone(),
                    expires_at_unix_ms,
                })
                .await?;
                Ok(DestroyStatus::ProcessExited {
                    remaining_artifacts,
                })
            }
        };
        drop(_permit_guard);
        result
    }
}

#[async_trait::async_trait]
impl SandboxTunnelPort for LocalRuntimeManager {
    async fn open_podman_unix_stream(&self, id: &SandboxId) -> Result<TunnelStream, SandboxError> {
        let session = self.get_active_session_for_op(id)?;
        session.open_tunnel(StreamTargetWire::PodmanUnixSocket).await
    }

    async fn open_guest_tcp_stream(
        &self,
        id: &SandboxId,
        guest_port: u16,
    ) -> Result<TunnelStream, SandboxError> {
        if guest_port == 0 {
            return Err(SandboxError::InvalidSpec(
                "guest_port must be greater than zero".to_owned(),
            ));
        }
        let session = self.get_active_session_for_op(id)?;
        session
            .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: guest_port })
            .await
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn expires_at_unix_ms(ttl: Duration) -> u64 {
    let ttl_ms = ttl.as_millis().min(u128::from(u64::MAX)) as u64;
    unix_now_ms().saturating_add(ttl_ms)
}

/// Validates that a guest filesystem path argument is non-empty, bounded, and free of NUL bytes.
pub fn validate_guest_path(path: &str, field: &str) -> Result<(), SandboxError> {
    if path.is_empty() {
        return Err(SandboxError::InvalidSpec(format!(
            "{field} cannot be empty"
        )));
    }
    if path.len() > MAX_GUEST_PATH_BYTES {
        return Err(SandboxError::InvalidSpec(format!(
            "{field} exceeds maximum length of {MAX_GUEST_PATH_BYTES} bytes"
        )));
    }
    if path.contains('\0') {
        return Err(SandboxError::InvalidSpec(format!(
            "{field} cannot contain NUL bytes"
        )));
    }
    Ok(())
}

fn validate_exec_request(req: &ExecRequest) -> Result<(), SandboxError> {
    if req.argv.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "exec argv cannot be empty".to_owned(),
        ));
    }
    if req.deadline.is_zero() {
        return Err(SandboxError::InvalidSpec(
            "exec deadline must be greater than zero".to_owned(),
        ));
    }
    if let ExecTarget::Container { ref id_or_name } = req.target {
        if id_or_name.is_empty()
            || id_or_name.len() > 128
            || id_or_name.starts_with('-')
            || !id_or_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(SandboxError::InvalidSpec(
                "container exec target id_or_name must be 1..=128 ASCII [a-zA-Z0-9_.-] and cannot start with '-'".to_owned(),
            ));
        }
    }
    Ok(())
}

fn bytes_to_mib_ceil(bytes: u64) -> u64 {
    bytes.div_ceil(1024 * 1024)
}

fn build_lease_capabilities(
    spec: &SandboxSpec,
    prepared: &PreparedOverlay,
    boot_caps: CapabilityReport,
) -> CapabilityReport {
    let host_budget_bytes =
        u64::from(spec.budget.host_storage_budget_mb).saturating_mul(1024 * 1024);
    let virtual_disk_mb = u64::from(prepared.virtual_disk_mb.max(spec.budget.virtual_disk_mb));
    let host_storage = if virtual_disk_mb.saturating_add(QCOW2_STORAGE_HEADROOM_MB)
        <= u64::from(spec.budget.host_storage_budget_mb)
        && prepared.provisioned_host_bytes <= host_budget_bytes
    {
        EnforcementLevel::HardLimit
    } else {
        EnforcementLevel::BestEffort
    };
    let egress_filter = match &spec.network {
        NetworkPolicy::Isolated
        | NetworkPolicy::InternetOnly
        | NetworkPolicy::DomainAllowList { .. } => EnforcementLevel::HardLimit,
        NetworkPolicy::Unrestricted => EnforcementLevel::Unsupported,
    };
    CapabilityReport {
        cpu_quota: boot_caps.cpu_quota,
        host_rss: boot_caps.host_rss,
        host_storage,
        egress_filter,
    }
}

fn push_unique_path(dst: &mut Vec<PathBuf>, path: &Path) {
    if !dst.iter().any(|existing| existing == path) {
        dst.push(path.to_path_buf());
    }
}

fn merge_artifact_paths(
    primary: &[PathBuf],
    secondary: &[PathBuf],
    work_dir: &Path,
) -> Vec<PathBuf> {
    let mut merged = Vec::new();
    for path in primary.iter().chain(secondary.iter()) {
        if path != work_dir {
            push_unique_path(&mut merged, path);
        }
    }
    push_unique_path(&mut merged, work_dir);
    merged
}

fn is_overlay_artifact(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("qcow2")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashSet};
    use std::fs;
    use std::sync::atomic::AtomicBool;

    use sandbox_core::{AccelerationPolicy, EgressRule, ExecExitStatus, ResourceBudget};
    use sandbox_protocol::StreamId;

    use crate::exec_stream::{ExecOutputChunk, OutputStreamKind};
    use crate::ports::{PreparedOverlay, VmBootOutcome};
    use crate::test_util::TestTempDir;

    fn valid_spec(ttl: Duration) -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: None,
                guest_ram_mb: 256,
                host_rss_budget_mb: Some(512),
                virtual_disk_mb: 512,
                host_storage_budget_mb: 1024,
            },
            lease_ttl: ttl,
        }
    }

    fn base_config(state_dir: PathBuf) -> RuntimeManagerConfig {
        RuntimeManagerConfig {
            state_dir,
            sweep_interval: Duration::from_millis(20),
            graceful_shutdown_timeout: Duration::from_millis(50),
            max_copy_bytes: 1024 * 1024,
            max_copy_entries: 128,
            cleanup_max_attempts: 4,
            cleanup_initial_delay: Duration::from_millis(2),
            admission: AdmissionLimits::default(),
        }
    }

    #[derive(Default)]
    struct MockOverlayState {
        fail_prepare: bool,
        removed_paths: Vec<PathBuf>,
    }

    #[derive(Default)]
    struct MockOverlayStore {
        state: Mutex<MockOverlayState>,
    }

    impl MockOverlayStore {
        fn set_fail_prepare(&self, fail: bool) {
            lock_unpoisoned(&self.state).fail_prepare = fail;
        }

        fn removed_paths(&self) -> Vec<PathBuf> {
            lock_unpoisoned(&self.state).removed_paths.clone()
        }
    }

    #[async_trait::async_trait]
    impl DiskOverlayPort for MockOverlayStore {
        async fn prepare_overlay(
            &self,
            sandbox_id: &SandboxId,
            spec: &SandboxSpec,
            work_dir: &Path,
        ) -> Result<PreparedOverlay, SandboxError> {
            let fail = lock_unpoisoned(&self.state).fail_prepare;
            if fail {
                return Err(SandboxError::Internal("simulated prepare failure".into()));
            }
            let overlay_path = work_dir.join("overlay.qcow2");
            fs::write(&overlay_path, format!("overlay-for-{sandbox_id}").as_bytes()).unwrap();
            Ok(PreparedOverlay {
                overlay_path,
                kernel_path: PathBuf::from("/bundle/vmlinuz"),
                initramfs_path: PathBuf::from("/bundle/initramfs.cpio.gz"),
                rootfs_path: PathBuf::from("/bundle/rootfs.qcow2"),
                kernel_cmdline: "quiet panic=-1 minipod.root=/dev/vda".to_owned(),
                virtual_disk_mb: spec.budget.virtual_disk_mb,
                provisioned_host_bytes: 64,
            })
        }

        async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
            lock_unpoisoned(&self.state)
                .removed_paths
                .push(overlay_path.to_path_buf());
            if overlay_path.exists() {
                let _ = fs::remove_file(overlay_path);
            }
            Ok(())
        }
    }

    struct MockSessionState {
        alive: AtomicBool,
        rss_bytes: AtomicU64,
        graceful_succeeds: bool,
        graceful_calls: Mutex<usize>,
        force_kill_calls: Mutex<usize>,
        copied_in: Mutex<Vec<(String, Vec<u8>)>>,
        copy_out_archive: Mutex<Vec<u8>>,
    }

    struct MockVmSession {
        pid: u32,
        start_token: u64,
        artifacts: Vec<PathBuf>,
        state: Arc<MockSessionState>,
    }

    #[async_trait::async_trait]
    impl VmSessionPort for MockVmSession {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn start_token(&self) -> u64 {
            self.start_token
        }

        fn artifact_paths(&self) -> &[PathBuf] {
            &self.artifacts
        }

        fn is_alive(&self) -> bool {
            self.state.alive.load(Ordering::Acquire)
        }

        fn current_rss_bytes(&self) -> Option<u64> {
            self.is_alive()
                .then(|| self.state.rss_bytes.load(Ordering::Acquire))
        }

        async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError> {
            let (stream, handle) = ExecStream::channel(StreamId(1));
            tokio::spawn(async move {
                let payload = format!("ran:{}", req.argv.join(" ")).into_bytes();
                let _ = handle
                    .send_output(ExecOutputChunk {
                        stream: OutputStreamKind::Stdout,
                        data: payload,
                    })
                    .await;
                handle.finish(Ok(ExecExitStatus {
                    code: Some(0),
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                }));
            });
            Ok(stream)
        }

        async fn open_tunnel(&self, target: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            if let StreamTargetWire::GuestLoopbackTcp { port: 0 } = target {
                return Err(SandboxError::InvalidSpec(
                    "guest_port must be greater than zero".to_owned(),
                ));
            }
            let (stream, mut handle) = TunnelStream::channel(StreamId(2));
            tokio::spawn(async move {
                let banner = match target {
                    StreamTargetWire::PodmanUnixSocket => b"podman:".to_vec(),
                    StreamTargetWire::GuestLoopbackTcp { port } => format!("tcp:{port}:").into_bytes(),
                };
                if handle.write_half.write_all(&banner).await.is_err() {
                    return;
                }
                let mut req = Vec::new();
                if handle.read_half.read_to_end(&mut req).await.is_ok() {
                    let _ = handle.write_half.write_all(&req).await;
                }
                let _ = handle.write_half.shutdown().await;
            });
            Ok(stream)
        }

        async fn copy_in_tar(
            &self,
            dst_guest: &str,
            tar_bytes: Vec<u8>,
            max_bytes: u64,
        ) -> Result<u64, SandboxError> {
            let len = tar_bytes.len() as u64;
            if len > max_bytes {
                return Err(SandboxError::BudgetExceeded("tar exceeds max_bytes".into()));
            }
            lock_unpoisoned(&self.state.copied_in).push((dst_guest.to_owned(), tar_bytes));
            Ok(len)
        }

        async fn copy_out_tar(
            &self,
            _src_guest: &str,
            max_bytes: u64,
        ) -> Result<Vec<u8>, SandboxError> {
            let bytes = lock_unpoisoned(&self.state.copy_out_archive).clone();
            if bytes.len() as u64 > max_bytes {
                return Err(SandboxError::BudgetExceeded("copy out exceeds max".into()));
            }
            Ok(bytes)
        }

        async fn graceful_shutdown(&self, _timeout: Duration) -> Result<bool, SandboxError> {
            *lock_unpoisoned(&self.state.graceful_calls) += 1;
            if self.state.graceful_succeeds {
                self.state.alive.store(false, Ordering::Release);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn force_kill(&self) -> Result<(), SandboxError> {
            *lock_unpoisoned(&self.state.force_kill_calls) += 1;
            self.state.alive.store(false, Ordering::Release);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockVmRuntimeState {
        fail_boot: bool,
        graceful_succeeds: bool,
        enable_egress_channel: bool,
        next_pid: u32,
        sessions: Vec<Arc<MockSessionState>>,
        egress_senders: Vec<tokio::sync::mpsc::Sender<TunnelStream>>,
        orphan_kill_calls: Vec<(u32, u64)>,
        live_orphans: HashSet<(u32, u64)>,
        error_on_orphan: Option<(u32, u64)>,
    }

    #[derive(Default)]
    struct MockVmRuntime {
        state: Mutex<MockVmRuntimeState>,
    }

    impl MockVmRuntime {
        fn new(graceful_succeeds: bool) -> Self {
            Self {
                state: Mutex::new(MockVmRuntimeState {
                    graceful_succeeds,
                    next_pid: 4000,
                    ..MockVmRuntimeState::default()
                }),
            }
        }
    }

    #[async_trait::async_trait]
    impl VmRuntimePort for MockVmRuntime {
        async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
            let (pid, token, graceful, fail, enable_egress) = {
                let mut st = lock_unpoisoned(&self.state);
                st.next_pid += 1;
                (
                    st.next_pid,
                    u64::from(st.next_pid) * 17,
                    st.graceful_succeeds,
                    st.fail_boot,
                    st.enable_egress_channel && config.spec.network != NetworkPolicy::Isolated,
                )
            };
            if fail {
                return Err(SandboxError::AccelerationUnavailable(
                    "simulated boot failure".into(),
                ));
            }
            let sock_path = config.work_dir.join("a.sock");
            fs::write(&sock_path, b"sock").unwrap();
            let sess_state = Arc::new(MockSessionState {
                alive: AtomicBool::new(true),
                rss_bytes: AtomicU64::new(64 * 1024 * 1024),
                graceful_succeeds: graceful,
                graceful_calls: Mutex::new(0),
                force_kill_calls: Mutex::new(0),
                copied_in: Mutex::new(Vec::new()),
                copy_out_archive: Mutex::new(Vec::new()),
            });
            let (egress_tx, egress_rx) = if enable_egress {
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
            {
                let mut st = lock_unpoisoned(&self.state);
                st.sessions.push(Arc::clone(&sess_state));
                if let Some(tx) = egress_tx {
                    st.egress_senders.push(tx);
                }
            }

            Ok(VmBootOutcome {
                session: Box::new(MockVmSession {
                    pid,
                    start_token: token,
                    artifacts: vec![sock_path.clone()],
                    state: sess_state,
                }),
                pid,
                start_token: token,
                artifact_paths: vec![sock_path],
                hardware_accelerated: true,
                capabilities: CapabilityReport {
                    cpu_quota: EnforcementLevel::Unsupported,
                    host_rss: EnforcementLevel::Unsupported,
                    host_storage: EnforcementLevel::Unsupported,
                    egress_filter: EnforcementLevel::HardLimit,
                },
                egress_rx,
            })
        }

        async fn kill_orphan_process(
            &self,
            pid: u32,
            expected_start_token: u64,
        ) -> Result<bool, SandboxError> {
            let mut st = lock_unpoisoned(&self.state);
            st.orphan_kill_calls.push((pid, expected_start_token));
            if st.error_on_orphan == Some((pid, expected_start_token)) {
                return Err(SandboxError::PolicyViolation(
                    "simulated permission denied killing orphan".into(),
                ));
            }
            Ok(st.live_orphans.remove(&(pid, expected_start_token)))
        }
    }

    fn build_sample_tar(file_name: &str, body: &[u8]) -> Vec<u8> {
        let tmp = TestTempDir::new("sample-tar");
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join(file_name), body).unwrap();
        pack_host_path_to_tar(&src, 1024 * 1024).unwrap()
    }

    #[test]
    fn config_rejects_empty_or_zero_bounds() {
        let tmp = TestTempDir::new("cfg-bad");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));

        let mut cfg = base_config(PathBuf::new());
        assert!(matches!(
            LocalRuntimeManager::new(cfg.clone(), overlay.clone(), vm.clone()),
            Err(SandboxError::InvalidSpec(_))
        ));

        cfg = base_config(tmp.path().to_path_buf());
        cfg.sweep_interval = Duration::ZERO;
        assert!(matches!(
            LocalRuntimeManager::new(cfg, overlay.clone(), vm.clone()),
            Err(SandboxError::InvalidSpec(_))
        ));

        cfg = base_config(tmp.path().to_path_buf());
        cfg.cleanup_max_attempts = 0;
        assert!(matches!(
            LocalRuntimeManager::new(cfg, overlay.clone(), vm.clone()),
            Err(SandboxError::InvalidSpec(_))
        ));

        cfg = base_config(tmp.path().to_path_buf());
        cfg.admission.max_concurrent_sandboxes = Some(0);
        assert!(matches!(
            LocalRuntimeManager::new(cfg, overlay, vm),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn full_lifecycle_spawn_exec_renew_copy_and_idempotent_destroy() {
        let tmp = TestTempDir::new("mgr-lifecycle");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(
            base_config(state_dir.clone()),
            overlay.clone(),
            vm.clone(),
        )
        .unwrap();

        let lease = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert_eq!(lease.capabilities.egress_filter, EnforcementLevel::HardLimit);
        assert_eq!(lease.capabilities.host_storage, EnforcementLevel::HardLimit);
        assert_eq!(lease.capabilities.cpu_quota, EnforcementLevel::Unsupported);

        // Journal must persist Active state with PID & start_token.
        let rec = mgr.journal.load_record(&lease.id).unwrap().unwrap();
        assert_eq!(rec.state, JournalLifecycleState::Active);
        assert!(rec.pid.is_some());
        assert!(rec.start_token.is_some());

        // Execute command stream.
        let stream = mgr
            .exec_stream(
                &lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["echo".into(), "hi".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(5),
                    stdout_budget_bytes: 1024,
                    stderr_budget_bytes: 1024,
                },
            )
            .await
            .unwrap();
        let out = stream.collect().await.unwrap();
        assert_eq!(out.exit.code, Some(0));
        assert_eq!(out.stdout, b"ran:echo hi");

        // Renew lease updates journal expiration.
        mgr.renew_lease(&lease.id, Duration::from_secs(120))
            .await
            .unwrap();
        let rec_renewed = mgr.journal.load_record(&lease.id).unwrap().unwrap();
        assert!(rec_renewed.expires_at_unix_ms >= rec.expires_at_unix_ms);

        // Copy in packs host dir safely and transmits tar to session.
        let src_host = tmp.path().join("upload");
        fs::create_dir_all(&src_host).unwrap();
        fs::write(src_host.join("hello.txt"), b"world").unwrap();
        mgr.copy_in(&lease.id, src_host, "/workspace".to_owned())
            .await
            .unwrap();

        // Prepare tar archive on mock session and copy out safely.
        let guest_tar = build_sample_tar("from-guest.txt", b"guest-data");
        {
            let st = lock_unpoisoned(&vm.state);
            *lock_unpoisoned(&st.sessions[0].copy_out_archive) = guest_tar;
        }
        let dst_host = tmp.path().join("download");
        mgr.copy_out(&lease.id, "/workspace".to_owned(), dst_host.clone())
            .await
            .unwrap();
        assert_eq!(
            fs::read(dst_host.join("from-guest.txt")).unwrap(),
            b"guest-data"
        );

        // Destroy cleanly and verify idempotency.
        assert_eq!(
            mgr.destroy(&lease.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        assert!(mgr.journal.load_record(&lease.id).unwrap().is_none());
        assert!(!state_dir.join("sandboxes").join(lease.id.as_str()).exists());
        assert!(!overlay.removed_paths().is_empty());

        // Second destroy must return AllResourcesCleaned without failing.
        assert_eq!(
            mgr.destroy(&lease.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );

        // Operations on destroyed sandbox fail with NotFound.
        assert!(matches!(
            mgr.renew_lease(&lease.id, Duration::from_secs(10)).await,
            Err(SandboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn rejects_shared_kernel_and_malformed_domain_allow_list_and_reports_capabilities() {
        let tmp = TestTempDir::new("mgr-policy");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(
            base_config(tmp.path().to_path_buf()),
            overlay,
            vm,
        )
        .unwrap();

        let mut shared = valid_spec(Duration::from_secs(10));
        shared.isolation = IsolationMode::SharedKernelAllowed;
        assert!(matches!(
            mgr.spawn(shared).await,
            Err(SandboxError::UnsupportedIsolationMode(_))
        ));

        for bad_net in [
            NetworkPolicy::DomainAllowList {
                rules: vec![EgressRule {
                    domain: "example.com".into(),
                    port: 0,
                }],
            },
            NetworkPolicy::DomainAllowList {
                rules: vec![EgressRule {
                    domain: "127.0.0.1".into(),
                    port: 443,
                }],
            },
        ] {
            let mut spec = valid_spec(Duration::from_secs(10));
            spec.network = bad_net;
            assert!(matches!(
                mgr.spawn(spec).await,
                Err(SandboxError::InvalidSpec(_))
            ));
        }

        // Neither failure may leave sandbox artifacts or journals behind.
        assert!(mgr.journal.load_records().unwrap().is_empty());

        // Tight storage headroom (<= virtual_disk_mb + 16 MiB) reports BestEffort; >= 16 MiB reports HardLimit.
        let mut tight = valid_spec(Duration::from_secs(30));
        tight.budget.virtual_disk_mb = 512;
        tight.budget.host_storage_budget_mb = 520;
        let tight_lease = mgr.spawn(tight).await.unwrap();
        assert_eq!(tight_lease.capabilities.host_storage, EnforcementLevel::BestEffort);
        assert_eq!(tight_lease.capabilities.egress_filter, EnforcementLevel::HardLimit);
        mgr.destroy(&tight_lease.id).await.unwrap();

        for (net, expected_egress) in [
            (NetworkPolicy::InternetOnly, EnforcementLevel::HardLimit),
            (
                NetworkPolicy::DomainAllowList {
                    rules: vec![EgressRule {
                        domain: "api.example.com".into(),
                        port: 443,
                    }],
                },
                EnforcementLevel::HardLimit,
            ),
            (NetworkPolicy::Unrestricted, EnforcementLevel::Unsupported),
        ] {
            let mut spec = valid_spec(Duration::from_secs(30));
            spec.network = net;
            let lease = mgr.spawn(spec).await.unwrap();
            assert_eq!(lease.capabilities.egress_filter, expected_egress);
            assert_eq!(lease.capabilities.host_storage, EnforcementLevel::HardLimit);
            mgr.destroy(&lease.id).await.unwrap();
        }
    }

    #[tokio::test]
    async fn mid_spawn_failures_roll_back_overlay_work_dir_and_journal() {
        let tmp = TestTempDir::new("mgr-rollback");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(
            base_config(state_dir.clone()),
            overlay.clone(),
            vm.clone(),
        )
        .unwrap();

        overlay.set_fail_prepare(true);
        assert!(mgr.spawn(valid_spec(Duration::from_secs(10))).await.is_err());
        assert!(mgr.journal.load_records().unwrap().is_empty());
        assert_eq!(
            fs::read_dir(state_dir.join("sandboxes")).unwrap().count(),
            0
        );

        overlay.set_fail_prepare(false);
        lock_unpoisoned(&vm.state).fail_boot = true;
        assert!(matches!(
            mgr.spawn(valid_spec(Duration::from_secs(10))).await,
            Err(SandboxError::AccelerationUnavailable(_))
        ));
        assert_eq!(overlay.removed_paths().len(), 1);
        assert!(mgr.journal.load_records().unwrap().is_empty());
        assert_eq!(
            fs::read_dir(state_dir.join("sandboxes")).unwrap().count(),
            0
        );
    }

    #[tokio::test]
    async fn expired_leases_fail_eagerly_and_are_cleaned_by_sweeper() {
        let tmp = TestTempDir::new("mgr-expiry");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(false));
        let mgr = LocalRuntimeManager::new(
            base_config(tmp.path().to_path_buf()),
            overlay,
            vm.clone(),
        )
        .unwrap();

        let short_lease = mgr
            .spawn(valid_spec(Duration::from_millis(25)))
            .await
            .unwrap();
        let long_lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();

        tokio::time::sleep(Duration::from_millis(45)).await;

        assert!(matches!(
            mgr.exec_stream(
                &short_lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["true".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(1),
                    stdout_budget_bytes: 64,
                    stderr_budget_bytes: 64,
                },
            )
            .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert!(matches!(
            mgr.copy_in(&short_lease.id, tmp.path().to_path_buf(), "/dst".into())
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert!(matches!(
            mgr.copy_out(&short_lease.id, "/src".into(), tmp.path().to_path_buf())
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert!(matches!(
            mgr.renew_lease(&short_lease.id, Duration::from_secs(5))
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));

        let swept = mgr.sweep_expired_leases().await;
        assert_eq!(swept, 1);
        assert_eq!(mgr.sweep_expired_leases().await, 0);

        // graceful_succeeds=false in MockVmRuntime triggered force_kill on short_lease.
        {
            let st = lock_unpoisoned(&vm.state);
            assert_eq!(*lock_unpoisoned(&st.sessions[0].force_kill_calls), 1);
        }

        // Long lease remains usable and is cleaned cleanly.
        mgr.renew_lease(&long_lease.id, Duration::from_secs(30))
            .await
            .unwrap();
        mgr.destroy(&long_lease.id).await.unwrap();
    }

    #[tokio::test]
    async fn startup_reconciler_kills_orphans_and_retains_partial_failures() {
        let tmp = TestTempDir::new("mgr-reconcile");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(
            base_config(state_dir.clone()),
            overlay.clone(),
            vm.clone(),
        )
        .unwrap();

        // Orphan 1: Active sandbox with cleanable work_dir and live orphan process.
        let work1 = state_dir.join("sandboxes").join("mp-orphan-1");
        fs::create_dir_all(&work1).unwrap();
        let overlay1 = work1.join("overlay.qcow2");
        fs::write(&overlay1, b"q1").unwrap();
        {
            let mut st = lock_unpoisoned(&vm.state);
            st.live_orphans.insert((7777, 8888));
        }
        mgr.journal
            .write_record(&JournalRecord {
                sandbox_id: SandboxId::new("mp-orphan-1"),
                state: JournalLifecycleState::Active,
                pid: Some(7777),
                start_token: Some(8888),
                artifact_paths: vec![overlay1.clone(), work1.clone()],
                expires_at_unix_ms: 100,
            })
            .unwrap();

        // Orphan 2: Spawning sandbox without pid yet.
        let work2 = state_dir.join("sandboxes").join("mp-orphan-2");
        fs::create_dir_all(&work2).unwrap();
        mgr.journal
            .write_record(&JournalRecord {
                sandbox_id: SandboxId::new("mp-orphan-2"),
                state: JournalLifecycleState::Spawning,
                pid: None,
                start_token: None,
                artifact_paths: vec![work2.clone()],
                expires_at_unix_ms: 200,
            })
            .unwrap();

        let report = mgr.reconcile_startup().await.unwrap();
        assert_eq!(
            report,
            ReconciliationReport {
                records_seen: 2,
                orphans_killed: 1,
                cleaned: 2,
                remaining: 0,
            }
        );
        assert!(!work1.exists());
        assert!(!work2.exists());
        assert!(mgr.journal.load_records().unwrap().is_empty());
        assert!(overlay.removed_paths().contains(&overlay1));

        // Partial cleanup failure (Windows share_mode(0) lock) retains Destroying journal with pid=None.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            let work3 = state_dir.join("sandboxes").join("mp-partial-3");
            fs::create_dir_all(&work3).unwrap();
            let locked = work3.join("locked.bin");
            let lock_handle = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .share_mode(0)
                .open(&locked)
                .unwrap();

            mgr.journal
                .write_record(&JournalRecord {
                    sandbox_id: SandboxId::new("mp-partial-3"),
                    state: JournalLifecycleState::Active,
                    pid: Some(9999),
                    start_token: Some(1234),
                    artifact_paths: vec![locked.clone(), work3.clone()],
                    expires_at_unix_ms: 300,
                })
                .unwrap();

            let partial_report = mgr.reconcile_startup().await.unwrap();
            assert_eq!(partial_report.records_seen, 1);
            assert_eq!(partial_report.cleaned, 0);
            assert_eq!(partial_report.remaining, 1);

            let retained = mgr
                .journal
                .load_record(&SandboxId::new("mp-partial-3"))
                .unwrap()
                .unwrap();
            assert_eq!(retained.state, JournalLifecycleState::Destroying);
            assert_eq!(retained.pid, None);
            assert_eq!(retained.start_token, None);
            assert!(!retained.artifact_paths.is_empty());

            drop(lock_handle);
            let final_report = mgr.reconcile_startup().await.unwrap();
            assert_eq!(final_report.cleaned, 1);
            assert_eq!(final_report.remaining, 0);
            assert!(mgr.journal.load_records().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn sweeper_task_reaps_expired_sandboxes_and_aborts_when_manager_drops() {
        let tmp = TestTempDir::new("mgr-sweeper-drop");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.sweep_interval = Duration::from_millis(15);

        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm).unwrap());
        let sweeper_handle = mgr.spawn_lease_sweeper();

        let lease = mgr
            .spawn(valid_spec(Duration::from_millis(20)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(mgr.journal.load_record(&lease.id).unwrap().is_none());

        drop(mgr);
        let join_res = tokio::time::timeout(Duration::from_millis(200), sweeper_handle)
            .await
            .expect("sweeper must exit promptly when manager drops");
        assert!(join_res.is_err()); // Cancelled via AbortHandle in Drop.
    }

    #[tokio::test]
    async fn concurrent_destroy_and_invalid_guest_paths_behave_safely() {
        let tmp = TestTempDir::new("mgr-conc-destroy");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = Arc::new(
            LocalRuntimeManager::new(base_config(tmp.path().to_path_buf()), overlay, vm).unwrap(),
        );

        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();

        assert!(matches!(
            mgr.copy_in(&lease.id, tmp.path().to_path_buf(), String::new())
                .await,
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            mgr.copy_out(&lease.id, "bad\0path".to_owned(), tmp.path().to_path_buf())
                .await,
            Err(SandboxError::InvalidSpec(_))
        ));
        for bad_target in ["", "--privileged", "foo/bar", "a\0b", &"x".repeat(129)] {
            assert!(matches!(
                mgr.exec_stream(
                    &lease.id,
                    ExecRequest {
                        target: ExecTarget::Container {
                            id_or_name: bad_target.to_owned(),
                        },
                        argv: vec!["/bin/true".to_owned()],
                        env: BTreeMap::new(),
                        cwd: None,
                        user: None,
                        deadline: Duration::from_secs(5),
                        stdout_budget_bytes: 1024,
                        stderr_budget_bytes: 1024,
                    },
                )
                .await,
                Err(SandboxError::InvalidSpec(_))
            ));
        }

        let m1 = Arc::clone(&mgr);
        let m2 = Arc::clone(&mgr);
        let id1 = lease.id.clone();
        let id2 = lease.id.clone();
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { m1.destroy(&id1).await }),
            tokio::spawn(async move { m2.destroy(&id2).await }),
        );
        assert_eq!(r1.unwrap().unwrap(), DestroyStatus::AllResourcesCleaned);
        assert_eq!(r2.unwrap().unwrap(), DestroyStatus::AllResourcesCleaned);
    }

    #[tokio::test]
    async fn tunnel_port_validates_port_zero_leases_and_streams_duplex() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp = TestTempDir::new("mgr-tunnel");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(base_config(tmp.path().to_path_buf()), overlay, vm)
            .unwrap();

        let active_lease = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        let short_lease = mgr
            .spawn(valid_spec(Duration::from_millis(20)))
            .await
            .unwrap();

        // Port 0 is rejected upfront with InvalidSpec.
        assert!(matches!(
            mgr.open_guest_tcp_stream(&active_lease.id, 0).await,
            Err(SandboxError::InvalidSpec(_))
        ));

        // Missing sandbox returns NotFound.
        assert!(matches!(
            mgr.open_podman_unix_stream(&SandboxId::new("missing")).await,
            Err(SandboxError::NotFound(_))
        ));

        // Active Podman unix tunnel streams bidirectionally and half-closes cleanly.
        let mut unix_tunnel = mgr.open_podman_unix_stream(&active_lease.id).await.unwrap();
        unix_tunnel.write_all(b"GET /_ping").await.unwrap();
        unix_tunnel.shutdown().await.unwrap();
        let mut resp = Vec::new();
        unix_tunnel.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"podman:GET /_ping");

        // Active guest loopback TCP tunnel targets requested port.
        let mut tcp_tunnel = mgr
            .open_guest_tcp_stream(&active_lease.id, 5432)
            .await
            .unwrap();
        tcp_tunnel.write_all(b"hello").await.unwrap();
        tcp_tunnel.shutdown().await.unwrap();
        let mut tcp_resp = Vec::new();
        tcp_tunnel.read_to_end(&mut tcp_resp).await.unwrap();
        assert_eq!(tcp_resp, b"tcp:5432:hello");

        // Expired lease returns LeaseExpired for both tunnel variants.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(matches!(
            mgr.open_podman_unix_stream(&short_lease.id).await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert!(matches!(
            mgr.open_guest_tcp_stream(&short_lease.id, 80).await,
            Err(SandboxError::LeaseExpired(_))
        ));

        mgr.destroy(&active_lease.id).await.unwrap();
        mgr.destroy(&short_lease.id).await.unwrap();

        assert!(matches!(
            mgr.open_podman_unix_stream(&active_lease.id).await,
            Err(SandboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn admission_control_enforces_limits_fifo_queue_cancellation_and_live_rss() {
        // 1. Immediate rejection across count, RSS, storage, CPU when queue timeout is ZERO,
        // plus permit release on mid-spawn rollback.
        let tmp = TestTempDir::new("mgr-adm-limits");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.admission = AdmissionLimits {
            max_concurrent_sandboxes: Some(2),
            max_total_host_rss_mb: Some(768),
            max_total_host_storage_mb: Some(1536),
            max_total_host_cpu_millicores: Some(2000),
            admission_queue_timeout: Duration::ZERO,
            max_admission_queue_depth: 8,
        };
        let mgr = LocalRuntimeManager::new(cfg, overlay.clone(), vm.clone()).unwrap();

        // Rollback during failed spawn must NOT leak the AdmissionPermit.
        overlay.set_fail_prepare(true);
        assert!(mgr.spawn(valid_spec(Duration::from_secs(30))).await.is_err());
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
        overlay.set_fail_prepare(false);

        let lease1 = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 1);

        // Exceeds RSS (512 + 300 > 768)
        let mut over_rss = valid_spec(Duration::from_secs(30));
        over_rss.budget.host_rss_budget_mb = Some(300);
        over_rss.budget.host_storage_budget_mb = 256;
        over_rss.budget.virtual_disk_mb = 128;
        assert!(matches!(
            mgr.spawn(over_rss).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Exceeds storage (1024 + 600 > 1536)
        let mut over_storage = valid_spec(Duration::from_secs(30));
        over_storage.budget.host_rss_budget_mb = Some(256);
        over_storage.budget.host_storage_budget_mb = 600;
        assert!(matches!(
            mgr.spawn(over_storage).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Exceeds CPU (1000 + 1500 > 2000)
        let mut over_cpu = valid_spec(Duration::from_secs(30));
        over_cpu.budget.host_rss_budget_mb = Some(256);
        over_cpu.budget.host_storage_budget_mb = 256;
        over_cpu.budget.virtual_disk_mb = 128;
        over_cpu.budget.host_cpu_quota_Millicores = Some(1500);
        assert!(matches!(
            mgr.spawn(over_cpu).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Live observed RSS spike on lease1 (600 MiB > 512 MiB reserved) blocks a 200 MiB spawn (600 + 200 > 768).
        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions[0]
                .rss_bytes
                .store(600 * 1024 * 1024, Ordering::Release);
        }
        let mut small_rss = valid_spec(Duration::from_secs(30));
        small_rss.budget.guest_ram_mb = 128;
        small_rss.budget.host_rss_budget_mb = Some(200);
        small_rss.budget.host_storage_budget_mb = 256;
        small_rss.budget.virtual_disk_mb = 128;
        assert!(matches!(
            mgr.spawn(small_rss.clone()).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Restore live RSS <= reserved -> small_rss fits, then 3rd fails max_concurrent_sandboxes (2).
        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions[0]
                .rss_bytes
                .store(64 * 1024 * 1024, Ordering::Release);
        }
        let lease2 = mgr.spawn(small_rss.clone()).await.unwrap();
        let mut tiny = small_rss;
        tiny.budget.host_rss_budget_mb = Some(16);
        tiny.budget.guest_ram_mb = 16;
        tiny.budget.host_storage_budget_mb = 64;
        tiny.budget.virtual_disk_mb = 32;
        tiny.budget.host_cpu_quota_Millicores = Some(100);
        assert!(matches!(
            mgr.spawn(tiny).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        mgr.destroy(&lease1.id).await.unwrap();
        mgr.destroy(&lease2.id).await.unwrap();
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());

        // 2. FIFO queue waits, wakes upon destroy(), rejects queue overflow/timeout, and handles cancelled waiter.
        let tmp_q = TestTempDir::new("mgr-adm-queue");
        let overlay_q = Arc::new(MockOverlayStore::default());
        let vm_q = Arc::new(MockVmRuntime::new(true));
        let mut cfg_q = base_config(tmp_q.path().to_path_buf());
        cfg_q.admission = AdmissionLimits {
            max_concurrent_sandboxes: Some(1),
            admission_queue_timeout: Duration::from_secs(2),
            max_admission_queue_depth: 2,
            ..Default::default()
        };
        let mgr_q = Arc::new(LocalRuntimeManager::new(cfg_q, overlay_q, vm_q).unwrap());

        let hold = mgr_q.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();

        let mgr_cancel = Arc::clone(&mgr_q);
        let cancelled_waiter = tokio::spawn(async move {
            mgr_cancel.spawn(valid_spec(Duration::from_secs(30))).await
        });
        tokio::task::yield_now().await;

        let mgr_next = Arc::clone(&mgr_q);
        let next_waiter = tokio::spawn(async move {
            mgr_next.spawn(valid_spec(Duration::from_secs(30))).await
        });
        tokio::task::yield_now().await;

        // Queue depth is 2 -> 3rd queued caller must reject immediately.
        assert!(matches!(
            mgr_q.spawn(valid_spec(Duration::from_secs(30))).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Abort cancelled_waiter before destroying `hold`; next_waiter must still succeed promptly!
        cancelled_waiter.abort();
        let _ = cancelled_waiter.await;

        mgr_q.destroy(&hold.id).await.unwrap();
        let admitted = next_waiter.await.unwrap().unwrap();
        mgr_q.destroy(&admitted.id).await.unwrap();
        assert_eq!(mgr_q.current_admission_usage(), AdmissionUsage::default());

        // Timeout rejects cleanly.
        let tmp_t = TestTempDir::new("mgr-adm-timeout");
        let mut cfg_t = base_config(tmp_t.path().to_path_buf());
        cfg_t.admission = AdmissionLimits {
            max_concurrent_sandboxes: Some(1),
            admission_queue_timeout: Duration::from_millis(30),
            max_admission_queue_depth: 4,
            ..Default::default()
        };
        let mgr_t = LocalRuntimeManager::new(
            cfg_t,
            Arc::new(MockOverlayStore::default()),
            Arc::new(MockVmRuntime::new(true)),
        )
        .unwrap();
        let hold_t = mgr_t.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert!(matches!(
            mgr_t.spawn(valid_spec(Duration::from_secs(30))).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        mgr_t.destroy(&hold_t.id).await.unwrap();
    }

    #[tokio::test]
    async fn copy_in_and_watchdog_enforce_physical_storage_and_live_rss_budgets() {
        let tmp = TestTempDir::new("mgr-watchdog");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(state_dir.clone());
        cfg.max_copy_bytes = 8 * 1024 * 1024;
        let mgr = LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap();

        let mut tight_storage = valid_spec(Duration::from_secs(60));
        tight_storage.budget.virtual_disk_mb = 1;
        tight_storage.budget.host_storage_budget_mb = 1;
        let lease_storage = mgr.spawn(tight_storage).await.unwrap();

        // Attempting copy_in larger than remaining 1 MiB host_storage_budget_mb must return BudgetExceeded.
        let big_src = tmp.path().join("big_upload.bin");
        fs::write(&big_src, vec![0xABu8; 1_200_000]).unwrap();
        assert!(matches!(
            mgr.copy_in(&lease_storage.id, big_src, "/workspace".to_owned())
                .await,
            Err(SandboxError::BudgetExceeded(_))
        ));

        // Pre-existing work_dir growth beyond 1 MiB is reaped by enforce_resource_budgets.
        let work_dir = state_dir.join("sandboxes").join(lease_storage.id.as_str());
        fs::write(work_dir.join("bloated_overlay.bin"), vec![0xCDu8; 1_100_000]).unwrap();
        assert_eq!(mgr.enforce_resource_budgets().await, 1);
        assert!(!work_dir.exists());
        assert!(matches!(
            mgr.renew_lease(&lease_storage.id, Duration::from_secs(10)).await,
            Err(SandboxError::NotFound(_))
        ));

        // Live RSS breach beyond host_rss_budget_mb is also reaped by enforce_resource_budgets.
        let mut rss_spec = valid_spec(Duration::from_secs(60));
        rss_spec.budget.guest_ram_mb = 128;
        rss_spec.budget.host_rss_budget_mb = Some(256);
        let lease_rss = mgr.spawn(rss_spec).await.unwrap();
        assert_eq!(
            mgr.sandbox_current_rss_bytes(&lease_rss.id),
            Some(64 * 1024 * 1024)
        );
        assert_eq!(
            mgr.sandbox_current_rss_bytes(&SandboxId::new("missing-id")),
            None
        );
        {
            let st = lock_unpoisoned(&vm.state);
            let idx = st.sessions.len() - 1;
            st.sessions[idx]
                .rss_bytes
                .store(300 * 1024 * 1024, Ordering::Release);
        }
        assert_eq!(
            mgr.sandbox_current_rss_bytes(&lease_rss.id),
            Some(300 * 1024 * 1024)
        );
        assert_eq!(mgr.enforce_resource_budgets().await, 1);
        assert_eq!(mgr.sandbox_current_rss_bytes(&lease_rss.id), None);
        assert!(matches!(
            mgr.renew_lease(&lease_rss.id, Duration::from_secs(10)).await,
            Err(SandboxError::NotFound(_))
        ));

        // Background sweeper also runs enforce_resource_budgets automatically alongside TTL sweeping.
        let tmp_sw = TestTempDir::new("mgr-watchdog-sweeper");
        let overlay_sw = Arc::new(MockOverlayStore::default());
        let vm_sw = Arc::new(MockVmRuntime::new(true));
        let mut cfg_sw = base_config(tmp_sw.path().to_path_buf());
        cfg_sw.sweep_interval = Duration::from_millis(15);
        let mgr_sw = Arc::new(LocalRuntimeManager::new(cfg_sw, overlay_sw, vm_sw.clone()).unwrap());
        let _sweeper = mgr_sw.spawn_lease_sweeper();

        let mut sw_spec = valid_spec(Duration::from_secs(60));
        sw_spec.budget.guest_ram_mb = 128;
        sw_spec.budget.host_rss_budget_mb = Some(256);
        let sw_lease = mgr_sw.spawn(sw_spec).await.unwrap();
        {
            let st = lock_unpoisoned(&vm_sw.state);
            st.sessions[0]
                .rss_bytes
                .store(300 * 1024 * 1024, Ordering::Release);
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(matches!(
            mgr_sw.renew_lease(&sw_lease.id, Duration::from_secs(10)).await,
            Err(SandboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn egress_proxy_integration_filters_bogon_and_rebound_ips_and_aborts_on_destroy() {
        use std::collections::VecDeque;
        use std::io;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::egress::BoxedUpstreamStream;

        struct TestDns {
            responses: Mutex<VecDeque<io::Result<Vec<SocketAddr>>>>,
        }

        #[async_trait::async_trait]
        impl HostDnsResolver for TestDns {
            async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
                let mut q = lock_unpoisoned(&self.responses);
                q.pop_front().unwrap_or_else(|| {
                    Ok(vec![SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        port,
                    )])
                })
            }
        }

        struct TestDialer {
            dialed: Mutex<Vec<SocketAddr>>,
            hold_forever: AtomicBool,
            active_hold_started: tokio::sync::Notify,
        }

        #[async_trait::async_trait]
        impl UpstreamDialer for TestDialer {
            async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
                lock_unpoisoned(&self.dialed).push(addr);
                if self.hold_forever.load(Ordering::Acquire) {
                    self.active_hold_started.notify_one();
                    std::future::pending::<()>().await;
                }
                let (proxy_side, mut server_side) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    if let Ok(n) = server_side.read(&mut buf).await {
                        if n > 0 {
                            let _ = server_side.write_all(b"echo:").await;
                            let _ = server_side.write_all(&buf[..n]).await;
                        }
                    }
                    let _ = server_side.shutdown().await;
                });
                Ok(Box::pin(proxy_side))
            }
        }

        let tmp = TestTempDir::new("mgr-egress");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        lock_unpoisoned(&vm.state).enable_egress_channel = true;

        let dns = Arc::new(TestDns {
            responses: Mutex::new(VecDeque::from([
                // 1. Allowed public IP for api.example.com:443
                Ok(vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    443,
                )]),
                // 2. DNS rebinding to loopback 127.0.0.1 for api.example.com:443
                Ok(vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    443,
                )]),
                // 3. Allowed public IP for stalled tunnel test
                Ok(vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    443,
                )]),
            ])),
        });
        let dialer = Arc::new(TestDialer {
            dialed: Mutex::new(Vec::new()),
            hold_forever: AtomicBool::new(false),
            active_hold_started: tokio::sync::Notify::new(),
        });

        let mgr = LocalRuntimeManager::with_egress_hooks(
            base_config(tmp.path().to_path_buf()),
            overlay,
            vm.clone(),
            dns,
            dialer.clone(),
        )
        .unwrap();

        let mut spec = valid_spec(Duration::from_secs(60));
        spec.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "api.example.com".to_owned(),
                port: 443,
            }],
        };
        let lease = mgr.spawn(spec).await.unwrap();
        let egress_tx = {
            let st = lock_unpoisoned(&vm.state);
            st.egress_senders[0].clone()
        };

        // 1. Allowed HTTP CONNECT succeeds via HostEgressProxy.
        let (stream_ok, mut handle_ok) = TunnelStream::channel(StreamId(10));
        egress_tx.send(stream_ok).await.unwrap();
        handle_ok
            .write_half
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut ok_head = [0u8; 64];
        let n = handle_ok.read_half.read(&mut ok_head).await.unwrap();
        assert!(
            String::from_utf8_lossy(&ok_head[..n]).starts_with("HTTP/1.1 200 Connection Established")
        );
        handle_ok.write_half.write_all(b"ping").await.unwrap();
        handle_ok.write_half.shutdown().await.unwrap();
        let mut tunnel_resp = Vec::new();
        handle_ok.read_half.read_to_end(&mut tunnel_resp).await.unwrap();
        assert_eq!(tunnel_resp, b"echo:ping");

        // 2. DNS rebinding to 127.0.0.1 is blocked with 403 Forbidden and NEVER dialed.
        let (stream_rebind, mut handle_rebind) = TunnelStream::channel(StreamId(11));
        egress_tx.send(stream_rebind).await.unwrap();
        handle_rebind
            .write_half
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
            .await
            .unwrap();
        handle_rebind.write_half.shutdown().await.unwrap();
        let mut rebind_resp = Vec::new();
        handle_rebind
            .read_half
            .read_to_end(&mut rebind_resp)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&rebind_resp).starts_with("HTTP/1.1 403 Forbidden"));

        // 3. Raw private IP literal is blocked with 403 Forbidden.
        let (stream_ip, mut handle_ip) = TunnelStream::channel(StreamId(12));
        egress_tx.send(stream_ip).await.unwrap();
        handle_ip
            .write_half
            .write_all(b"CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n")
            .await
            .unwrap();
        handle_ip.write_half.shutdown().await.unwrap();
        let mut ip_resp = Vec::new();
        handle_ip.read_half.read_to_end(&mut ip_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&ip_resp).starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(
            *lock_unpoisoned(&dialer.dialed),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443
            )]
        );

        // 4. An active stalled proxied connection task is aborted immediately when destroy() runs.
        dialer.hold_forever.store(true, Ordering::Release);
        let (stream_stalled, mut handle_stalled) = TunnelStream::channel(StreamId(13));
        egress_tx.send(stream_stalled).await.unwrap();
        handle_stalled
            .write_half
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
            .await
            .unwrap();
        dialer.active_hold_started.notified().await;

        assert_eq!(
            mgr.destroy(&lease.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        // Once proxy task aborts on destroy(), TunnelStream drops and driver handle reads EOF promptly.
        let mut after_destroy = Vec::new();
        tokio::time::timeout(
            Duration::from_millis(200),
            handle_stalled.read_half.read_to_end(&mut after_destroy),
        )
        .await
        .expect("stalled proxy task must abort promptly on destroy")
        .unwrap();
        assert!(after_destroy.is_empty());
    }
}
