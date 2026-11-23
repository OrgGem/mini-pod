//! Layer 2 `RuntimeManager` implementation: sandbox lifecycle orchestration,
//! durable crash journaling, TTL lease enforcement, and safe workspace copy I/O.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::{
    CapabilityReport, DestroyStatus, EnforcementLevel, ExecRequest, ExecTarget, NetworkPolicy,
    SandboxError, SandboxId, SandboxLease, SandboxSpec, MAX_LEASE_TTL,
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
    ReconciliationScan,
};
use crate::ports::{
    BundleReadGuard, DiskOverlayPort, PreBootJournalHook, PreparedOverlay, SandboxTunnelPort,
    VmBootConfig, VmRuntimePort, VmSessionPort,
};
use crate::safe_tar::{
    apply_open_no_follow, ensure_safe_dir_path, extract_tar_safely, measure_dir_bytes,
    pack_host_path_to_tar, validate_tar_bytes,
};
use crate::warm_pool::WarmReplenishGuard;
use crate::tunnel::TunnelStream;
use crate::warm_pool::{
    validate_vm_spec, CheckoutPop, ReplenisherHandle, WarmEntry, WarmPoolConfig, WarmPoolKey,
    WarmPoolStats, WarmPoolStore,
};
use crate::{is_symlink_or_reparse, map_fs_error, RuntimeManager};

const MAX_GUEST_PATH_BYTES: usize = 4096;
const EGRESS_PROXY_PORT: u16 = 3128;
const MAX_CONCURRENT_EGRESS_STREAMS: usize = 64;

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
    pub warm_pool: WarmPoolConfig,
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
            warm_pool: WarmPoolConfig::default(),
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
        self.warm_pool.validate()?;
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
    pub corrupt_files: usize,
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
                            while tasks.try_join_next().is_some() {}
                            if tasks.len() >= MAX_CONCURRENT_EGRESS_STREAMS {
                                drop(stream);
                                continue;
                            }
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

/// Point-in-time summary of an active sandbox owned by [`LocalRuntimeManager`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveSandboxSummary {
    pub id: SandboxId,
    pub pid: u32,
    pub alive: bool,
    pub network: NetworkPolicy,
    pub remaining_ttl_ms: u64,
    pub live_rss_bytes: Option<u64>,
    pub reserved_rss_mb: u64,
    pub host_rss_budget_mb: Option<u32>,
    pub host_storage_budget_mb: u32,
}

struct ActiveSandbox {
    session: Arc<dyn VmSessionPort>,
    work_dir: PathBuf,
    overlay_path: PathBuf,
    artifact_paths: Vec<PathBuf>,
    network_policy: NetworkPolicy,
    expires_at: Instant,
    reserved_rss_mb: u64,
    host_rss_budget_mb: Option<u32>,
    host_storage_budget_mb: u32,
    egress_proxy: Option<EgressProxyHandle>,
    // Drop `bundle_guard` after `session` and `permit` last so QEMU exits before bundle swap/admission re-opens.
    bundle_guard: Option<BundleReadGuard>,
    permit: AdmissionPermit,
}

struct DestroySlotGuard {
    map: Arc<Mutex<HashMap<SandboxId, watch::Sender<bool>>>>,
    id: SandboxId,
    notify_done: watch::Sender<bool>,
}

impl Drop for DestroySlotGuard {
    fn drop(&mut self) {
        {
            let mut guard = lock_unpoisoned(&self.map);
            guard.remove(&self.id);
        }
        let _ = self.notify_done.send(true);
    }
}

struct SandboxLifecycleGuard {
    map: Arc<Mutex<HashMap<SandboxId, Arc<tokio::sync::Mutex<()>>>>>,
    id: SandboxId,
    inner_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    mutex_arc: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for SandboxLifecycleGuard {
    fn drop(&mut self) {
        drop(self.inner_guard.take());
        let mut map = lock_unpoisoned(&self.map);
        if let Some(existing) = map.get(&self.id) {
            if Arc::ptr_eq(existing, &self.mutex_arc) && Arc::strong_count(&self.mutex_arc) == 2 {
                map.remove(&self.id);
            }
        }
    }
}

struct InFlightSpawnGuard {
    set: Arc<Mutex<HashSet<SandboxId>>>,
    id: SandboxId,
}

impl Drop for InFlightSpawnGuard {
    fn drop(&mut self) {
        lock_unpoisoned(&self.set).remove(&self.id);
    }
}

/// Layer 2 `RuntimeManager` orchestrating VMs, disk overlays, leases, and crash recovery.
pub struct LocalRuntimeManager {
    config: RuntimeManagerConfig,
    _state_lock: File,
    journal: JournalStore,
    sandboxes_dir: PathBuf,
    overlay: Arc<dyn DiskOverlayPort>,
    vm_runtime: Arc<dyn VmRuntimePort>,
    dns_resolver: Arc<dyn HostDnsResolver>,
    dialer: Arc<dyn UpstreamDialer>,
    admission: AdmissionController,
    active: Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    warm_pool: WarmPoolStore,
    in_flight_spawns: Arc<Mutex<HashSet<SandboxId>>>,
    in_flight_destroys: Arc<Mutex<HashMap<SandboxId, watch::Sender<bool>>>>,
    lifecycle_locks: Arc<Mutex<HashMap<SandboxId, Arc<tokio::sync::Mutex<()>>>>>,
    sweeper_abort: Mutex<Option<tokio::task::AbortHandle>>,
    destroy_listeners: Mutex<Vec<DestroyListener>>,
    next_seq: AtomicU64,
    alive: Arc<AtomicBool>,
}

type DestroyListener = Arc<dyn Fn(&SandboxId) + Send + Sync>;

impl Drop for LocalRuntimeManager {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        {
            let mut guard = lock_unpoisoned(&self.sweeper_abort);
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        self.warm_pool.abort_replenisher();
        let drained_active: Vec<ActiveSandbox> = {
            let mut guard = lock_unpoisoned(&self.active);
            guard.drain().map(|(_, entry)| entry).collect()
        };
        let drained_warm = self.warm_pool.clear_ready_for_drop();
        // Drop entries outside `active` and `warm_pool` locks so `AdmissionPermit::drop`
        // and `VmSessionPort::drop` preserve strict lock ordering.
        drop(drained_active);
        drop(drained_warm);
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
        let state_lock = acquire_exclusive_state_lock(&config.state_dir)?;
        let journal = JournalStore::new(config.state_dir.join("journals"))?;
        let sandboxes_dir = config.state_dir.join("sandboxes");
        ensure_safe_dir_path(&sandboxes_dir, true)?;

        let active = Arc::new(Mutex::new(HashMap::<SandboxId, ActiveSandbox>::new()));
        let warm_pool = WarmPoolStore::new();
        let active_for_rss = Arc::downgrade(&active);
        let warm_pool_for_rss = warm_pool.downgrade();
        let observed_rss_fn = Arc::new(move || -> u64 {
            let mut collected: Vec<(Arc<dyn VmSessionPort>, u64)> = Vec::new();
            if let Some(active_arc) = active_for_rss.upgrade() {
                let guard = lock_unpoisoned(&active_arc);
                collected.extend(
                    guard
                        .values()
                        .map(|entry| (Arc::clone(&entry.session), entry.reserved_rss_mb)),
                );
                // Sample WarmPool inside `active` lock (`active -> warm_pool`) so Warm -> Active
                // commit transitions cannot momentarily disappear from both collections.
                warm_pool_for_rss.collect_rss_samples(&mut collected);
            } else {
                warm_pool_for_rss.collect_rss_samples(&mut collected);
            }
            collected
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
            _state_lock: state_lock,
            journal,
            sandboxes_dir,
            overlay,
            vm_runtime,
            dns_resolver,
            dialer,
            admission,
            active,
            warm_pool,
            in_flight_spawns: Arc::new(Mutex::new(HashSet::new())),
            in_flight_destroys: Arc::new(Mutex::new(HashMap::new())),
            lifecycle_locks: Arc::new(Mutex::new(HashMap::new())),
            sweeper_abort: Mutex::new(None),
            destroy_listeners: Mutex::new(Vec::new()),
            next_seq: AtomicU64::new(1),
            alive: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Registers a synchronous listener invoked whenever a sandbox is destroyed (including TTL
    /// lease sweeps and resource-budget enforcement).
    pub fn register_destroy_listener<F>(&self, listener: F)
    where
        F: Fn(&SandboxId) + Send + Sync + 'static,
    {
        lock_unpoisoned(&self.destroy_listeners).push(Arc::new(listener));
    }

    fn notify_destroy_listeners(&self, id: &SandboxId) {
        let listeners: Vec<DestroyListener> = lock_unpoisoned(&self.destroy_listeners).clone();
        for listener in listeners {
            listener(id);
        }
    }

    pub fn config(&self) -> &RuntimeManagerConfig {
        &self.config
    }

    /// Returns a snapshot of current host admission reservations and effective live RSS.
    pub fn current_admission_usage(&self) -> AdmissionUsage {
        self.admission.usage()
    }

    /// Returns a snapshot of current Warm Pool gauges and lifecycle counters.
    pub fn warm_pool_stats(&self) -> WarmPoolStats {
        self.warm_pool.stats()
    }

    /// Returns the IDs of all currently active sandboxes.
    pub fn active_sandbox_ids(&self) -> Vec<SandboxId> {
        let active = lock_unpoisoned(&self.active);
        active.keys().cloned().collect()
    }

    /// Returns a deterministically sorted snapshot of all active sandboxes without holding the
    /// active-map mutex across OS process/RSS probes.
    pub fn list_active_sandboxes(&self) -> Vec<ActiveSandboxSummary> {
        struct RawSandboxEntry {
            id: SandboxId,
            session: Arc<dyn VmSessionPort>,
            network: NetworkPolicy,
            expires_at: Instant,
            reserved_rss_mb: u64,
            host_rss_budget_mb: Option<u32>,
            host_storage_budget_mb: u32,
        }

        let now = Instant::now();
        let raw_entries: Vec<RawSandboxEntry> = {
            let active = lock_unpoisoned(&self.active);
            active
                .iter()
                .map(|(id, entry)| RawSandboxEntry {
                    id: id.clone(),
                    session: Arc::clone(&entry.session),
                    network: entry.network_policy.clone(),
                    expires_at: entry.expires_at,
                    reserved_rss_mb: entry.reserved_rss_mb,
                    host_rss_budget_mb: entry.host_rss_budget_mb,
                    host_storage_budget_mb: entry.host_storage_budget_mb,
                })
                .collect()
        };

        let mut summaries: Vec<ActiveSandboxSummary> = raw_entries
            .into_iter()
            .map(|raw| {
                let remaining_ttl_ms = u64::try_from(
                    raw.expires_at.saturating_duration_since(now).as_millis(),
                )
                .unwrap_or(u64::MAX);
                ActiveSandboxSummary {
                    id: raw.id,
                    pid: raw.session.pid(),
                    alive: raw.session.is_alive(),
                    network: raw.network,
                    remaining_ttl_ms,
                    live_rss_bytes: raw.session.current_rss_bytes(),
                    reserved_rss_mb: raw.reserved_rss_mb,
                    host_rss_budget_mb: raw.host_rss_budget_mb,
                    host_storage_budget_mb: raw.host_storage_budget_mb,
                }
            })
            .collect();
        summaries.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        summaries
    }

    /// Returns the configured [`NetworkPolicy`] for an active, unexpired, living sandbox.
    pub fn active_sandbox_network(&self, id: &SandboxId) -> Result<NetworkPolicy, SandboxError> {
        self.get_active_op_target(id)
            .map(|(_, _, _, network)| network)
    }

    /// Checks whether the owned VM process has definitely exited.
    pub fn sandbox_process_exited(&self, id: &SandboxId) -> Result<bool, SandboxError> {
        let session = {
            let active = lock_unpoisoned(&self.active);
            active.get(id).map(|entry| Arc::clone(&entry.session)).ok_or_else(|| {
                SandboxError::NotFound(format!("sandbox '{id}' does not exist"))
            })?
        };
        session.confirmed_exited()
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

    /// Pre-warms idle VMs in [`NetworkPolicy::Isolated`] mode up to `warm_pool.target_size`
    /// while admission headroom exists and no foreground waiters are queued, returning the ready count.
    pub async fn warm_up(&self) -> Result<usize, SandboxError> {
        let target_size = self.config.warm_pool.target_size;
        let Some(ref template_spec) = self.config.warm_pool.template_spec else {
            return Ok(0);
        };
        if target_size == 0 {
            return Ok(0);
        }

        let mut boot_spec = template_spec.clone();
        boot_spec.network = NetworkPolicy::Isolated;
        let key = WarmPoolKey::from_spec(&boot_spec);

        loop {
            if self.warm_pool.is_draining() || self.admission.has_waiters() {
                break;
            }
            let Some(permit) = self.admission.try_acquire_background(&boot_spec) else {
                break;
            };
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            let sandbox_id = SandboxId::new(format!("mp-{}-{seq}", std::process::id()));
            let Some(guard) = self
                .warm_pool
                .try_begin_replenish(target_size, sandbox_id.clone())
            else {
                drop(permit);
                break;
            };
            if self.admission.has_waiters() {
                drop(guard);
                drop(permit);
                break;
            }

            let (booted, permit, _, warm_guard) = self
                .boot_sandbox_with_journal(
                    sandbox_id.clone(),
                    &boot_spec,
                    JournalLifecycleState::Warm,
                    permit,
                    None,
                    Some(guard),
                )
                .await?;
            let guard = warm_guard.expect("warm replenish guard preserved across boot");
            drop(booted.egress_rx);

            let entry = WarmEntry {
                sandbox_id,
                key: key.clone(),
                session: booted.session,
                work_dir: booted.work_dir,
                prepared: booted.prepared,
                artifact_paths: booted.artifact_paths,
                boot_capabilities: booted.capabilities,
                booted_at: Instant::now(),
                reserved_rss_mb: permit.demand().rss_mb,
                permit,
            };

            let effective_target =
                if self.warm_pool.is_draining() || self.admission.has_waiters() {
                    0
                } else {
                    target_size
                };
            if let Some(rejected) = self
                .warm_pool
                .park_from_replenish(guard, entry, effective_target)
            {
                self.dispose_warm_entry(rejected).await;
                break;
            }
        }

        Ok(self.warm_pool.ready_len())
    }

    /// Starts the background Warm Pool replenisher & `max_idle_age` rotator; aborted when
    /// [`LocalRuntimeManager`] drops or when [`Self::drain_warm_pool`] shuts it down.
    pub fn spawn_warm_pool_replenisher(self: &Arc<Self>) -> JoinHandle<()> {
        struct DoneGuard(watch::Sender<bool>);
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                let _ = self.0.send(true);
            }
        }

        let weak = Arc::downgrade(self);
        let max_idle_age = self.config.warm_pool.max_idle_age;
        let retry_delay = self.config.warm_pool.replenish_retry_delay;
        let expiry_tick =
            Duration::from_secs(1).min((max_idle_age / 2).max(Duration::from_millis(1)));
        let notify = Arc::clone(self.warm_pool.replenish_notify());
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (done_tx, done_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let _done_guard = DoneGuard(done_tx);
            let mut interval = tokio::time::interval(expiry_tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;

            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                let Some(mgr) = weak.upgrade() else {
                    break;
                };

                let _ = mgr.evict_expired_warm_vms().await;

                let wait_retry = !mgr.warm_pool.is_draining()
                    && !mgr.admission.has_waiters()
                    && mgr.config.warm_pool.target_size > 0
                    && mgr.warm_up().await.is_err();
                drop(mgr);

                if *shutdown_rx.borrow() {
                    break;
                }

                if wait_retry {
                    tokio::select! {
                        biased;
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(retry_delay) => {}
                    }
                } else {
                    tokio::select! {
                        biased;
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = notify.notified() => {}
                        _ = interval.tick() => {}
                    }
                }
            }
        });

        self.warm_pool.replace_replenisher(ReplenisherHandle {
            abort_handle: handle.abort_handle(),
            shutdown_tx,
            done_rx,
        });
        handle
    }

    /// Stops any active replenisher and one-way destroys every idle warm VM in the pool.
    pub async fn drain_warm_pool(&self) -> Result<usize, SandboxError> {
        struct DrainReset<'a>(&'a WarmPoolStore);
        impl Drop for DrainReset<'_> {
            fn drop(&mut self) {
                self.0.end_drain();
            }
        }

        self.warm_pool.begin_drain();
        let _drain_reset = DrainReset(&self.warm_pool);

        if let Some(mut handle) = self.warm_pool.take_replenisher() {
            let _ = handle.shutdown_tx.send(true);
            let wait_limit = self
                .config
                .graceful_shutdown_timeout
                .max(Duration::from_millis(500));
            if tokio::time::timeout(wait_limit, handle.done_rx.wait_for(|done| *done))
                .await
                .is_err()
            {
                handle.abort_handle.abort();
                let _ = handle.done_rx.wait_for(|done| *done).await;
            }
        }

        self.warm_pool.wait_for_no_replenishing().await;

        let mut drained = 0usize;
        let mut first_err: Option<SandboxError> = None;
        while let Some(entry) = self.warm_pool.pop_one_for_drain() {
            match self.dispose_warm_entry_checked(entry).await {
                Ok(()) => drained += 1,
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }

        // Wait for any concurrently checking-out, evicting, or replenishing-rejected entries to finish
        // transitioning cleanly before returning (bounded so a stuck guest cannot hang shutdown forever).
        let transition_wait = self
            .config
            .graceful_shutdown_timeout
            .saturating_add(Duration::from_secs(5));
        let _ = tokio::time::timeout(transition_wait, self.warm_pool.wait_for_idle_drain()).await;

        match first_err {
            Some(err) => Err(err),
            None => Ok(drained),
        }
    }

    async fn evict_expired_warm_vms(&self) -> usize {
        let mut count = 0usize;
        while let Some(entry) = self
            .warm_pool
            .pop_one_expired(self.config.warm_pool.max_idle_age)
        {
            self.dispose_warm_entry(entry).await;
            count += 1;
        }
        count
    }

    /// Reconciles persisted crash-recovery journals on daemon startup, killing verified orphans
    /// and cleaning remaining sandbox artifacts while isolating individual corrupt `.journal` files.
    pub async fn reconcile_startup(&self) -> Result<ReconciliationReport, SandboxError> {
        let scan = self.scan_for_reconciliation_async().await?;
        let mut report = ReconciliationReport {
            records_seen: scan.corrupt_files,
            orphans_killed: 0,
            cleaned: 0,
            remaining: scan.corrupt_files,
            corrupt_files: scan.corrupt_files,
        };

        for record in scan.records {
            let is_live = {
                let active = lock_unpoisoned(&self.active);
                active.contains_key(&record.sandbox_id)
                    || self.warm_pool.contains_live_id(&record.sandbox_id)
                    || self.is_in_flight_spawn(&record.sandbox_id)
                    || lock_unpoisoned(&self.in_flight_destroys).contains_key(&record.sandbox_id)
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

    async fn acquire_destroy_slot(&self, id: &SandboxId) -> DestroySlotGuard {
        loop {
            let existing_rx = {
                let mut map = lock_unpoisoned(&self.in_flight_destroys);
                if let Some(tx) = map.get(id) {
                    Some(tx.subscribe())
                } else {
                    let (tx, _rx) = watch::channel(false);
                    map.insert(id.clone(), tx.clone());
                    return DestroySlotGuard {
                        map: Arc::clone(&self.in_flight_destroys),
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

    async fn acquire_lifecycle_lock(&self, id: &SandboxId) -> SandboxLifecycleGuard {
        let mutex_arc = {
            let mut map = lock_unpoisoned(&self.lifecycle_locks);
            Arc::clone(
                map.entry(id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let inner_guard = Arc::clone(&mutex_arc).lock_owned().await;
        SandboxLifecycleGuard {
            map: Arc::clone(&self.lifecycle_locks),
            id: id.clone(),
            inner_guard: Some(inner_guard),
            mutex_arc,
        }
    }

    fn begin_cold_spawn(&self, id: &SandboxId) -> InFlightSpawnGuard {
        lock_unpoisoned(&self.in_flight_spawns).insert(id.clone());
        InFlightSpawnGuard {
            set: Arc::clone(&self.in_flight_spawns),
            id: id.clone(),
        }
    }

    fn is_in_flight_spawn(&self, id: &SandboxId) -> bool {
        lock_unpoisoned(&self.in_flight_spawns).contains(id)
    }

    fn get_active_op_target(
        &self,
        id: &SandboxId,
    ) -> Result<(Arc<dyn VmSessionPort>, PathBuf, u32, NetworkPolicy), SandboxError> {
        let destroying = {
            let map = lock_unpoisoned(&self.in_flight_destroys);
            map.contains_key(id)
        };
        if destroying {
            return Err(SandboxError::LeaseExpired(format!(
                "sandbox '{id}' is being destroyed"
            )));
        }

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
                    entry.network_policy.clone(),
                ));
            }
        }

        Err(SandboxError::NotFound(format!(
            "sandbox '{id}' does not exist"
        )))
    }

    fn get_active_session_for_op(
        &self,
        id: &SandboxId,
    ) -> Result<Arc<dyn VmSessionPort>, SandboxError> {
        self.get_active_op_target(id)
            .map(|(session, _, _, _)| session)
    }

    /// Returns the driver-reported accelerator for a live, leased sandbox.
    pub fn sandbox_accelerator(&self, id: &SandboxId) -> Result<Option<&'static str>, SandboxError> {
        Ok(self.get_active_session_for_op(id)?.accelerator_name())
    }

    /// Validates pre-packed `tar_bytes` on the host (traversal, entry types, storage budget)
    /// and copies it directly to `dst_guest` without re-extracting or re-packing on disk.
    pub async fn copy_in_tar_bytes(
        &self,
        id: &SandboxId,
        dst_guest: String,
        tar_bytes: Vec<u8>,
    ) -> Result<(), SandboxError> {
        validate_guest_path(&dst_guest, "dst_guest")?;
        let (session, work_dir, storage_budget_bytes, pre_bytes) = self.begin_copy_in(id).await?;
        let max_copy_bytes = self.config.max_copy_bytes;
        let max_copy_entries = self.config.max_copy_entries;

        if (tar_bytes.len() as u64) > max_copy_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in tar archive ({} bytes) exceeds max_copy_bytes ({max_copy_bytes} bytes)",
                tar_bytes.len()
            )));
        }
        let remaining_storage_bytes = storage_budget_bytes.saturating_sub(pre_bytes);
        if (tar_bytes.len() as u64) > remaining_storage_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in archive ({} bytes) plus existing storage ({pre_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)",
                tar_bytes.len()
            )));
        }

        let validate_budget = max_copy_bytes.min(remaining_storage_bytes);
        let tar_bytes = tokio::task::spawn_blocking(move || {
            validate_tar_bytes(&tar_bytes, validate_budget, max_copy_entries)?;
            Ok::<_, SandboxError>(tar_bytes)
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("copy_in tar validation failed: {err}")))??;

        self.finish_copy_in(
            id,
            session,
            &work_dir,
            storage_budget_bytes,
            pre_bytes,
            &dst_guest,
            tar_bytes,
        )
        .await
    }

    /// Streams `src_guest` from `id` as validated raw tar bytes without touching the host disk.
    pub async fn copy_out_tar_bytes(
        &self,
        id: &SandboxId,
        src_guest: String,
    ) -> Result<Vec<u8>, SandboxError> {
        validate_guest_path(&src_guest, "src_guest")?;
        let session = self.get_active_session_for_op(id)?;
        let max_bytes = self.config.max_copy_bytes;
        let max_entries = self.config.max_copy_entries;

        let tar_bytes = session.copy_out_tar(&src_guest, max_bytes).await?;

        tokio::task::spawn_blocking(move || {
            validate_tar_bytes(&tar_bytes, max_bytes, max_entries)?;
            Ok::<_, SandboxError>(tar_bytes)
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("copy_out tar validation failed: {err}")))?
    }

    async fn begin_copy_in(
        &self,
        id: &SandboxId,
    ) -> Result<(Arc<dyn VmSessionPort>, PathBuf, u64, u64), SandboxError> {
        let (session, work_dir, host_storage_budget_mb, _) = self.get_active_op_target(id)?;
        let storage_budget_bytes = u64::from(host_storage_budget_mb).saturating_mul(1024 * 1024);

        let pre_bytes = self.measure_sandbox_storage_bytes(id, &work_dir).await?;
        if pre_bytes > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "sandbox '{id}' physical storage ({pre_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)"
            )));
        }

        Ok((session, work_dir, storage_budget_bytes, pre_bytes))
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_copy_in(
        &self,
        id: &SandboxId,
        session: Arc<dyn VmSessionPort>,
        work_dir: &Path,
        storage_budget_bytes: u64,
        pre_bytes: u64,
        dst_guest: &str,
        tar_bytes: Vec<u8>,
    ) -> Result<(), SandboxError> {
        if pre_bytes.saturating_add(tar_bytes.len() as u64) > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in archive ({} bytes) plus existing storage ({pre_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)",
                tar_bytes.len()
            )));
        }

        let _ = session
            .copy_in_tar(dst_guest, tar_bytes, self.config.max_copy_bytes)
            .await?;

        let post_bytes = self.measure_sandbox_storage_bytes(id, work_dir).await?;
        if post_bytes > storage_budget_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "sandbox '{id}' physical storage after copy_in ({post_bytes} bytes) exceeds host_storage_budget ({storage_budget_bytes} bytes)"
            )));
        }

        Ok(())
    }
}

struct BootedSandbox {
    session: Arc<dyn VmSessionPort>,
    work_dir: PathBuf,
    prepared: PreparedOverlay,
    artifact_paths: Vec<PathBuf>,
    capabilities: CapabilityReport,
    expires_at: Instant,
    egress_rx: Option<tokio::sync::mpsc::Receiver<TunnelStream>>,
}

enum CheckoutAttempt {
    Success(SandboxLease),
    FallbackCold,
    Err(SandboxError),
}

struct OwnedAbortTransitionGuard {
    warm_pool: WarmPoolStore,
    sandbox_id: SandboxId,
    is_dirty_checkout: bool,
    armed: bool,
}

impl OwnedAbortTransitionGuard {
    fn new(warm_pool: WarmPoolStore, sandbox_id: SandboxId, is_dirty_checkout: bool) -> Self {
        Self {
            warm_pool,
            sandbox_id,
            is_dirty_checkout,
            armed: true,
        }
    }
}

impl Drop for OwnedAbortTransitionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.is_dirty_checkout {
            self.warm_pool.abort_checkout(&self.sandbox_id);
        } else {
            self.warm_pool.finish_eviction(&self.sandbox_id);
        }
    }
}

struct TransitioningCheckoutGuard {
    manager_alive: Arc<AtomicBool>,
    warm_pool: WarmPoolStore,
    active: Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    journal: JournalStore,
    overlay: Arc<dyn DiskOverlayPort>,
    config: RuntimeManagerConfig,
    entry: Option<WarmEntry>,
}

impl Drop for TransitioningCheckoutGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            let manager_alive = Arc::clone(&self.manager_alive);
            let warm_pool = self.warm_pool.clone();
            let active = Arc::clone(&self.active);
            let journal = self.journal.clone();
            let overlay = Arc::clone(&self.overlay);
            let config = self.config.clone();
            if !manager_alive.load(Ordering::Acquire) {
                warm_pool.abort_checkout(&entry.sandbox_id);
                drop(entry);
                return;
            }
            let abort_guard =
                OwnedAbortTransitionGuard::new(warm_pool.clone(), entry.sandbox_id.clone(), true);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = dispose_warm_entry_with_deps(
                        &warm_pool,
                        &active,
                        &manager_alive,
                        &journal,
                        &overlay,
                        &config,
                        entry,
                        abort_guard,
                    )
                    .await;
                    warm_pool.notify_replenisher();
                });
            } else {
                drop(abort_guard);
                drop(entry);
            }
        }
    }
}

struct BootHookDoneGuard(watch::Sender<bool>);

impl BootHookDoneGuard {
    fn keep_alive(&self) {}
}

impl Drop for BootHookDoneGuard {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

#[derive(Default)]
struct BootProgressState {
    cancelled: bool,
    pid: Option<u32>,
    start_token: Option<u64>,
    artifacts: Vec<PathBuf>,
}

struct BootCancellationGuard {
    manager_alive: Arc<AtomicBool>,
    active: Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    journal: JournalStore,
    overlay: Arc<dyn DiskOverlayPort>,
    vm_runtime: Arc<dyn VmRuntimePort>,
    config: RuntimeManagerConfig,
    sandbox_id: SandboxId,
    spec: SandboxSpec,
    work_dir: PathBuf,
    initial_expires_ms: u64,
    overlay_path: Option<PathBuf>,
    artifact_paths: Vec<PathBuf>,
    bundle_guard: Option<BundleReadGuard>,
    session: Option<Arc<dyn VmSessionPort>>,
    permit: Option<AdmissionPermit>,
    in_flight_guard: Option<InFlightSpawnGuard>,
    warm_guard: Option<WarmReplenishGuard>,
    progress: Arc<Mutex<BootProgressState>>,
    boot_done_rx: Option<watch::Receiver<bool>>,
    armed: bool,
}

impl BootCancellationGuard {
    fn disarm(
        &mut self,
    ) -> (
        AdmissionPermit,
        Option<InFlightSpawnGuard>,
        Option<WarmReplenishGuard>,
    ) {
        self.armed = false;
        (
            self.permit.take().expect("boot permit still held"),
            self.in_flight_guard.take(),
            self.warm_guard.take(),
        )
    }
}

impl Drop for BootCancellationGuard {
    fn drop(&mut self) {
        let (recorded_pid, recorded_token, recorded_artifacts) = {
            let mut st = lock_unpoisoned(&self.progress);
            st.cancelled = true;
            (
                st.pid,
                st.start_token,
                std::mem::take(&mut st.artifacts),
            )
        };
        if !self.armed {
            return;
        }
        let manager_alive = Arc::clone(&self.manager_alive);
        let active = Arc::clone(&self.active);
        let journal = self.journal.clone();
        let overlay = Arc::clone(&self.overlay);
        let vm_runtime = Arc::clone(&self.vm_runtime);
        let config = self.config.clone();
        let sandbox_id = self.sandbox_id.clone();
        let spec = self.spec.clone();
        let work_dir = self.work_dir.clone();
        let initial_expires_ms = self.initial_expires_ms;
        let overlay_path = self.overlay_path.take();
        let mut artifact_paths = std::mem::take(&mut self.artifact_paths);
        for path in recorded_artifacts {
            push_unique_path(&mut artifact_paths, &path);
        }
        let bundle_guard = self.bundle_guard.take();
        let session = self.session.take();
        let permit = self.permit.take();
        let in_flight_guard = self.in_flight_guard.take();
        let warm_guard = self.warm_guard.take();
        let progress = Arc::clone(&self.progress);
        let boot_done_rx = self.boot_done_rx.take();

        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _permit = permit;
                let _in_flight_guard = in_flight_guard;
                let _warm_guard = warm_guard;
                let _bundle_guard = bundle_guard;

                if let Some(session) = session {
                    let graceful = session
                        .graceful_shutdown(config.graceful_shutdown_timeout)
                        .await
                        .unwrap_or(false);
                    let kill_res = if !graceful && session.is_alive() {
                        session.force_kill().await
                    } else {
                        Ok(())
                    };
                    if kill_res.is_err() && session.is_alive() {
                        if let Some(permit) = _permit {
                            let overlay_path =
                                overlay_path.unwrap_or_else(|| work_dir.join("overlay.qcow2"));
                            let reserved_rss_mb = permit.demand().rss_mb;
                            let restored = ActiveSandbox {
                                session,
                                work_dir,
                                overlay_path,
                                artifact_paths,
                                network_policy: spec.network,
                                expires_at: Instant::now(),
                                reserved_rss_mb,
                                host_rss_budget_mb: spec.budget.host_rss_budget_mb,
                                host_storage_budget_mb: spec.budget.host_storage_budget_mb,
                                egress_proxy: None,
                                bundle_guard: _bundle_guard,
                                permit,
                            };
                            restore_active_if_alive(&active, &manager_alive, sandbox_id, restored);
                        }
                        return;
                    }
                    drop(session);
                } else {
                    let mut target_pid = recorded_pid;
                    let mut target_token = recorded_token;
                    if manager_alive.load(Ordering::Acquire) {
                        let rec_journal = journal.clone();
                        let rec_id = sandbox_id.clone();
                        if let Ok(Ok(Some(rec))) =
                            tokio::task::spawn_blocking(move || rec_journal.load_record(&rec_id))
                                .await
                        {
                            if target_pid.is_none() || target_token.is_none() {
                                target_pid = rec.pid;
                                target_token = rec.start_token;
                            }
                            for path in rec.artifact_paths {
                                push_unique_path(&mut artifact_paths, &path);
                            }
                        }
                    }
                    // Immediately terminate any already-started QEMU process to unblock `boot_vm_blocking`.
                    let mut kill_failed = false;
                    let mut attempted_identity: Option<(u32, u64)> = None;
                    if let (Some(pid), Some(start_token)) = (target_pid, target_token) {
                        attempted_identity = Some((pid, start_token));
                        match vm_runtime.kill_orphan_process(pid, start_token).await {
                            Ok(_) | Err(SandboxError::NotFound(_)) => {}
                            Err(_) => kill_failed = true,
                        }
                    }

                    // Wait for `boot_vm` (including any `spawn_blocking` thread) to drop its
                    // `VmBootConfig` before removing overlay/artifacts or releasing permits.
                    let mut boot_still_running = false;
                    if let Some(mut rx) = boot_done_rx {
                        let wait_cap = config.graceful_shutdown_timeout.max(Duration::from_secs(5));
                        if tokio::time::timeout(wait_cap, rx.wait_for(|done| *done))
                            .await
                            .is_err()
                        {
                            boot_still_running = true;
                        }
                    }

                    // Re-read progress to catch any late PID/token/artifacts recorded right before
                    // `boot_vm_blocking` observed cancellation.
                    let (late_pid, late_token, late_artifacts) = {
                        let mut st = lock_unpoisoned(&progress);
                        (st.pid, st.start_token, std::mem::take(&mut st.artifacts))
                    };
                    for path in late_artifacts {
                        push_unique_path(&mut artifact_paths, &path);
                    }
                    if let (Some(pid), Some(start_token)) = (late_pid, late_token) {
                        if attempted_identity != Some((pid, start_token)) || kill_failed {
                            match vm_runtime.kill_orphan_process(pid, start_token).await {
                                Ok(_) | Err(SandboxError::NotFound(_)) => kill_failed = false,
                                Err(_) => kill_failed = true,
                            }
                        }
                    }

                    if kill_failed || boot_still_running {
                        return;
                    }
                }

                if !manager_alive.load(Ordering::Acquire) {
                    return;
                }
                rollback_spawn_with_deps(
                    &journal,
                    &overlay,
                    &config,
                    &sandbox_id,
                    overlay_path.as_deref(),
                    artifact_paths,
                    initial_expires_ms,
                )
                .await;
            });
        }
    }
}

impl LocalRuntimeManager {
    #[allow(clippy::too_many_arguments)]
    async fn boot_sandbox_with_journal(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxSpec,
        target_state: JournalLifecycleState,
        permit: AdmissionPermit,
        in_flight_guard: Option<InFlightSpawnGuard>,
        warm_guard: Option<WarmReplenishGuard>,
    ) -> Result<
        (
            BootedSandbox,
            AdmissionPermit,
            Option<InFlightSpawnGuard>,
            Option<WarmReplenishGuard>,
        ),
        SandboxError,
    > {
        let work_dir = self.sandboxes_dir.join(sandbox_id.as_str());
        let initial_expires_ms = expires_at_unix_ms(spec.lease_ttl);
        let progress = Arc::new(Mutex::new(BootProgressState::default()));
        let mut cancel_guard = BootCancellationGuard {
            manager_alive: Arc::clone(&self.alive),
            active: Arc::clone(&self.active),
            journal: self.journal.clone(),
            overlay: Arc::clone(&self.overlay),
            vm_runtime: Arc::clone(&self.vm_runtime),
            config: self.config.clone(),
            sandbox_id: sandbox_id.clone(),
            spec: spec.clone(),
            work_dir: work_dir.clone(),
            initial_expires_ms,
            overlay_path: None,
            artifact_paths: vec![work_dir.clone()],
            bundle_guard: None,
            session: None,
            permit: Some(permit),
            in_flight_guard,
            warm_guard,
            progress: Arc::clone(&progress),
            boot_done_rx: None,
            armed: true,
        };
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
            cancel_guard.armed = false;
            return Err(err);
        }

        let work_dir_for_create = work_dir.clone();
        let create_dir_res =
            tokio::task::spawn_blocking(move || ensure_safe_dir_path(&work_dir_for_create, true))
                .await
                .map_err(|err| {
                    SandboxError::Internal(format!("create sandbox work_dir task failed: {err}"))
                })?;
        if let Err(err) = create_dir_res {
            self.rollback_spawn(
                &sandbox_id,
                None,
                vec![work_dir],
                initial_expires_ms,
            )
            .await;
            cancel_guard.armed = false;
            return Err(err);
        }

        let prepared = match self
            .overlay
            .prepare_overlay(&sandbox_id, spec, &work_dir)
            .await
        {
            Ok(overlay) => overlay,
            Err(err) => {
                self.rollback_spawn(&sandbox_id, None, vec![work_dir], initial_expires_ms)
                    .await;
                cancel_guard.armed = false;
                return Err(err);
            }
        };

        let spawn_artifacts = merge_artifact_paths(
            &[],
            std::slice::from_ref(&prepared.overlay_path),
            &work_dir,
        );
        cancel_guard.overlay_path = Some(prepared.overlay_path.clone());
        cancel_guard.artifact_paths = spawn_artifacts.clone();
        cancel_guard.bundle_guard = prepared.bundle_guard.clone();
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
            cancel_guard.armed = false;
            return Err(err);
        }

        let journal_for_hook = self.journal.clone();
        let manager_alive_for_hook = Arc::clone(&self.alive);
        let id_for_hook = sandbox_id.clone();
        let overlay_for_hook = prepared.overlay_path.clone();
        let work_dir_for_hook = work_dir.clone();
        let progress_for_hook = Arc::clone(&progress);
        let (boot_done_tx, boot_done_rx) = watch::channel(false);
        let boot_done_guard = BootHookDoneGuard(boot_done_tx);
        cancel_guard.boot_done_rx = Some(boot_done_rx);
        let on_boot_progress: PreBootJournalHook = Arc::new(move |identity, boot_artifacts| {
            // Keep the full `BootHookDoneGuard` inside the hook closure until `VmBootConfig` drops.
            boot_done_guard.keep_alive();
            let mut st = lock_unpoisoned(&progress_for_hook);
            let merged = merge_artifact_paths(
                boot_artifacts,
                std::slice::from_ref(&overlay_for_hook),
                &work_dir_for_hook,
            );
            for path in &merged {
                push_unique_path(&mut st.artifacts, path);
            }
            if st.cancelled {
                let mut newly_recorded = false;
                if let Some((p, t)) = identity {
                    if st.pid != Some(p) || st.start_token != Some(t) {
                        st.pid = Some(p);
                        st.start_token = Some(t);
                        newly_recorded = true;
                    }
                }
                let (pid, start_token) = (st.pid, st.start_token);
                let merged_snapshot = st.artifacts.clone();
                drop(st);
                if newly_recorded && manager_alive_for_hook.load(Ordering::Acquire) {
                    let _ = journal_for_hook.write_record(&JournalRecord {
                        sandbox_id: id_for_hook.clone(),
                        state: JournalLifecycleState::Spawning,
                        pid,
                        start_token,
                        artifact_paths: merged_snapshot,
                        expires_at_unix_ms: initial_expires_ms,
                    });
                }
                return Err(SandboxError::Transport("spawn cancelled".to_owned()));
            }
            let (pid, start_token) = match identity {
                Some((p, t)) => (Some(p), Some(t)),
                None => (None, None),
            };
            st.pid = pid;
            st.start_token = start_token;
            let merged_all = st.artifacts.clone();
            drop(st);
            journal_for_hook.write_record(&JournalRecord {
                sandbox_id: id_for_hook.clone(),
                state: JournalLifecycleState::Spawning,
                pid,
                start_token,
                artifact_paths: merged_all,
                expires_at_unix_ms: initial_expires_ms,
            })
        });

        let boot_cfg = VmBootConfig {
            sandbox_id: sandbox_id.clone(),
            spec: spec.clone(),
            overlay: prepared.clone(),
            work_dir: work_dir.clone(),
            on_boot_progress: Some(on_boot_progress),
        };
        let boot = match self.vm_runtime.boot_vm(boot_cfg).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let (prog_pid, prog_token, prog_artifacts) = {
                    let st = lock_unpoisoned(&progress);
                    (st.pid, st.start_token, st.artifacts.clone())
                };
                let recorded = self.load_record_async(sandbox_id.clone()).await.ok().flatten();
                let (mut target_pid, mut target_token) = (prog_pid, prog_token);
                let mut rollback_artifacts = spawn_artifacts;
                for path in prog_artifacts {
                    push_unique_path(&mut rollback_artifacts, &path);
                }
                if let Some(rec) = recorded {
                    if target_pid.is_none() || target_token.is_none() {
                        target_pid = rec.pid;
                        target_token = rec.start_token;
                    }
                    rollback_artifacts = merge_artifact_paths(
                        &rec.artifact_paths,
                        &rollback_artifacts,
                        &work_dir,
                    );
                }
                cancel_guard.artifact_paths = rollback_artifacts.clone();
                if let (Some(pid), Some(start_token)) = (target_pid, target_token) {
                    match self.vm_runtime.kill_orphan_process(pid, start_token).await {
                        Ok(_) | Err(SandboxError::NotFound(_)) => {}
                        Err(_) => {
                            // Leave the `Spawning` journal with `(pid, start_token)` intact so
                            // `reconcile_startup()` can reap the surviving process later.
                            cancel_guard.armed = false;
                            return Err(err);
                        }
                    }
                }
                drop(prepared.bundle_guard);
                self.rollback_spawn(
                    &sandbox_id,
                    Some(&prepared.overlay_path),
                    rollback_artifacts,
                    initial_expires_ms,
                )
                .await;
                cancel_guard.armed = false;
                return Err(err);
            }
        };

        let session: Arc<dyn VmSessionPort> = Arc::from(boot.session);
        let all_artifacts = merge_artifact_paths(
            &boot.artifact_paths,
            std::slice::from_ref(&prepared.overlay_path),
            &work_dir,
        );
        cancel_guard.session = Some(Arc::clone(&session));
        cancel_guard.artifact_paths = all_artifacts.clone();
        // Anchor lease expiry after VM boot succeeds so cold-boot latency does not consume `spec.lease_ttl`.
        let expires_at = match Instant::now().checked_add(spec.lease_ttl) {
            Some(at) => at,
            None => {
                drop(boot.egress_rx);
                self.teardown_post_boot_failure(
                    &mut cancel_guard,
                    session,
                    &sandbox_id,
                    &prepared.overlay_path,
                    all_artifacts,
                    initial_expires_ms,
                )
                .await;
                return Err(SandboxError::InvalidSpec(
                    "lease ttl overflows host monotonic clock".to_owned(),
                ));
            }
        };
        let target_expires_ms = expires_at_unix_ms(spec.lease_ttl);

        if let Err(err) = self
            .write_journal_async(JournalRecord {
                sandbox_id: sandbox_id.clone(),
                state: target_state,
                pid: Some(boot.pid),
                start_token: Some(boot.start_token),
                artifact_paths: all_artifacts.clone(),
                expires_at_unix_ms: target_expires_ms,
            })
            .await
        {
            drop(boot.egress_rx);
            self.teardown_post_boot_failure(
                &mut cancel_guard,
                session,
                &sandbox_id,
                &prepared.overlay_path,
                all_artifacts,
                target_expires_ms,
            )
            .await;
            return Err(err);
        }

        let (permit, in_flight_guard, warm_guard) = cancel_guard.disarm();
        Ok((
            BootedSandbox {
                session,
                work_dir,
                prepared,
                artifact_paths: all_artifacts,
                capabilities: boot.capabilities,
                expires_at,
                egress_rx: boot.egress_rx,
            },
            permit,
            in_flight_guard,
            warm_guard,
        ))
    }

    async fn teardown_post_boot_failure(
        &self,
        cancel_guard: &mut BootCancellationGuard,
        session: Arc<dyn VmSessionPort>,
        sandbox_id: &SandboxId,
        overlay_path: &Path,
        artifacts: Vec<PathBuf>,
        expires_at_unix_ms: u64,
    ) {
        // Disarm `cancel_guard` synchronously before awaiting so cancelling `spawn()` during
        // teardown never runs a second concurrent `graceful_shutdown` from `Drop`.
        cancel_guard.armed = false;
        cancel_guard.session = None;
        let permit_slot = cancel_guard.permit.take();
        let in_flight_guard = cancel_guard.in_flight_guard.take();
        let warm_guard = cancel_guard.warm_guard.take();
        let bundle_guard = cancel_guard.bundle_guard.take();
        let work_dir = cancel_guard.work_dir.clone();
        let spec = cancel_guard.spec.clone();

        let active = Arc::clone(&self.active);
        let manager_alive = Arc::clone(&self.alive);
        let journal = self.journal.clone();
        let overlay = Arc::clone(&self.overlay);
        let config = self.config.clone();
        let sandbox_id = sandbox_id.clone();
        let overlay_path = overlay_path.to_path_buf();

        let _ = tokio::spawn(async move {
            let _permit = permit_slot;
            let _in_flight_guard = in_flight_guard;
            let _warm_guard = warm_guard;
            let _bundle_guard = bundle_guard;
            let session = session;

            let graceful = session
                .graceful_shutdown(config.graceful_shutdown_timeout)
                .await
                .unwrap_or(false);
            let kill_res = if !graceful && session.is_alive() {
                session.force_kill().await
            } else {
                Ok(())
            };
            if kill_res.is_err() && session.is_alive() {
                if let Some(permit) = _permit {
                    let reserved_rss_mb = permit.demand().rss_mb;
                    let restored = ActiveSandbox {
                        session,
                        work_dir,
                        overlay_path,
                        artifact_paths: artifacts,
                        network_policy: spec.network,
                        expires_at: Instant::now(),
                        reserved_rss_mb,
                        host_rss_budget_mb: spec.budget.host_rss_budget_mb,
                        host_storage_budget_mb: spec.budget.host_storage_budget_mb,
                        egress_proxy: None,
                        bundle_guard: _bundle_guard,
                        permit,
                    };
                    restore_active_if_alive(&active, &manager_alive, sandbox_id, restored);
                }
                return;
            }
            drop(session);
            if manager_alive.load(Ordering::Acquire) {
                rollback_spawn_with_deps(
                    &journal,
                    &overlay,
                    &config,
                    &sandbox_id,
                    Some(&overlay_path),
                    artifacts,
                    expires_at_unix_ms,
                )
                .await;
            }
        })
        .await;
    }

    async fn try_checkout_warm_entry(
        &self,
        entry: WarmEntry,
        spec: &SandboxSpec,
    ) -> CheckoutAttempt {
        let mut guard = TransitioningCheckoutGuard {
            manager_alive: Arc::clone(&self.alive),
            warm_pool: self.warm_pool.clone(),
            active: Arc::clone(&self.active),
            journal: self.journal.clone(),
            overlay: Arc::clone(&self.overlay),
            config: self.config.clone(),
            entry: Some(entry),
        };

        let Some(expires_at) = Instant::now().checked_add(spec.lease_ttl) else {
            let dirty = guard.entry.take().expect("warm entry present");
            self.dispose_checked_out_warm_entry(dirty).await;
            return CheckoutAttempt::Err(SandboxError::InvalidSpec(
                "lease ttl overflows host monotonic clock".to_owned(),
            ));
        };

        let egress_rx = if spec.network != NetworkPolicy::Isolated {
            let res = {
                let candidate = guard.entry.as_ref().expect("warm entry present");
                candidate
                    .session
                    .enable_egress_proxy(EGRESS_PROXY_PORT)
                    .await
            };
            match res {
                Ok(rx) => Some(rx),
                Err(_) => {
                    let dirty = guard.entry.take().expect("warm entry present");
                    self.dispose_checked_out_warm_entry(dirty).await;
                    return CheckoutAttempt::FallbackCold;
                }
            }
        } else {
            None
        };

        let active_expires_ms = expires_at_unix_ms(spec.lease_ttl);
        let journal_res = {
            let candidate = guard.entry.as_ref().expect("warm entry present");
            self.write_journal_async(JournalRecord {
                sandbox_id: candidate.sandbox_id.clone(),
                state: JournalLifecycleState::Active,
                pid: Some(candidate.session.pid()),
                start_token: Some(candidate.session.start_token()),
                artifact_paths: candidate.artifact_paths.clone(),
                expires_at_unix_ms: active_expires_ms,
            })
            .await
        };
        if let Err(err) = journal_res {
            drop(egress_rx);
            let dirty = guard.entry.take().expect("warm entry present");
            self.dispose_checked_out_warm_entry(dirty).await;
            return CheckoutAttempt::Err(err);
        }

        let warm = guard.entry.take().expect("warm entry present");
        let booted = BootedSandbox {
            session: warm.session,
            work_dir: warm.work_dir,
            prepared: warm.prepared,
            artifact_paths: warm.artifact_paths,
            capabilities: warm.boot_capabilities,
            expires_at,
            egress_rx,
        };
        let lease = self.register_active_sandbox(
            warm.sandbox_id,
            spec,
            booted,
            expires_at,
            warm.permit,
            true,
        );
        CheckoutAttempt::Success(lease)
    }

    fn register_active_sandbox(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxSpec,
        booted: BootedSandbox,
        expires_at: Instant,
        permit: AdmissionPermit,
        commit_warm_checkout: bool,
    ) -> SandboxLease {
        let egress_proxy = booted.egress_rx.map(|rx| {
            let proxy = Arc::new(HostEgressProxy::new(
                spec.network.clone(),
                Arc::clone(&self.dns_resolver),
                Arc::clone(&self.dialer),
            ));
            spawn_egress_acceptor(proxy, rx)
        });
        let capabilities = build_lease_capabilities(spec, &booted.prepared, booted.capabilities);
        let reserved_rss_mb = permit.demand().rss_mb;
        let replaced = {
            let mut active = lock_unpoisoned(&self.active);
            let prev = active.insert(
                sandbox_id.clone(),
                ActiveSandbox {
                    session: booted.session,
                    work_dir: booted.work_dir,
                    overlay_path: booted.prepared.overlay_path,
                    artifact_paths: booted.artifact_paths,
                    network_policy: spec.network.clone(),
                    expires_at,
                    reserved_rss_mb,
                    host_rss_budget_mb: spec.budget.host_rss_budget_mb,
                    host_storage_budget_mb: spec.budget.host_storage_budget_mb,
                    egress_proxy,
                    bundle_guard: booted.prepared.bundle_guard,
                    permit,
                },
            );
            if commit_warm_checkout {
                // Commit inside `active` lock (preserving `active -> warm_pool`) so RSS sampling
                // never double-counts or under-counts across the Warm -> Active handoff.
                self.warm_pool.commit_checkout(&sandbox_id);
            }
            prev
        };
        drop(replaced);

        SandboxLease {
            id: sandbox_id,
            ttl: spec.lease_ttl,
            capabilities,
        }
    }

    async fn dispose_warm_entry(&self, entry: WarmEntry) {
        let _ = self.dispose_warm_entry_inner(entry, false).await;
    }

    async fn dispose_warm_entry_checked(&self, entry: WarmEntry) -> Result<(), SandboxError> {
        self.dispose_warm_entry_inner(entry, false).await
    }

    async fn dispose_checked_out_warm_entry(&self, entry: WarmEntry) {
        let _ = self.dispose_warm_entry_inner(entry, true).await;
    }

    async fn dispose_warm_entry_inner(
        &self,
        entry: WarmEntry,
        abort_transitioning_dirty: bool,
    ) -> Result<(), SandboxError> {
        let warm_pool = self.warm_pool.clone();
        let active = Arc::clone(&self.active);
        let manager_alive = Arc::clone(&self.alive);
        let journal = self.journal.clone();
        let overlay = Arc::clone(&self.overlay);
        let config = self.config.clone();
        let abort_guard = OwnedAbortTransitionGuard::new(
            warm_pool.clone(),
            entry.sandbox_id.clone(),
            abort_transitioning_dirty,
        );
        tokio::spawn(async move {
            dispose_warm_entry_with_deps(
                &warm_pool,
                &active,
                &manager_alive,
                &journal,
                &overlay,
                &config,
                entry,
                abort_guard,
            )
            .await
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("warm disposal task failed: {err}")))?
    }

    async fn rollback_spawn(
        &self,
        sandbox_id: &SandboxId,
        overlay_path: Option<&Path>,
        artifacts: Vec<PathBuf>,
        expires_at_unix_ms: u64,
    ) {
        rollback_spawn_with_deps(
            &self.journal,
            &self.overlay,
            &self.config,
            sandbox_id,
            overlay_path,
            artifacts,
            expires_at_unix_ms,
        )
        .await;
    }

    async fn remove_overlay_artifacts(&self, paths: &[PathBuf]) {
        remove_overlay_artifacts_with(&self.overlay, paths).await;
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

    async fn scan_for_reconciliation_async(&self) -> Result<ReconciliationScan, SandboxError> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.scan_for_reconciliation())
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
        validate_vm_spec(&spec, "requested")?;

        // Fast path: check out a compatible warm VM when no foreground waiters are queued.
        if !self.admission.has_waiters() {
            let key = WarmPoolKey::from_spec(&spec);
            loop {
                match self
                    .warm_pool
                    .pop_for_checkout(&key, self.config.warm_pool.max_idle_age)
                {
                    CheckoutPop::None => break,
                    CheckoutPop::ExpiredOrDead(stale) => {
                        self.dispose_warm_entry(stale).await;
                        if self.admission.has_waiters() {
                            break;
                        }
                    }
                    CheckoutPop::Candidate(entry) => {
                        match self.try_checkout_warm_entry(entry, &spec).await {
                            CheckoutAttempt::Success(lease) => {
                                self.warm_pool.notify_replenisher();
                                return Ok(lease);
                            }
                            CheckoutAttempt::FallbackCold => {
                                self.warm_pool.notify_replenisher();
                                break;
                            }
                            CheckoutAttempt::Err(err) => {
                                self.warm_pool.notify_replenisher();
                                return Err(err);
                            }
                        }
                    }
                }
            }
        }

        // Cold path: reject impossible specs before evicting healthy warm VMs.
        self.admission.check_individual_cap(&spec)?;

        while self.admission.would_exceed_with(&spec) {
            let Some(evicted) = self.warm_pool.pop_one_for_eviction() else {
                break;
            };
            self.dispose_warm_entry(evicted).await;
        }

        let permit = self.admission.acquire(&spec).await?;

        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let sandbox_id = SandboxId::new(format!("mp-{}-{seq}", std::process::id()));
        let spawn_guard = self.begin_cold_spawn(&sandbox_id);

        let (booted, permit, spawn_guard, _) = self
            .boot_sandbox_with_journal(
                sandbox_id.clone(),
                &spec,
                JournalLifecycleState::Active,
                permit,
                Some(spawn_guard),
                None,
            )
            .await?;

        let expires_at = booted.expires_at;
        let lease =
            self.register_active_sandbox(sandbox_id, &spec, booted, expires_at, permit, false);
        drop(spawn_guard);
        self.warm_pool.record_cold_spawn();
        Ok(lease)
    }

    async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError> {
        if ttl.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "lease ttl must be greater than zero".to_owned(),
            ));
        }
        if ttl > MAX_LEASE_TTL {
            return Err(SandboxError::InvalidSpec(format!(
                "lease ttl exceeds maximum allowed duration of {} seconds",
                MAX_LEASE_TTL.as_secs()
            )));
        }

        let _lifecycle = self.acquire_lifecycle_lock(id).await;
        let destroying = {
            let map = lock_unpoisoned(&self.in_flight_destroys);
            map.contains_key(id)
        };
        if destroying {
            return Err(SandboxError::LeaseExpired(format!(
                "sandbox '{id}' is being destroyed"
            )));
        }

        let new_expires_ms = expires_at_unix_ms(ttl);
        let (prev_expires_at, updated_record) = {
            let now = Instant::now();
            let next_expires_at = now.checked_add(ttl).ok_or_else(|| {
                SandboxError::InvalidSpec("lease ttl overflows host monotonic clock".to_owned())
            })?;
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
            let prev_expires_at = entry.expires_at;
            entry.expires_at = next_expires_at;
            (
                prev_expires_at,
                JournalRecord {
                    sandbox_id: id.clone(),
                    state: JournalLifecycleState::Active,
                    pid: Some(entry.session.pid()),
                    start_token: Some(entry.session.start_token()),
                    artifact_paths: entry.artifact_paths.clone(),
                    expires_at_unix_ms: new_expires_ms,
                },
            )
        };

        if let Err(err) = self.write_journal_async(updated_record).await {
            let mut active = lock_unpoisoned(&self.active);
            if let Some(entry) = active.get_mut(id) {
                entry.expires_at = prev_expires_at;
            }
            return Err(err);
        }

        Ok(())
    }

    async fn exec_stream(
        &self,
        id: &SandboxId,
        req: ExecRequest,
    ) -> Result<ExecStream, SandboxError> {
        validate_exec_request(&req)?;
        let deadline = req.deadline;
        let stdout_budget_bytes = req.stdout_budget_bytes;
        let stderr_budget_bytes = req.stderr_budget_bytes;
        let session = self.get_active_session_for_op(id)?;
        let stream = session.exec_stream(req).await?;
        Ok(stream.with_limits(deadline, stdout_budget_bytes, stderr_budget_bytes))
    }

    async fn copy_in(
        &self,
        id: &SandboxId,
        src_host: PathBuf,
        dst_guest: String,
    ) -> Result<(), SandboxError> {
        validate_guest_path(&dst_guest, "dst_guest")?;
        let (session, work_dir, storage_budget_bytes, pre_bytes) = self.begin_copy_in(id).await?;

        let max_copy_bytes = self.config.max_copy_bytes;
        let remaining_storage_bytes = storage_budget_bytes.saturating_sub(pre_bytes);
        let pack_budget = max_copy_bytes.min(remaining_storage_bytes);

        let tar_bytes =
            tokio::task::spawn_blocking(move || pack_host_path_to_tar(&src_host, pack_budget))
                .await
                .map_err(|err| {
                    SandboxError::Internal(format!("copy_in tar packing failed: {err}"))
                })??;

        self.finish_copy_in(
            id,
            session,
            &work_dir,
            storage_budget_bytes,
            pre_bytes,
            &dst_guest,
            tar_bytes,
        )
        .await
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
        let slot = self.acquire_destroy_slot(id).await;
        let lifecycle = self.acquire_lifecycle_lock(id).await;

        let pre_in_flight = self.warm_pool.contains_live_id(id) || self.is_in_flight_spawn(id);
        let mut removed_active = {
            let mut active = lock_unpoisoned(&self.active);
            active.remove(id)
        };
        if removed_active.is_none() {
            let post_in_flight =
                self.warm_pool.contains_live_id(id) || self.is_in_flight_spawn(id);
            removed_active = lock_unpoisoned(&self.active).remove(id);
            if removed_active.is_none() && (pre_in_flight || post_in_flight) {
                return Ok(DestroyStatus::AllResourcesCleaned);
            }
        }
        self.notify_destroy_listeners(id);

        let id_owned = id.clone();
        let manager_alive = Arc::clone(&self.alive);
        let active = Arc::clone(&self.active);
        let warm_pool = self.warm_pool.clone();
        let journal = self.journal.clone();
        let overlay = Arc::clone(&self.overlay);
        let vm_runtime = Arc::clone(&self.vm_runtime);
        let config = self.config.clone();
        let sandboxes_dir = self.sandboxes_dir.clone();

        tokio::spawn(async move {
            let _slot = slot;
            let _lifecycle = lifecycle;
            destroy_locked_with_deps(
                id_owned,
                removed_active,
                manager_alive,
                active,
                warm_pool,
                journal,
                overlay,
                vm_runtime,
                config,
                sandboxes_dir,
            )
            .await
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("destroy task failed: {err}")))?
    }
}

#[allow(clippy::too_many_arguments)]
async fn destroy_locked_with_deps(
    id: SandboxId,
    removed_active: Option<ActiveSandbox>,
    manager_alive: Arc<AtomicBool>,
    active: Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    warm_pool: WarmPoolStore,
    journal: JournalStore,
    overlay: Arc<dyn DiskOverlayPort>,
    vm_runtime: Arc<dyn VmRuntimePort>,
    config: RuntimeManagerConfig,
    sandboxes_dir: PathBuf,
) -> Result<DestroyStatus, SandboxError> {
    struct OwnedDestroyPermit {
        bundle_guard: Option<BundleReadGuard>,
        permit: Option<AdmissionPermit>,
        warm_pool: WarmPoolStore,
    }
    impl Drop for OwnedDestroyPermit {
        fn drop(&mut self) {
            drop(self.bundle_guard.take());
            drop(self.permit.take());
            self.warm_pool.notify_replenisher();
        }
    }

    let j_load = journal.clone();
    let id_load = id.clone();
    let journal_rec = match tokio::task::spawn_blocking(move || j_load.load_record(&id_load))
        .await
        .map_err(|err| SandboxError::Internal(format!("journal load task failed: {err}")))?
    {
        Ok(rec) => rec,
        Err(_) if removed_active.is_some() => None,
        Err(err) => return Err(err),
    };

    if removed_active.is_none() && journal_rec.is_none() {
        return Ok(DestroyStatus::AllResourcesCleaned);
    }

    let expires_at_unix_ms = journal_rec
        .as_ref()
        .map(|rec| rec.expires_at_unix_ms)
        .unwrap_or_else(unix_now_ms);

    let (overlay_path_opt, artifacts, _permit_and_notify) = if let Some(entry) = removed_active {
        let ActiveSandbox {
            session,
            work_dir,
            overlay_path,
            artifact_paths: entry_artifacts,
            network_policy,
            expires_at: _,
            reserved_rss_mb,
            host_rss_budget_mb,
            host_storage_budget_mb,
            egress_proxy,
            bundle_guard,
            permit,
        } = entry;

        let journal_paths = journal_rec
            .as_ref()
            .map(|rec| rec.artifact_paths.as_slice())
            .unwrap_or(&[]);
        let mut merged = merge_artifact_paths(
            &entry_artifacts,
            journal_paths,
            &sandboxes_dir.join(id.as_str()),
        );
        push_unique_path(&mut merged, &overlay_path);

        if manager_alive.load(Ordering::Acquire) {
            let rec = JournalRecord {
                sandbox_id: id.clone(),
                state: JournalLifecycleState::Destroying,
                pid: Some(session.pid()),
                start_token: Some(session.start_token()),
                artifact_paths: merged.clone(),
                expires_at_unix_ms,
            };
            let j = journal.clone();
            let _ = tokio::task::spawn_blocking(move || j.write_record(&rec)).await;
        }

        let graceful_ok = session
            .graceful_shutdown(config.graceful_shutdown_timeout)
            .await
            .unwrap_or(false);
        let kill_res = if !graceful_ok && session.is_alive() {
            session.force_kill().await
        } else {
            Ok(())
        };
        if let Err(err) = kill_res {
            if session.is_alive() {
                let restored = ActiveSandbox {
                    session,
                    work_dir,
                    overlay_path,
                    artifact_paths: entry_artifacts,
                    network_policy,
                    expires_at: Instant::now(),
                    reserved_rss_mb,
                    host_rss_budget_mb,
                    host_storage_budget_mb,
                    egress_proxy,
                    bundle_guard,
                    permit,
                };
                restore_active_if_alive(&active, &manager_alive, id.clone(), restored);
                return Err(err);
            }
        }

        // Strict one-way disposal: dirty sandboxes are never recycled back into `warm_pool`.
        warm_pool.record_disposed_dirty();
        let permit_guard = OwnedDestroyPermit {
            bundle_guard,
            permit: Some(permit),
            warm_pool: warm_pool.clone(),
        };

        // Drop session ownership before removing overlays/sockets so Windows releases all handles,
        // and shut down all proxy tasks before cleanup completes.
        drop(session);
        if let Some(proxy) = egress_proxy {
            proxy.shutdown().await;
        }
        (Some(overlay_path), merged, Some(permit_guard))
    } else if let Some(rec) = journal_rec {
        if let (Some(pid), Some(start_token)) = (rec.pid, rec.start_token) {
            match vm_runtime.kill_orphan_process(pid, start_token).await {
                Ok(_) | Err(SandboxError::NotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }
        (None, rec.artifact_paths, None)
    } else {
        return Ok(DestroyStatus::AllResourcesCleaned);
    };

    if !manager_alive.load(Ordering::Acquire) {
        return Err(SandboxError::Transport(
            "runtime manager dropped during destroy".to_owned(),
        ));
    }

    if let Some(overlay_path) = overlay_path_opt {
        let _ = overlay.remove_overlay(&overlay_path).await;
    }
    remove_overlay_artifacts_with(&overlay, &artifacts).await;

    let result = match cleanup_artifacts_with_backoff(
        &artifacts,
        config.cleanup_max_attempts,
        config.cleanup_initial_delay,
    )
    .await
    {
        DestroyStatus::AllResourcesCleaned => {
            let j_rm = journal.clone();
            let id_rm = id.clone();
            let rm_res = tokio::task::spawn_blocking(move || j_rm.remove_record(&id_rm))
                .await
                .map_err(|err| SandboxError::Internal(format!("journal remove task failed: {err}")));
            if !matches!(rm_res, Ok(Ok(()))) {
                Ok(DestroyStatus::ProcessExited {
                    remaining_artifacts: vec![journal.record_path(&id)],
                })
            } else {
                Ok(DestroyStatus::AllResourcesCleaned)
            }
        }
        DestroyStatus::ProcessExited {
            remaining_artifacts,
        } => {
            let rec = JournalRecord {
                sandbox_id: id,
                state: JournalLifecycleState::Destroying,
                pid: None,
                start_token: None,
                artifact_paths: remaining_artifacts.clone(),
                expires_at_unix_ms,
            };
            let j_wr = journal.clone();
            let _ = tokio::task::spawn_blocking(move || j_wr.write_record(&rec)).await;
            Ok(DestroyStatus::ProcessExited {
                remaining_artifacts,
            })
        }
    };
    drop(_permit_and_notify);
    result
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
    if req.deadline > MAX_LEASE_TTL {
        return Err(SandboxError::InvalidSpec(format!(
            "exec deadline exceeds maximum allowed duration of {} seconds",
            MAX_LEASE_TTL.as_secs()
        )));
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

fn acquire_exclusive_state_lock(state_dir: &Path) -> Result<File, SandboxError> {
    let lock_path = state_dir.join("state.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(SandboxError::PolicyViolation(format!(
                    "refusing symlink or reparse state lock file '{}'",
                    lock_path.display()
                )));
            }
            if !meta.file_type().is_file() {
                return Err(SandboxError::PolicyViolation(format!(
                    "state lock path '{}' is not a regular file",
                    lock_path.display()
                )));
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(map_fs_error(&lock_path, "inspect state lock file", err)),
    }

    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    apply_open_no_follow(&mut opts);
    let file = opts
        .open(&lock_path)
        .map_err(|err| map_fs_error(&lock_path, "open state lock file", err))?;

    let open_meta = file
        .metadata()
        .map_err(|err| map_fs_error(&lock_path, "inspect opened state lock file", err))?;
    if is_symlink_or_reparse(&open_meta) || !open_meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "opened state lock '{}' is not a safe regular file",
            lock_path.display()
        )));
    }

    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(SandboxError::PolicyViolation(format!(
            "state directory '{}' is already locked by another active runtime instance",
            state_dir.display()
        ))),
        Err(TryLockError::Error(err)) => {
            Err(map_fs_error(&lock_path, "acquire exclusive state lock", err))
        }
    }
}

fn bytes_to_mib_ceil(bytes: u64) -> u64 {
    bytes.div_ceil(1024 * 1024)
}

fn build_lease_capabilities(
    spec: &SandboxSpec,
    _prepared: &PreparedOverlay,
    boot_caps: CapabilityReport,
) -> CapabilityReport {
    // Host storage is enforced via qcow2 virtual disk sizing, admission reservations, pre-copy
    // checks, and periodic physical directory sweeps rather than a kernel filesystem quota, so it
    // is honestly reported as BestEffort unless the underlying VMM driver provides a HardLimit.
    let host_storage = match boot_caps.host_storage {
        EnforcementLevel::HardLimit => EnforcementLevel::HardLimit,
        EnforcementLevel::BestEffort | EnforcementLevel::Unsupported => {
            EnforcementLevel::BestEffort
        }
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

fn restore_active_if_alive(
    active: &Mutex<HashMap<SandboxId, ActiveSandbox>>,
    manager_alive: &AtomicBool,
    id: SandboxId,
    restored: ActiveSandbox,
) {
    let rejected = {
        let mut active_map = lock_unpoisoned(active);
        if manager_alive.load(Ordering::Acquire) {
            active_map.insert(id, restored);
            None
        } else {
            Some(restored)
        }
    };
    drop(rejected);
}

#[allow(clippy::too_many_arguments)]
async fn dispose_warm_entry_with_deps(
    warm_pool: &WarmPoolStore,
    active: &Arc<Mutex<HashMap<SandboxId, ActiveSandbox>>>,
    manager_alive: &Arc<AtomicBool>,
    journal: &JournalStore,
    overlay: &Arc<dyn DiskOverlayPort>,
    config: &RuntimeManagerConfig,
    entry: WarmEntry,
    abort_guard: OwnedAbortTransitionGuard,
) -> Result<(), SandboxError> {
    let WarmEntry {
        sandbox_id,
        key,
        session,
        work_dir,
        prepared,
        artifact_paths,
        boot_capabilities: _,
        booted_at: _,
        reserved_rss_mb,
        permit,
    } = entry;

    // Bind in strict LIFO order so unwind/abort drops `session` -> `bundle_guard` ->
    // `abort_guard` -> `permit_slot` and never re-opens admission before QEMU is terminated.
    let mut permit_slot = Some(permit);
    let mut abort_guard = abort_guard;
    let overlay_path = prepared.overlay_path;
    let bundle_guard = prepared.bundle_guard;
    let session = session;
    let is_dirty_checkout = abort_guard.is_dirty_checkout;

    let merged = merge_artifact_paths(
        &artifact_paths,
        std::slice::from_ref(&overlay_path),
        &work_dir,
    );
    let expires_ms = unix_now_ms();

    if manager_alive.load(Ordering::Acquire) {
        let rec = JournalRecord {
            sandbox_id: sandbox_id.clone(),
            state: JournalLifecycleState::Destroying,
            pid: Some(session.pid()),
            start_token: Some(session.start_token()),
            artifact_paths: merged.clone(),
            expires_at_unix_ms: expires_ms,
        };
        let j = journal.clone();
        let _ = tokio::task::spawn_blocking(move || j.write_record(&rec)).await;
    }

    let graceful_ok = session
        .graceful_shutdown(config.graceful_shutdown_timeout)
        .await
        .unwrap_or(false);
    let kill_res = if !graceful_ok && session.is_alive() {
        session.force_kill().await
    } else {
        Ok(())
    };
    if kill_res.is_err() && session.is_alive() {
        let permit = permit_slot.take().expect("permit still held");
        let restored = ActiveSandbox {
            session,
            work_dir,
            overlay_path,
            artifact_paths: merged,
            network_policy: NetworkPolicy::Isolated,
            expires_at: Instant::now(),
            reserved_rss_mb,
            host_rss_budget_mb: key.budget.host_rss_budget_mb,
            host_storage_budget_mb: key.budget.host_storage_budget_mb,
            egress_proxy: None,
            bundle_guard,
            permit,
        };
        let uninserted = {
            let mut active_map = lock_unpoisoned(active);
            let uninserted = if manager_alive.load(Ordering::Acquire) {
                active_map.insert(sandbox_id.clone(), restored);
                None
            } else {
                Some(restored)
            };
            // Commit transition under `active` lock (`active -> warm_pool`) to avoid RSS sampling gaps.
            if is_dirty_checkout {
                warm_pool.abort_checkout(&sandbox_id);
            } else {
                warm_pool.finish_eviction(&sandbox_id);
            }
            abort_guard.armed = false;
            uninserted
        };
        drop(uninserted);
        return kill_res;
    }
    drop(session);

    if manager_alive.load(Ordering::Acquire) {
        remove_overlay_artifacts_with(overlay, &merged).await;
        rollback_spawn_with_deps(
            journal,
            overlay,
            config,
            &sandbox_id,
            Some(&overlay_path),
            merged,
            expires_ms,
        )
        .await;
    }

    drop(bundle_guard);
    drop(abort_guard);
    drop(permit_slot.take());
    kill_res
}

async fn remove_overlay_artifacts_with(overlay: &Arc<dyn DiskOverlayPort>, paths: &[PathBuf]) {
    for path in paths {
        if is_overlay_artifact(path) {
            let _ = overlay.remove_overlay(path).await;
        }
    }
}

async fn rollback_spawn_with_deps(
    journal: &JournalStore,
    overlay: &Arc<dyn DiskOverlayPort>,
    config: &RuntimeManagerConfig,
    sandbox_id: &SandboxId,
    overlay_path: Option<&Path>,
    artifacts: Vec<PathBuf>,
    expires_at_unix_ms: u64,
) {
    if let Some(path) = overlay_path {
        let _ = overlay.remove_overlay(path).await;
    }
    match cleanup_artifacts_with_backoff(
        &artifacts,
        config.cleanup_max_attempts,
        config.cleanup_initial_delay,
    )
    .await
    {
        DestroyStatus::AllResourcesCleaned => {
            let j = journal.clone();
            let id = sandbox_id.clone();
            let _ = tokio::task::spawn_blocking(move || j.remove_record(&id)).await;
        }
        DestroyStatus::ProcessExited {
            remaining_artifacts,
        } => {
            let j = journal.clone();
            let rec = JournalRecord {
                sandbox_id: sandbox_id.clone(),
                state: JournalLifecycleState::Destroying,
                pid: None,
                start_token: None,
                artifact_paths: remaining_artifacts,
                expires_at_unix_ms,
            };
            let _ = tokio::task::spawn_blocking(move || j.write_record(&rec)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashSet};
    use std::fs;
    use std::sync::atomic::AtomicBool;

    use sandbox_core::{
        AccelerationPolicy, EgressRule, ExecExitStatus, IsolationMode, ResourceBudget,
    };
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
            warm_pool: WarmPoolConfig::default(),
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
                guest_arch: None,
                virtual_disk_mb: spec.budget.virtual_disk_mb,
                provisioned_host_bytes: 64,
                bundle_guard: None,
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
        dropped_count: AtomicU64,
        rss_bytes: AtomicU64,
        fail_enable_egress: AtomicBool,
        graceful_succeeds: bool,
        graceful_calls: Mutex<usize>,
        force_kill_calls: Mutex<usize>,
        copied_in: Mutex<Vec<(String, Vec<u8>)>>,
        copy_out_archive: Mutex<Vec<u8>>,
        egress_enabled_port: Mutex<Option<u16>>,
        egress_tx: Mutex<Option<tokio::sync::mpsc::Sender<TunnelStream>>>,
    }

    struct MockVmSession {
        pid: u32,
        start_token: u64,
        artifacts: Vec<PathBuf>,
        state: Arc<MockSessionState>,
    }

    impl Drop for MockVmSession {
        fn drop(&mut self) {
            self.state.alive.store(false, Ordering::Release);
            self.state.dropped_count.fetch_add(1, Ordering::AcqRel);
        }
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

        async fn enable_egress_proxy(
            &self,
            proxy_port: u16,
        ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> {
            if proxy_port == 0 {
                return Err(SandboxError::InvalidSpec(
                    "egress proxy_port must be greater than zero".to_owned(),
                ));
            }
            if !self.is_alive() {
                return Err(SandboxError::Transport(
                    "mock VM session is no longer alive".to_owned(),
                ));
            }
            if self.state.fail_enable_egress.load(Ordering::Acquire) {
                return Err(SandboxError::Transport(
                    "simulated egress activation failure".to_owned(),
                ));
            }
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            {
                let mut port_guard = lock_unpoisoned(&self.state.egress_enabled_port);
                if port_guard.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "egress proxy is already enabled on this session".to_owned(),
                    ));
                }
                *port_guard = Some(proxy_port);
            }
            *lock_unpoisoned(&self.state.egress_tx) = Some(tx);
            Ok(rx)
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
        boot_delay: Option<Duration>,
        pre_handshake_stall: Option<(
            PathBuf,
            tokio::sync::oneshot::Sender<(u32, u64)>,
        )>,
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
            let (pid, token, graceful, fail, boot_delay, enable_egress, stall) = {
                let mut st = lock_unpoisoned(&self.state);
                st.next_pid += 1;
                (
                    st.next_pid,
                    u64::from(st.next_pid) * 17,
                    st.graceful_succeeds,
                    st.fail_boot,
                    st.boot_delay,
                    st.enable_egress_channel && config.spec.network != NetworkPolicy::Isolated,
                    st.pre_handshake_stall.take(),
                )
            };
            if let Some((ext_ipc_path, notify_tx)) = stall {
                fs::write(&ext_ipc_path, b"ipc").unwrap();
                let artifacts = vec![ext_ipc_path];
                config.record_boot_progress(None, &artifacts)?;
                config.record_boot_progress(Some((pid, token)), &artifacts)?;
                let _ = notify_tx.send((pid, token));
                std::future::pending::<()>().await;
            }
            if let Some(delay) = boot_delay {
                tokio::time::sleep(delay).await;
            }
            if fail {
                return Err(SandboxError::AccelerationUnavailable(
                    "simulated boot failure".into(),
                ));
            }
            let sock_path = config.work_dir.join("a.sock");
            fs::write(&sock_path, b"sock").unwrap();
            let artifacts = vec![sock_path.clone()];
            config.record_boot_progress(None, &artifacts)?;
            config.record_boot_progress(Some((pid, token)), &artifacts)?;
            let (egress_tx, egress_rx) = if enable_egress {
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
            let sess_state = Arc::new(MockSessionState {
                alive: AtomicBool::new(true),
                dropped_count: AtomicU64::new(0),
                rss_bytes: AtomicU64::new(64 * 1024 * 1024),
                fail_enable_egress: AtomicBool::new(false),
                graceful_succeeds: graceful,
                graceful_calls: Mutex::new(0),
                force_kill_calls: Mutex::new(0),
                copied_in: Mutex::new(Vec::new()),
                copy_out_archive: Mutex::new(Vec::new()),
                egress_enabled_port: Mutex::new(enable_egress.then_some(3128)),
                egress_tx: Mutex::new(egress_tx.clone()),
            });
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
        assert_eq!(lease.capabilities.host_storage, EnforcementLevel::BestEffort);
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

        // Without an OS filesystem quota, host_storage honestly reports BestEffort across headroom levels.
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
            assert_eq!(lease.capabilities.host_storage, EnforcementLevel::BestEffort);
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
                corrupt_files: 0,
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

        let deadline = Instant::now() + Duration::from_secs(2);
        while mgr.journal.load_record(&lease.id).unwrap().is_some()
            || Arc::strong_count(&mgr) > 1
        {
            assert!(
                Instant::now() < deadline,
                "sweeper did not reap expired sandbox '{}' and release manager ref within 2s",
                lease.id
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

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

    #[tokio::test]
    async fn warm_pool_prewarms_writes_warm_journals_rejects_shared_kernel_and_counts_rss() {
        let tmp = TestTempDir::new("mgr-wp-prewarm");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));

        let mut shared_spec = valid_spec(Duration::from_secs(60));
        shared_spec.isolation = IsolationMode::SharedKernelAllowed;
        let mut bad_cfg = base_config(state_dir.clone());
        bad_cfg.warm_pool = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(shared_spec),
            ..Default::default()
        };
        assert!(matches!(
            LocalRuntimeManager::new(bad_cfg, overlay.clone(), vm.clone()),
            Err(SandboxError::UnsupportedIsolationMode(_))
        ));

        let mut cfg = base_config(state_dir.clone());
        let mut tmpl = valid_spec(Duration::from_secs(60));
        tmpl.budget.guest_ram_mb = 128;
        tmpl.budget.host_rss_budget_mb = Some(256);
        cfg.admission = AdmissionLimits {
            max_total_host_rss_mb: Some(600),
            ..Default::default()
        };
        cfg.warm_pool = WarmPoolConfig {
            target_size: 2,
            template_spec: Some(tmpl),
            ..Default::default()
        };

        let mgr = LocalRuntimeManager::new(cfg, overlay.clone(), vm.clone()).unwrap();

        // Boot failure during warm_up rolls back cleanly without leaking permits, journals, or dirs.
        lock_unpoisoned(&vm.state).fail_boot = true;
        assert!(matches!(
            mgr.warm_up().await,
            Err(SandboxError::AccelerationUnavailable(_))
        ));
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
        assert_eq!(mgr.warm_pool_stats().replenishing_vms, 0);
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
        assert!(mgr.journal.load_records().unwrap().is_empty());
        assert_eq!(fs::read_dir(state_dir.join("sandboxes")).unwrap().count(), 0);

        lock_unpoisoned(&vm.state).fail_boot = false;
        let ready = mgr.warm_up().await.unwrap();
        assert_eq!(ready, 2);
        let stats = mgr.warm_pool_stats();
        assert_eq!(stats.ready_vms, 2);
        assert_eq!(stats.replenishing_vms, 0);

        // Journal records on disk must be in `Warm` state with PID and start_token.
        let records = mgr.journal.load_records().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|r| r.state == JournalLifecycleState::Warm && r.pid.is_some()));

        // Idle warm VMs reserve capacity and contribute live RSS to effective_host_rss_mb.
        let usage = mgr.current_admission_usage();
        assert_eq!(usage.active_sandboxes, 2);
        assert_eq!(usage.reserved_host_rss_mb, 512);
        assert_eq!(usage.effective_host_rss_mb, 512);

        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions[0]
                .rss_bytes
                .store(400 * 1024 * 1024, Ordering::Release);
        }
        // 400 MiB (warm #0 live) + 256 MiB (warm #1 reserved) = 656 MiB > 600 MiB!
        assert_eq!(mgr.current_admission_usage().effective_host_rss_mb, 656);
        let mut extra = valid_spec(Duration::from_secs(30));
        extra.budget.guest_ram_mb = 64;
        extra.budget.host_rss_budget_mb = Some(64);
        assert!(mgr.admission.would_exceed_with(&extra));

        // Evicting warm #0 alone brings total RSS to 256 MiB, letting `extra` (64 MiB) fit cleanly!
        let extra_lease = mgr.spawn(extra.clone()).await.unwrap();
        assert_eq!(mgr.warm_pool_stats().ready_vms, 1);
        assert_eq!(mgr.warm_pool_stats().total_evictions, 1);

        // If the active sandbox spikes to 560 MiB, evicting warm #1 still leaves 560 + 64 > 600 -> rejected.
        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions[2]
                .rss_bytes
                .store(560 * 1024 * 1024, Ordering::Release);
        }
        assert!(matches!(
            mgr.spawn(extra).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
        assert_eq!(mgr.warm_pool_stats().total_evictions, 2);
        mgr.destroy(&extra_lease.id).await.unwrap();
    }

    #[tokio::test]
    async fn warm_pool_fast_checkout_serves_isolated_and_dynamic_domain_allowlist_egress() {
        use std::io;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use crate::egress::BoxedUpstreamStream;

        struct AllowDns;
        #[async_trait::async_trait]
        impl HostDnsResolver for AllowDns {
            async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
                Ok(vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    port,
                )])
            }
        }

        struct AllowDialer {
            dialed: Mutex<Vec<SocketAddr>>,
        }
        #[async_trait::async_trait]
        impl UpstreamDialer for AllowDialer {
            async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
                lock_unpoisoned(&self.dialed).push(addr);
                let (proxy_side, mut server_side) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = server_side.read(&mut buf).await {
                        if n > 0 {
                            let _ = server_side.write_all(&buf[..n]).await;
                        }
                    }
                    let _ = server_side.shutdown().await;
                });
                Ok(Box::pin(proxy_side))
            }
        }

        let tmp = TestTempDir::new("mgr-wp-checkout-egress");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let dialer = Arc::new(AllowDialer {
            dialed: Mutex::new(Vec::new()),
        });

        let tmpl = valid_spec(Duration::from_secs(60));
        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.warm_pool = WarmPoolConfig {
            target_size: 3,
            template_spec: Some(tmpl),
            ..Default::default()
        };

        let mgr = LocalRuntimeManager::with_egress_hooks(
            cfg,
            overlay,
            vm.clone(),
            Arc::new(AllowDns),
            dialer.clone(),
        )
        .unwrap();

        assert_eq!(mgr.warm_up().await.unwrap(), 3);

        // 1. Checkout for Isolated network (with distinct lease_ttl): reuses warm VM #0 without egress.
        let iso_lease = mgr.spawn(valid_spec(Duration::from_secs(120))).await.unwrap();
        assert_eq!(iso_lease.capabilities.egress_filter, EnforcementLevel::HardLimit);
        assert_eq!(mgr.warm_pool_stats().total_checkouts, 1);
        assert_eq!(mgr.warm_pool_stats().total_cold_spawns, 0);
        assert_eq!(
            mgr.journal.load_record(&iso_lease.id).unwrap().unwrap().state,
            JournalLifecycleState::Active
        );
        {
            let st = lock_unpoisoned(&vm.state);
            assert_eq!(*lock_unpoisoned(&st.sessions[0].egress_enabled_port), None);
        }

        // 2. Checkout for DomainAllowList: dynamically calls enable_egress_proxy(3128) and wires HostEgressProxy!
        let mut allow_spec = valid_spec(Duration::from_secs(45));
        allow_spec.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "api.example.com".to_owned(),
                port: 443,
            }],
        };
        let net_lease = mgr.spawn(allow_spec.clone()).await.unwrap();
        assert_eq!(net_lease.capabilities.egress_filter, EnforcementLevel::HardLimit);
        assert_eq!(mgr.warm_pool_stats().total_checkouts, 2);
        assert_eq!(mgr.warm_pool_stats().total_cold_spawns, 0);

        let egress_tx = {
            let st = lock_unpoisoned(&vm.state);
            assert_eq!(
                *lock_unpoisoned(&st.sessions[1].egress_enabled_port),
                Some(3128)
            );
            let tx = lock_unpoisoned(&st.sessions[1].egress_tx).clone().unwrap();
            tx
        };

        let (stream_ok, mut handle_ok) = TunnelStream::channel(StreamId(20));
        egress_tx.send(stream_ok).await.unwrap();
        handle_ok
            .write_half
            .write_all(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 64];
        let n = handle_ok.read_half.read(&mut head).await.unwrap();
        assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200 Connection Established"));
        handle_ok.write_half.write_all(b"hi").await.unwrap();
        handle_ok.write_half.shutdown().await.unwrap();
        let mut echo = Vec::new();
        handle_ok.read_half.read_to_end(&mut echo).await.unwrap();
        assert_eq!(echo, b"hi");

        let (stream_deny, mut handle_deny) = TunnelStream::channel(StreamId(21));
        egress_tx.send(stream_deny).await.unwrap();
        handle_deny
            .write_half
            .write_all(b"CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n")
            .await
            .unwrap();
        handle_deny.write_half.shutdown().await.unwrap();
        let mut deny_resp = Vec::new();
        handle_deny.read_half.read_to_end(&mut deny_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&deny_resp).starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(lock_unpoisoned(&dialer.dialed).len(), 1);

        // 3. Flaky warm VM failing enable_egress_proxy(3128) is disposed one-way as dirty and falls back cleanly.
        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions[2]
                .fail_enable_egress
                .store(true, Ordering::Release);
        }
        let fallback_lease = mgr.spawn(allow_spec).await.unwrap();
        let stats = mgr.warm_pool_stats();
        assert_eq!(stats.ready_vms, 0);
        assert_eq!(stats.total_checkouts, 2);
        assert_eq!(stats.total_disposed_dirty, 1);
        assert_eq!(stats.total_cold_spawns, 1);

        mgr.destroy(&iso_lease.id).await.unwrap();
        mgr.destroy(&net_lease.id).await.unwrap();
        mgr.destroy(&fallback_lease.id).await.unwrap();
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
        assert!(mgr.journal.load_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn warm_pool_strict_one_way_disposal_never_recycles_used_vms() {
        let tmp = TestTempDir::new("mgr-wp-oneway");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.warm_pool = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(valid_spec(Duration::from_secs(60))),
            ..Default::default()
        };
        let mgr = LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap();

        assert_eq!(mgr.warm_up().await.unwrap(), 1);
        let lease1 = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert_eq!(mgr.warm_pool_stats().total_checkouts, 1);
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);

        let stream = mgr
            .exec_stream(
                &lease1.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["id".into()],
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
        assert_eq!(stream.collect().await.unwrap().exit.code, Some(0));

        assert_eq!(
            mgr.destroy(&lease1.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        // Second idempotent destroy must NOT double-increment total_disposed_dirty.
        assert_eq!(
            mgr.destroy(&lease1.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );

        let stats = mgr.warm_pool_stats();
        assert_eq!(stats.ready_vms, 0);
        assert_eq!(stats.total_disposed_dirty, 1);
        assert!(!lock_unpoisoned(&vm.state).sessions[0]
            .alive
            .load(Ordering::Acquire));

        // Subsequent spawn cannot reuse the destroyed VM; it must cold-spawn a fresh one.
        let lease2 = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert_ne!(lease2.id, lease1.id);
        assert_eq!(mgr.warm_pool_stats().total_cold_spawns, 1);
        mgr.destroy(&lease2.id).await.unwrap();
        assert_eq!(mgr.warm_pool_stats().total_disposed_dirty, 2);

        // If an idle warm VM dies before checkout, spawn evicts it cleanly and falls back to cold boot.
        assert_eq!(mgr.warm_up().await.unwrap(), 1);
        {
            let st = lock_unpoisoned(&vm.state);
            st.sessions.last().unwrap().alive.store(false, Ordering::Release);
        }
        let lease3 = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        let stats_after = mgr.warm_pool_stats();
        assert_eq!(stats_after.total_evictions, 1);
        assert_eq!(stats_after.total_cold_spawns, 2);
        assert_eq!(stats_after.ready_vms, 0);
        mgr.destroy(&lease3.id).await.unwrap();
        assert!(mgr.journal.load_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn warm_pool_evicts_idle_vms_for_mismatched_spec_under_tight_admission() {
        let tmp = TestTempDir::new("mgr-wp-evict");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));

        let mut tmpl = valid_spec(Duration::from_secs(60));
        tmpl.budget.guest_ram_mb = 128;
        tmpl.budget.host_rss_budget_mb = Some(256);
        tmpl.budget.host_storage_budget_mb = 512;
        tmpl.budget.virtual_disk_mb = 256;

        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.admission = AdmissionLimits {
            max_concurrent_sandboxes: Some(2),
            max_total_host_rss_mb: Some(512),
            ..Default::default()
        };
        cfg.warm_pool = WarmPoolConfig {
            target_size: 2,
            template_spec: Some(tmpl),
            ..Default::default()
        };
        let mgr = LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap();
        assert_eq!(mgr.warm_up().await.unwrap(), 2);

        // Request exceeding single-sandbox cap (600 > 512) rejects immediately WITHOUT evicting pool.
        let mut impossible = valid_spec(Duration::from_secs(30));
        impossible.budget.guest_ram_mb = 512;
        impossible.budget.host_rss_budget_mb = Some(600);
        assert!(matches!(
            mgr.spawn(impossible).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        assert_eq!(mgr.warm_pool_stats().ready_vms, 2);
        assert_eq!(mgr.warm_pool_stats().total_evictions, 0);

        // Mismatched spec needing 384 MiB evicts both 256 MiB warm VMs so admission succeeds.
        let mut mismatched = valid_spec(Duration::from_secs(30));
        mismatched.budget.guest_ram_mb = 384;
        mismatched.budget.host_rss_budget_mb = Some(384);
        let lease = mgr.spawn(mismatched).await.unwrap();

        let stats = mgr.warm_pool_stats();
        assert_eq!(stats.ready_vms, 0);
        assert_eq!(stats.total_evictions, 2);
        assert_eq!(stats.total_cold_spawns, 1);
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 1);

        mgr.destroy(&lease.id).await.unwrap();
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
    }

    #[tokio::test]
    async fn warm_pool_overload_burst_prioritizes_foreground_waiters_and_never_breaches_rss() {
        let tmp = TestTempDir::new("mgr-wp-burst");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));

        let mut tmpl = valid_spec(Duration::from_secs(60));
        tmpl.budget.guest_ram_mb = 256;
        tmpl.budget.host_rss_budget_mb = Some(512);

        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.admission = AdmissionLimits {
            max_concurrent_sandboxes: Some(2),
            max_total_host_rss_mb: Some(1024),
            admission_queue_timeout: Duration::from_secs(3),
            max_admission_queue_depth: 2,
            ..Default::default()
        };
        cfg.warm_pool = WarmPoolConfig {
            target_size: 2,
            template_spec: Some(tmpl.clone()),
            max_idle_age: Duration::from_secs(60),
            replenish_retry_delay: Duration::from_millis(10),
        };

        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm).unwrap());
        let _replenisher = mgr.spawn_warm_pool_replenisher();

        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.warm_pool_stats().ready_vms < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("initial warm pool fill");

        // Burst 5 concurrent spawns: 2 warm checkouts, 2 queued waiters, 1 immediate queue-depth reject.
        let l1 = mgr.spawn(tmpl.clone()).await.unwrap();
        let l2 = mgr.spawn(tmpl.clone()).await.unwrap();
        assert_eq!(mgr.warm_pool_stats().total_checkouts, 2);
        assert!(mgr.current_admission_usage().effective_host_rss_mb <= 1024);

        let m_w1 = Arc::clone(&mgr);
        let s_w1 = tmpl.clone();
        let w1 = tokio::spawn(async move { m_w1.spawn(s_w1).await });
        tokio::task::yield_now().await;

        let m_w2 = Arc::clone(&mgr);
        let s_w2 = tmpl.clone();
        let w2 = tokio::spawn(async move { m_w2.spawn(s_w2).await });
        tokio::task::yield_now().await;

        // 5th concurrent caller exceeds max_admission_queue_depth (2).
        assert!(matches!(
            mgr.spawn(tmpl).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        assert!(mgr.admission.has_waiters());
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
        assert_eq!(mgr.warm_pool_stats().replenishing_vms, 0);

        // Destroying active leases must grant capacity to foreground waiters BEFORE replenisher re-warms!
        mgr.destroy(&l1.id).await.unwrap();
        mgr.destroy(&l2.id).await.unwrap();

        let l3 = w1.await.unwrap().unwrap();
        let l4 = w2.await.unwrap().unwrap();
        assert_eq!(mgr.warm_pool_stats().total_cold_spawns, 2);
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
        assert!(mgr.current_admission_usage().effective_host_rss_mb <= 1024);

        // Once foreground waiters finish and active leases drain, replenisher refills back to target_size.
        mgr.destroy(&l3.id).await.unwrap();
        mgr.destroy(&l4.id).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.warm_pool_stats().ready_vms < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("replenisher must refill after foreground load drains");

        assert_eq!(mgr.drain_warm_pool().await.unwrap(), 2);
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
    }

    #[tokio::test]
    async fn warm_pool_rotates_max_idle_age_drains_cleanly_and_aborts_on_drop() {
        let tmp = TestTempDir::new("mgr-wp-rotate-drain");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().to_path_buf());
        cfg.warm_pool = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(valid_spec(Duration::from_secs(60))),
            max_idle_age: Duration::from_millis(45),
            replenish_retry_delay: Duration::from_millis(10),
        };

        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap());
        let replenisher = mgr.spawn_warm_pool_replenisher();

        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.warm_pool_stats().ready_vms < 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("initial warm boot");

        // Wait past max_idle_age so the background ticker rotates the stale warm VM.
        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.warm_pool_stats().total_evictions < 1 || mgr.warm_pool_stats().ready_vms < 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("max_idle_age rotation");

        {
            let st = lock_unpoisoned(&vm.state);
            assert!(st.sessions.len() >= 2);
            assert!(!st.sessions[0].alive.load(Ordering::Acquire));
            assert!(st.sessions.last().unwrap().alive.load(Ordering::Acquire));
        }

        // drain_warm_pool stops replenisher and destroys all idle warm VMs cleanly.
        let drained = mgr.drain_warm_pool().await.unwrap();
        assert_eq!(drained, 1);
        assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
        assert_eq!(mgr.warm_pool_stats().replenishing_vms, 0);
        assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
        assert!(mgr.journal.load_records().unwrap().is_empty());
        tokio::time::timeout(Duration::from_millis(200), replenisher)
            .await
            .expect("replenisher exits on drain")
            .expect("replenisher joins cleanly");

        // Dropping Arc<LocalRuntimeManager> aborts a newly spawned replenisher cleanly.
        let replenisher2 = mgr.spawn_warm_pool_replenisher();
        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.warm_pool_stats().ready_vms < 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("re-warm after drain");

        drop(mgr);
        let join_res = tokio::time::timeout(Duration::from_millis(200), replenisher2)
            .await
            .expect("replenisher aborts promptly on manager drop");
        assert!(join_res.is_err());
    }

    #[tokio::test]
    async fn startup_reconciler_reaps_crashed_warm_journals_and_skips_live_warm_vms() {
        let tmp = TestTempDir::new("mgr-wp-reconcile");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(state_dir.clone());
        cfg.warm_pool = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(valid_spec(Duration::from_secs(60))),
            ..Default::default()
        };

        let mgr = LocalRuntimeManager::new(cfg, overlay.clone(), vm.clone()).unwrap();
        assert_eq!(mgr.warm_up().await.unwrap(), 1);

        // Simulate a crash-leftover Warm journal record from a dead daemon instance.
        let orphan_work = state_dir.join("sandboxes").join("mp-warm-orphan");
        fs::create_dir_all(&orphan_work).unwrap();
        let orphan_overlay = orphan_work.join("overlay.qcow2");
        fs::write(&orphan_overlay, b"warm-q").unwrap();
        {
            let mut st = lock_unpoisoned(&vm.state);
            st.live_orphans.insert((5555, 6666));
        }
        mgr.journal
            .write_record(&JournalRecord {
                sandbox_id: SandboxId::new("mp-warm-orphan"),
                state: JournalLifecycleState::Warm,
                pid: Some(5555),
                start_token: Some(6666),
                artifact_paths: vec![orphan_overlay.clone(), orphan_work.clone()],
                expires_at_unix_ms: 999,
            })
            .unwrap();

        let report = mgr.reconcile_startup().await.unwrap();
        assert_eq!(
            report,
            ReconciliationReport {
                records_seen: 1,
                orphans_killed: 1,
                cleaned: 1,
                remaining: 0,
                corrupt_files: 0,
            }
        );
        assert!(!orphan_work.exists());
        assert!(overlay.removed_paths().contains(&orphan_overlay));

        // Live warm VM must remain untouched and immediately available for checkout.
        assert_eq!(mgr.warm_pool_stats().ready_vms, 1);
        let lease = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        assert_eq!(mgr.warm_pool_stats().total_checkouts, 1);
        mgr.destroy(&lease.id).await.unwrap();
    }

    #[tokio::test]
    async fn copy_in_out_tar_bytes_and_active_helpers_validate_tar_and_track_sandboxes() {
        let tmp = TestTempDir::new("mgr-tar-bytes");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(base_config(state_dir), overlay, vm.clone()).unwrap();

        let mut spec = valid_spec(Duration::from_secs(60));
        spec.network = NetworkPolicy::InternetOnly;
        let lease = mgr.spawn(spec).await.unwrap();
        assert_eq!(mgr.active_sandbox_ids(), vec![lease.id.clone()]);
        assert_eq!(
            mgr.active_sandbox_network(&lease.id).unwrap(),
            NetworkPolicy::InternetOnly
        );

        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("hello.txt"), b"tar-bytes-ok").unwrap();
        let valid_tar = pack_host_path_to_tar(&src_dir, 64 * 1024).unwrap();

        mgr.copy_in_tar_bytes(&lease.id, "/workspace".to_owned(), valid_tar.clone())
            .await
            .unwrap();
        {
            let st = lock_unpoisoned(&vm.state);
            let sess = st.sessions.last().unwrap();
            assert_eq!(
                *lock_unpoisoned(&sess.copied_in),
                vec![("/workspace".to_owned(), valid_tar.clone())]
            );
            *lock_unpoisoned(&sess.copy_out_archive) = valid_tar.clone();
        }
        let out_tar = mgr
            .copy_out_tar_bytes(&lease.id, "/workspace".to_owned())
            .await
            .unwrap();
        assert_eq!(out_tar, valid_tar);

        // Malicious traversal tar must be rejected BEFORE forwarding to session.
        let mut evil_header = tar::Header::new_gnu();
        evil_header.set_entry_type(tar::EntryType::Symlink);
        evil_header.set_size(0);
        evil_header.set_mode(0o777);
        let raw_hdr = evil_header.as_mut_bytes();
        raw_hdr[..3].copy_from_slice(b"sym");
        raw_hdr[157..168].copy_from_slice(b"/etc/passwd");
        evil_header.set_cksum();
        let mut evil_tar = evil_header.as_bytes().to_vec();
        evil_tar.resize(evil_tar.len() + 1024, 0);

        let sessions_before = lock_unpoisoned(&vm.state).sessions.len();
        assert_eq!(sessions_before, 1);
        assert!(matches!(
            mgr.copy_in_tar_bytes(&lease.id, "/workspace".to_owned(), evil_tar.clone())
                .await,
            Err(SandboxError::PolicyViolation(_))
        ));
        // Only the 1 valid archive was forwarded to the mock VM session.
        let copied_count = {
            let st = lock_unpoisoned(&vm.state);
            let sess = st.sessions.last().unwrap();
            let count = lock_unpoisoned(&sess.copied_in).len();
            count
        };
        assert_eq!(copied_count, 1);

        // Compromised guest returning malicious symlink tar on copy_out must also be rejected.
        {
            let st = lock_unpoisoned(&vm.state);
            let sess = st.sessions.last().unwrap();
            *lock_unpoisoned(&sess.copy_out_archive) = evil_tar;
        }
        assert!(matches!(
            mgr.copy_out_tar_bytes(&lease.id, "/workspace".to_owned())
                .await,
            Err(SandboxError::PolicyViolation(_))
        ));

        mgr.destroy(&lease.id).await.unwrap();
        assert!(mgr.active_sandbox_ids().is_empty());
        assert!(matches!(
            mgr.active_sandbox_network(&lease.id),
            Err(SandboxError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn spawn_anchors_lease_ttl_after_boot_completes() {
        let tmp = TestTempDir::new("mgr-post-boot-ttl");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        lock_unpoisoned(&vm.state).boot_delay = Some(Duration::from_millis(90));
        let mgr = LocalRuntimeManager::new(base_config(tmp.path().to_path_buf()), overlay, vm)
            .unwrap();

        // Boot takes ~90ms (> 60ms TTL). Lease TTL must begin after boot finishes so the caller
        // receives a live lease rather than an already-expired one.
        let lease = mgr.spawn(valid_spec(Duration::from_millis(60))).await.unwrap();
        mgr.renew_lease(&lease.id, Duration::from_millis(120))
            .await
            .expect("lease must not be pre-expired by VM boot latency");
        mgr.destroy(&lease.id).await.unwrap();
    }

    #[tokio::test]
    async fn second_runtime_on_same_state_dir_is_rejected_before_reconciliation() {
        let tmp = TestTempDir::new("mgr-state-lock");
        let state_dir = tmp.path().join("state");
        let overlay1 = Arc::new(MockOverlayStore::default());
        let vm1 = Arc::new(MockVmRuntime::new(true));
        let mgr1 = LocalRuntimeManager::new(
            base_config(state_dir.clone()),
            overlay1,
            vm1.clone(),
        )
        .expect("first runtime acquires state.lock");

        let lease = mgr1
            .spawn(valid_spec(Duration::from_secs(60)))
            .await
            .expect("spawn sandbox on first runtime");

        let overlay2 = Arc::new(MockOverlayStore::default());
        let vm2 = Arc::new(MockVmRuntime::new(true));
        let second_err = match LocalRuntimeManager::new(
            base_config(state_dir.clone()),
            overlay2.clone(),
            vm2.clone(),
        ) {
            Ok(_) => panic!("second runtime sharing state_dir must be rejected"),
            Err(err) => err,
        };
        assert!(
            matches!(second_err, SandboxError::PolicyViolation(_)),
            "expected PolicyViolation on locked state_dir, got {second_err:?}"
        );

        // First runtime's VM and journal must remain untouched and fully executable.
        let out = mgr1
            .exec_stream(
                &lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["echo".into(), "alive".into()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(5),
                    stdout_budget_bytes: 1024,
                    stderr_budget_bytes: 1024,
                },
            )
            .await
            .expect("first runtime sandbox still active")
            .collect()
            .await
            .expect("collect exec output");
        assert_eq!(out.stdout, b"ran:echo alive");

        mgr1.destroy(&lease.id).await.unwrap();
        drop(mgr1);

        // Once the first runtime drops, state.lock is released and a new runtime can initialize.
        let mgr2 = LocalRuntimeManager::new(base_config(state_dir), overlay2, vm2)
            .expect("new runtime succeeds after previous owner drops");
        assert_eq!(mgr2.reconcile_startup().await.unwrap().records_seen, 0);
    }

    #[tokio::test]
    async fn dropping_manager_with_live_active_and_warm_leases_drops_all_sessions() {
        let tmp = TestTempDir::new("mgr-arc-drop");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));

        let mgr = LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap();
        assert_eq!(mgr.warm_up().await.unwrap(), 1);

        let mut custom = valid_spec(Duration::from_secs(60));
        custom.budget.guest_vcpus = 2; // Force cold spawn alongside the warm VM.
        let _active_lease = mgr.spawn(custom).await.unwrap();

        let sessions: Vec<Arc<MockSessionState>> = lock_unpoisoned(&vm.state).sessions.clone();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|s| s.dropped_count.load(Ordering::Acquire) == 0));

        // Dropping the manager without calling destroy() must break all Admission/RSS Arc references
        // and immediately run Drop on both the active and warm sessions.
        drop(mgr);

        for (idx, sess) in sessions.iter().enumerate() {
            assert_eq!(
                sess.dropped_count.load(Ordering::Acquire),
                1,
                "session {idx} leaked across LocalRuntimeManager::drop"
            );
        }
    }

    #[tokio::test]
    async fn pre_handshake_boot_crash_persists_pid_and_external_artifacts_for_reconciler() {
        let tmp = TestTempDir::new("mgr-pre-handshake-crash");
        let state_dir = tmp.path().join("state");
        let ext_ipc_dir = tmp.path().join("ext-ipc");
        fs::create_dir_all(&ext_ipc_dir).unwrap();
        let ext_ipc_sock = ext_ipc_dir.join("a.sock");

        let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();
        let overlay1 = Arc::new(MockOverlayStore::default());
        let vm1 = Arc::new(MockVmRuntime::new(true));
        lock_unpoisoned(&vm1.state).pre_handshake_stall = Some((ext_ipc_sock.clone(), spawned_tx));

        let mgr1 = Arc::new(
            LocalRuntimeManager::new(base_config(state_dir.clone()), overlay1, vm1).unwrap(),
        );
        let mgr1_spawn = Arc::clone(&mgr1);
        let spawn_task = tokio::spawn(async move {
            mgr1_spawn.spawn(valid_spec(Duration::from_secs(60))).await
        });

        let (orphan_pid, orphan_token) = spawned_rx
            .await
            .expect("receive pre-handshake spawned identity");

        // Simulate abrupt daemon death (SIGKILL) mid-boot before handshake completes.
        spawn_task.abort();
        let _ = spawn_task.await;
        drop(mgr1);

        // Journal on disk must already hold the spawned PID, start_token, and external IPC path.
        let records = JournalStore::new(state_dir.join("journals"))
            .unwrap()
            .load_records()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pid, Some(orphan_pid));
        assert_eq!(records[0].start_token, Some(orphan_token));
        assert!(records[0].artifact_paths.contains(&ext_ipc_sock));

        // Next daemon startup reconciles the pre-handshake orphan and removes external IPC artifact.
        let overlay2 = Arc::new(MockOverlayStore::default());
        let vm2 = Arc::new(MockVmRuntime::new(true));
        lock_unpoisoned(&vm2.state)
            .live_orphans
            .insert((orphan_pid, orphan_token));
        let mgr2 = LocalRuntimeManager::new(base_config(state_dir), overlay2, vm2.clone()).unwrap();
        let report = mgr2.reconcile_startup().await.unwrap();
        assert_eq!(report.records_seen, 1);
        assert_eq!(report.orphans_killed, 1);
        assert_eq!(report.cleaned, 1);
        assert_eq!(report.remaining, 0);
        assert!(!ext_ipc_sock.exists());
    }

    #[tokio::test]
    async fn list_active_sandboxes_returns_sorted_live_metadata_and_clears_on_destroy() {
        let tmp = TestTempDir::new("mgr-list-active");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(base_config(tmp.path().join("state")), overlay, vm)
            .unwrap();

        assert!(mgr.list_active_sandboxes().is_empty());

        let mut spec_a = valid_spec(Duration::from_secs(120));
        spec_a.network = NetworkPolicy::Isolated;
        let lease_a = mgr.spawn(spec_a).await.unwrap();

        let mut spec_b = valid_spec(Duration::from_secs(300));
        spec_b.network = NetworkPolicy::InternetOnly;
        spec_b.budget.host_rss_budget_mb = Some(768);
        spec_b.budget.host_storage_budget_mb = 2048;
        let lease_b = mgr.spawn(spec_b).await.unwrap();

        let listed = mgr.list_active_sandboxes();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].id.as_str() < listed[1].id.as_str());

        let found_b = listed.iter().find(|s| s.id == lease_b.id).unwrap();
        assert!(found_b.alive);
        assert!(found_b.pid > 0);
        assert_eq!(found_b.network, NetworkPolicy::InternetOnly);
        assert!(found_b.remaining_ttl_ms > 200_000);
        assert_eq!(found_b.host_rss_budget_mb, Some(768));
        assert_eq!(found_b.host_storage_budget_mb, 2048);

        mgr.destroy(&lease_a.id).await.unwrap();
        let remaining = mgr.list_active_sandboxes();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, lease_b.id);
    }

    #[tokio::test]
    async fn concurrent_renew_lease_and_destroy_keep_journal_consistent_and_never_resurrect() {
        let tmp = TestTempDir::new("mgr-renew-destroy-race");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = Arc::new(
            LocalRuntimeManager::new(base_config(state_dir.clone()), overlay, vm).unwrap(),
        );
        let journals = JournalStore::new(state_dir.join("journals")).unwrap();

        // Part 1: Two concurrent renewals with distinct TTLs must leave on-disk journal consistent
        // with the final in-memory expiry (never scrambling writes or colliding on `.tmp`).
        let lease = mgr.spawn(valid_spec(Duration::from_secs(30))).await.unwrap();
        let m1 = Arc::clone(&mgr);
        let m2 = Arc::clone(&mgr);
        let id1 = lease.id.clone();
        let id2 = lease.id.clone();
        let (r1, r2) = tokio::join!(
            m1.renew_lease(&id1, Duration::from_secs(60)),
            m2.renew_lease(&id2, Duration::from_secs(600))
        );
        r1.unwrap();
        r2.unwrap();

        let disk_rec = journals
            .load_record(&lease.id)
            .unwrap()
            .expect("journal present after concurrent renewals");
        let mem_remaining_ms = mgr
            .list_active_sandboxes()
            .into_iter()
            .find(|s| s.id == lease.id)
            .expect("active sandbox summary")
            .remaining_ttl_ms;
        let disk_remaining_ms = disk_rec.expires_at_unix_ms.saturating_sub(unix_now_ms());
        assert!(
            mem_remaining_ms.abs_diff(disk_remaining_ms) < 5_000,
            "in-memory TTL ({mem_remaining_ms} ms) diverged from on-disk journal ({disk_remaining_ms} ms)"
        );
        mgr.destroy(&lease.id).await.unwrap();
        assert!(journals.load_record(&lease.id).unwrap().is_none());

        // Part 2: Concurrent `renew_lease` + `destroy` must never resurrect `<id>.journal` on disk.
        for _ in 0..16 {
            let raced = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
            let mr = Arc::clone(&mgr);
            let md = Arc::clone(&mgr);
            let id_r = raced.id.clone();
            let id_d = raced.id.clone();
            let (_renew_res, destroy_res) = tokio::join!(
                mr.renew_lease(&id_r, Duration::from_secs(120)),
                md.destroy(&id_d)
            );
            assert_eq!(destroy_res.unwrap(), DestroyStatus::AllResourcesCleaned);
            assert!(
                journals.load_record(&raced.id).unwrap().is_none(),
                "destroy raced with renew_lease and resurrected journal for {}",
                raced.id
            );
        }
        assert!(
            lock_unpoisoned(&mgr.lifecycle_locks).is_empty(),
            "per-sandbox lifecycle locks must prune themselves on drop"
        );
    }

    #[tokio::test]
    async fn destroy_ignores_unleased_warm_pool_and_in_flight_spawning_sandboxes() {
        let tmp = TestTempDir::new("mgr-destroy-unleased-guard");
        let state_dir = tmp.path().join("state");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));

        let mut cfg = base_config(state_dir.clone());
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm.clone()).unwrap());

        assert_eq!(mgr.warm_up().await.unwrap(), 1);
        let journals = JournalStore::new(state_dir.join("journals")).unwrap();
        let warm_records = journals.load_records().unwrap();
        assert_eq!(warm_records.len(), 1);
        let warm_id = warm_records[0].sandbox_id.clone();

        // Calling destroy on an unleased Warm Pool ID must NOT kill the warm VM via its `.journal`.
        assert_eq!(
            mgr.destroy(&warm_id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        assert_eq!(mgr.warm_pool_stats().ready_vms, 1);
        assert!(journals.load_record(&warm_id).unwrap().is_some());

        // Likewise, calling destroy on a pre-handshake cold-spawning ID must NOT reap it mid-boot.
        let ext_ipc = tmp.path().join("spawn.sock");
        let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();
        lock_unpoisoned(&vm.state).pre_handshake_stall = Some((ext_ipc, spawned_tx));

        let mgr_spawn = Arc::clone(&mgr);
        let spawn_task = tokio::spawn(async move {
            let mut cold_spec = valid_spec(Duration::from_secs(60));
            cold_spec.budget.guest_vcpus = 2;
            mgr_spawn.spawn(cold_spec).await
        });
        let (spawning_pid, _) = spawned_rx.await.unwrap();
        let spawning_id = journals
            .load_records()
            .unwrap()
            .into_iter()
            .find(|r| r.pid == Some(spawning_pid))
            .expect("spawning journal")
            .sandbox_id;

        assert_eq!(
            mgr.destroy(&spawning_id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        assert!(
            journals.load_record(&spawning_id).unwrap().is_some(),
            "in-flight cold spawn journal must remain intact while spawn is still running"
        );
        spawn_task.abort();
        let _ = spawn_task.await;
    }

    #[tokio::test]
    async fn reconcile_startup_isolates_corrupt_journal_and_destroy_listener_runs_after_removal() {
        let tmp = TestTempDir::new("mgr-reconcile-corrupt-and-listener");
        let state_dir = tmp.path().join("state");
        let orphan_dir = tmp.path().join("orphan-work");
        fs::create_dir_all(&orphan_dir).unwrap();

        let journals = JournalStore::new(state_dir.join("journals")).unwrap();
        journals
            .write_record(&JournalRecord {
                sandbox_id: SandboxId::new("valid-orphan"),
                state: JournalLifecycleState::Active,
                pid: Some(77_001),
                start_token: Some(88_002),
                artifact_paths: vec![orphan_dir.clone()],
                expires_at_unix_ms: 1,
            })
            .unwrap();
        fs::write(
            journals.root_dir().join("broken.journal"),
            b"corrupt-non-kv-content\n",
        )
        .unwrap();

        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        lock_unpoisoned(&vm.state)
            .live_orphans
            .insert((77_001, 88_002));

        let mgr = Arc::new(LocalRuntimeManager::new(base_config(state_dir), overlay, vm).unwrap());
        let report = mgr.reconcile_startup().await.unwrap();
        assert_eq!(report.records_seen, 2);
        assert_eq!(report.orphans_killed, 1);
        assert_eq!(report.cleaned, 1);
        assert_eq!(report.remaining, 1);
        assert!(!orphan_dir.exists());
        assert!(journals.root_dir().join("broken.journal").exists());

        // Verify destroy listeners observe `active_sandbox_network(id) == Err(...)`.
        let mgr_weak = Arc::downgrade(&mgr);
        let saw_still_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_clone = Arc::clone(&saw_still_active);
        mgr.register_destroy_listener(move |destroyed_id| {
            if let Some(m) = mgr_weak.upgrade() {
                if m.active_sandbox_network(destroyed_id).is_ok() {
                    saw_clone.store(true, Ordering::Release);
                }
            }
        });

        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
        mgr.destroy(&lease.id).await.unwrap();
        assert!(
            !saw_still_active.load(Ordering::Acquire),
            "destroy listener ran before sandbox was removed from active map"
        );
    }

    #[tokio::test]
    async fn bundle_read_guard_stays_locked_across_warm_and_active_vm_lifetime_until_destroy() {
        struct GuardedOverlayStore {
            lock_path: PathBuf,
        }

        #[async_trait::async_trait]
        impl DiskOverlayPort for GuardedOverlayStore {
            async fn prepare_overlay(
                &self,
                _sandbox_id: &SandboxId,
                spec: &SandboxSpec,
                work_dir: &Path,
            ) -> Result<PreparedOverlay, SandboxError> {
                let overlay_path = work_dir.join("overlay.qcow2");
                fs::write(&overlay_path, b"qcow2").unwrap();
                let lock_file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&self.lock_path)
                    .unwrap();
                lock_file.lock_shared().unwrap();
                Ok(PreparedOverlay {
                    overlay_path,
                    kernel_path: PathBuf::from("/bundle/vmlinuz"),
                    initramfs_path: PathBuf::from("/bundle/initrd"),
                    rootfs_path: PathBuf::from("/bundle/rootfs.qcow2"),
                    kernel_cmdline: "quiet".to_owned(),
                    guest_arch: None,
                    virtual_disk_mb: spec.budget.virtual_disk_mb,
                    provisioned_host_bytes: 5,
                    bundle_guard: Some(BundleReadGuard::new(lock_file)),
                })
            }

            async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
                if overlay_path.exists() {
                    let _ = fs::remove_file(overlay_path);
                }
                Ok(())
            }
        }

        let tmp = TestTempDir::new("mgr-bundle-read-guard");
        let lock_path = tmp.path().join(".lock-bundle");
        let overlay = Arc::new(GuardedOverlayStore {
            lock_path: lock_path.clone(),
        });
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));

        let mgr = LocalRuntimeManager::new(cfg, overlay, vm).unwrap();
        assert_eq!(mgr.warm_up().await.unwrap(), 1);

        let probe_exclusive = || -> bool {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .unwrap();
            f.try_lock().is_ok()
        };

        assert!(
            !probe_exclusive(),
            "shared bundle lock must stay held while VM sits in Warm Pool"
        );

        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
        assert!(
            !probe_exclusive(),
            "shared bundle lock must stay held while checked-out VM is active"
        );

        mgr.destroy(&lease.id).await.unwrap();
        assert!(
            probe_exclusive(),
            "shared bundle lock must be released once the VM is destroyed"
        );
    }

    #[tokio::test]
    async fn destroy_still_kills_vm_and_deletes_overlay_when_journal_is_unreadable_or_unwritable() {
        let tmp = TestTempDir::new("mgr-destroy-journal-resilient");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.cleanup_max_attempts = 1;
        cfg.cleanup_initial_delay = Duration::from_millis(1);
        let mgr = LocalRuntimeManager::new(cfg.clone(), overlay.clone(), vm.clone()).unwrap();

        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
        let journal_file = cfg.state_dir.join("journals").join(format!("{}.journal", lease.id.as_str()));
        assert!(journal_file.exists());
        fs::write(&journal_file, "corrupted-journal-data").unwrap();
        let status = mgr.destroy(&lease.id).await.unwrap();
        assert_eq!(status, DestroyStatus::AllResourcesCleaned);
        assert_eq!(mgr.list_active_sandboxes().len(), 0);
        assert!(!overlay.removed_paths().is_empty());
        assert!(!journal_file.exists());
    }

    #[tokio::test]
    async fn destroy_retains_active_slot_and_permit_if_force_kill_fails_while_alive() {
        struct UnkillableSession {
            alive: AtomicBool,
            pid: u32,
            artifacts: Vec<PathBuf>,
        }
        #[async_trait::async_trait]
        impl VmSessionPort for UnkillableSession {
            fn pid(&self) -> u32 {
                self.pid
            }
            fn start_token(&self) -> u64 {
                99
            }
            fn is_alive(&self) -> bool {
                self.alive.load(Ordering::Acquire)
            }
            fn artifact_paths(&self) -> &[PathBuf] {
                &self.artifacts
            }
            fn confirmed_exited(&self) -> Result<bool, SandboxError> {
                Ok(!self.is_alive())
            }
            fn current_rss_bytes(&self) -> Option<u64> {
                None
            }
            async fn graceful_shutdown(&self, _timeout: Duration) -> Result<bool, SandboxError> {
                Ok(false)
            }
            async fn force_kill(&self) -> Result<(), SandboxError> {
                if self.alive.load(Ordering::Acquire) {
                    Err(SandboxError::Transport("simulated EPERM on force_kill".to_owned()))
                } else {
                    Ok(())
                }
            }
            async fn exec_stream(&self, _req: ExecRequest) -> Result<ExecStream, SandboxError> {
                unreachable!()
            }
            async fn copy_in_tar(&self, _d: &str, _t: Vec<u8>, _m: u64) -> Result<u64, SandboxError> {
                unreachable!()
            }
            async fn copy_out_tar(&self, _s: &str, _m: u64) -> Result<Vec<u8>, SandboxError> {
                unreachable!()
            }
            async fn open_tunnel(&self, _t: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
                unreachable!()
            }
            async fn enable_egress_proxy(
                &self,
                _guest_port: u16,
            ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> {
                unreachable!()
            }
        }
        struct UnkillableVm {
            session: Arc<UnkillableSession>,
        }
        #[async_trait::async_trait]
        impl VmRuntimePort for UnkillableVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                if let Some(hook) = cfg.on_boot_progress {
                    let _ = hook(Some((self.session.pid, 99)), &[]);
                }
                struct SharedSession(Arc<UnkillableSession>);
                #[async_trait::async_trait]
                impl VmSessionPort for SharedSession {
                    fn pid(&self) -> u32 { self.0.pid() }
                    fn start_token(&self) -> u64 { self.0.start_token() }
                    fn is_alive(&self) -> bool { self.0.is_alive() }
                    fn artifact_paths(&self) -> &[PathBuf] { self.0.artifact_paths() }
                    fn confirmed_exited(&self) -> Result<bool, SandboxError> { self.0.confirmed_exited() }
                    fn current_rss_bytes(&self) -> Option<u64> { self.0.current_rss_bytes() }
                    async fn graceful_shutdown(&self, t: Duration) -> Result<bool, SandboxError> {
                        self.0.graceful_shutdown(t).await
                    }
                    async fn force_kill(&self) -> Result<(), SandboxError> {
                        self.0.force_kill().await
                    }
                    async fn exec_stream(&self, r: ExecRequest) -> Result<ExecStream, SandboxError> {
                        self.0.exec_stream(r).await
                    }
                    async fn copy_in_tar(&self, d: &str, t: Vec<u8>, m: u64) -> Result<u64, SandboxError> {
                        self.0.copy_in_tar(d, t, m).await
                    }
                    async fn copy_out_tar(&self, s: &str, m: u64) -> Result<Vec<u8>, SandboxError> {
                        self.0.copy_out_tar(s, m).await
                    }
                    async fn open_tunnel(&self, t: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
                        self.0.open_tunnel(t).await
                    }
                    async fn enable_egress_proxy(
                        &self,
                        p: u16,
                    ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> {
                        self.0.enable_egress_proxy(p).await
                    }
                }
                Ok(VmBootOutcome {
                    session: Box::new(SharedSession(Arc::clone(&self.session))),
                    pid: self.session.pid,
                    start_token: 99,
                    hardware_accelerated: false,
                    artifact_paths: vec![],
                    capabilities: CapabilityReport {
                        cpu_quota: EnforcementLevel::BestEffort,
                        host_rss: EnforcementLevel::BestEffort,
                        host_storage: EnforcementLevel::BestEffort,
                        egress_filter: EnforcementLevel::HardLimit,
                    },
                    egress_rx: None,
                })
            }
            async fn kill_orphan_process(&self, _pid: u32, _tok: u64) -> Result<bool, SandboxError> {
                Ok(true)
            }
        }

        let tmp = TestTempDir::new("mgr-destroy-kill-fail");
        let overlay = Arc::new(MockOverlayStore::default());
        let session = Arc::new(UnkillableSession {
            alive: AtomicBool::new(true),
            pid: 4444,
            artifacts: vec![],
        });
        let vm = Arc::new(UnkillableVm {
            session: Arc::clone(&session),
        });
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.admission.max_concurrent_sandboxes = Some(1);
        let mgr = LocalRuntimeManager::new(cfg, overlay.clone(), vm).unwrap();

        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
        // force_kill fails while alive: destroy must return Err and KEEP admission permit & active entry!
        assert!(mgr.destroy(&lease.id).await.is_err());
        assert_eq!(mgr.list_active_sandboxes().len(), 1);
        assert!(overlay.removed_paths().is_empty());

        // Once VM actually dies, retry of destroy cleans everything cleanly.
        session.alive.store(false, Ordering::Release);
        assert_eq!(
            mgr.destroy(&lease.id).await.unwrap(),
            DestroyStatus::AllResourcesCleaned
        );
        assert!(mgr.list_active_sandboxes().is_empty());
        assert!(!overlay.removed_paths().is_empty());
    }

    #[tokio::test]
    async fn warm_pool_eviction_and_drain_keep_transitioning_rss_accounted() {
        let tmp = TestTempDir::new("mgr-warm-evict-rss");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 2;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = LocalRuntimeManager::new(cfg, overlay, vm).unwrap();
        assert_eq!(mgr.warm_up().await.unwrap(), 2);

        let evicted = mgr.warm_pool.pop_one_for_eviction().unwrap();
        assert!(mgr.warm_pool.contains_live_id(&evicted.sandbox_id));
        let weak = mgr.warm_pool.downgrade();
        let mut samples = Vec::new();
        weak.collect_rss_samples(&mut samples);
        assert_eq!(samples.len(), 2);

        mgr.dispose_warm_entry(evicted).await;
        let mut samples_after = Vec::new();
        weak.collect_rss_samples(&mut samples_after);
        assert_eq!(samples_after.len(), 1);

        assert_eq!(mgr.drain_warm_pool().await.unwrap(), 1);
        let mut samples_final = Vec::new();
        weak.collect_rss_samples(&mut samples_final);
        assert!(samples_final.is_empty());
    }

    #[tokio::test]
    async fn cancelling_spawn_mid_boot_keeps_permit_until_cleanup_and_blocks_late_progress_hook() {
        let tmp = TestTempDir::new("mgr-cancel-spawn-mid-boot");
        let overlay = Arc::new(MockOverlayStore::default());
        let boot_entered = Arc::new(tokio::sync::Notify::new());
        let kill_entered = Arc::new(tokio::sync::Notify::new());
        let release_kill = Arc::new(tokio::sync::Notify::new());
        let release_late_hook = Arc::new(tokio::sync::Notify::new());
        let late_hook_err = Arc::new(AtomicBool::new(false));
        let orphan_killed = Arc::new(AtomicBool::new(false));

        struct BlockingBootVm {
            boot_entered: Arc<tokio::sync::Notify>,
            kill_entered: Arc<tokio::sync::Notify>,
            release_kill: Arc<tokio::sync::Notify>,
            release_late_hook: Arc<tokio::sync::Notify>,
            late_hook_err: Arc<AtomicBool>,
            orphan_killed: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl VmRuntimePort for BlockingBootVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                if let Some(ref hook) = cfg.on_boot_progress {
                    hook(Some((6666, 9999)), &[])?;
                    let hook_late = Arc::clone(hook);
                    let release_late_hook = Arc::clone(&self.release_late_hook);
                    let late_hook_err = Arc::clone(&self.late_hook_err);
                    tokio::spawn(async move {
                        release_late_hook.notified().await;
                        if hook_late(Some((7777, 8888)), &[]).is_err() {
                            late_hook_err.store(true, Ordering::Release);
                        }
                    });
                }
                self.boot_entered.notify_one();
                std::future::pending::<()>().await;
                unreachable!()
            }

            async fn kill_orphan_process(
                &self,
                _pid: u32,
                _expected_start_token: u64,
            ) -> Result<bool, SandboxError> {
                self.kill_entered.notify_one();
                self.release_kill.notified().await;
                self.orphan_killed.store(true, Ordering::Release);
                Ok(true)
            }
        }

        let vm = Arc::new(BlockingBootVm {
            boot_entered: Arc::clone(&boot_entered),
            kill_entered: Arc::clone(&kill_entered),
            release_kill: Arc::clone(&release_kill),
            release_late_hook: Arc::clone(&release_late_hook),
            late_hook_err: Arc::clone(&late_hook_err),
            orphan_killed: Arc::clone(&orphan_killed),
        });
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.admission.max_concurrent_sandboxes = Some(1);
        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay.clone(), vm).unwrap());

        let mgr_spawn = Arc::clone(&mgr);
        let handle = tokio::spawn(async move {
            mgr_spawn.spawn(valid_spec(Duration::from_secs(30))).await
        });
        boot_entered.notified().await;
        handle.abort();
        let _ = handle.await;

        kill_entered.notified().await;
        assert!(
            mgr.admission.try_acquire_background(&valid_spec(Duration::from_secs(30))).is_none(),
            "AdmissionPermit must stay held by cancellation cleanup until rollback finishes"
        );

        release_late_hook.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if late_hook_err.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late on_boot_progress after cancellation must fail");

        release_kill.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if orphan_killed.load(Ordering::Acquire)
                    && mgr.current_admission_usage().active_sandboxes == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled spawn rollback must finish and release admission");
        assert!(mgr.journal.load_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn aborting_warm_eviction_mid_loop_never_leaks_transitioning_or_rss() {
        struct SlowShutdownSession(Box<dyn VmSessionPort>);
        #[async_trait::async_trait]
        impl VmSessionPort for SlowShutdownSession {
            fn pid(&self) -> u32 { self.0.pid() }
            fn start_token(&self) -> u64 { self.0.start_token() }
            fn artifact_paths(&self) -> &[PathBuf] { self.0.artifact_paths() }
            fn is_alive(&self) -> bool { self.0.is_alive() }
            fn current_rss_bytes(&self) -> Option<u64> { self.0.current_rss_bytes() }
            async fn exec_stream(&self, r: ExecRequest) -> Result<ExecStream, SandboxError> {
                self.0.exec_stream(r).await
            }
            async fn open_tunnel(&self, t: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
                self.0.open_tunnel(t).await
            }
            async fn enable_egress_proxy(
                &self,
                p: u16,
            ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> {
                self.0.enable_egress_proxy(p).await
            }
            async fn copy_in_tar(&self, d: &str, t: Vec<u8>, m: u64) -> Result<u64, SandboxError> {
                self.0.copy_in_tar(d, t, m).await
            }
            async fn copy_out_tar(&self, s: &str, m: u64) -> Result<Vec<u8>, SandboxError> {
                self.0.copy_out_tar(s, m).await
            }
            async fn graceful_shutdown(&self, timeout: Duration) -> Result<bool, SandboxError> {
                tokio::time::sleep(Duration::from_millis(80)).await;
                self.0.graceful_shutdown(timeout).await
            }
            async fn force_kill(&self) -> Result<(), SandboxError> {
                self.0.force_kill().await
            }
        }
        struct SlowWarmVm(MockVmRuntime);
        #[async_trait::async_trait]
        impl VmRuntimePort for SlowWarmVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                let mut out = self.0.boot_vm(cfg).await?;
                out.session = Box::new(SlowShutdownSession(out.session));
                Ok(out)
            }
            async fn kill_orphan_process(&self, p: u32, t: u64) -> Result<bool, SandboxError> {
                self.0.kill_orphan_process(p, t).await
            }
        }

        let tmp = TestTempDir::new("mgr-warm-abort-evict");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(SlowWarmVm(MockVmRuntime::new(true)));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 2;
        cfg.warm_pool.max_idle_age = Duration::from_millis(10);
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm).unwrap());
        assert_eq!(mgr.warm_up().await.unwrap(), 2);

        tokio::time::sleep(Duration::from_millis(25)).await;
        let mgr_evict = Arc::clone(&mgr);
        let evict_task = tokio::spawn(async move { mgr_evict.evict_expired_warm_vms().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        evict_task.abort();
        let _ = evict_task.await;

        assert_eq!(mgr.drain_warm_pool().await.unwrap(), 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut samples = Vec::new();
                mgr.warm_pool.downgrade().collect_rss_samples(&mut samples);
                if samples.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transitioning warm entries must clear completely after abort");
    }

    #[tokio::test]
    async fn cancelling_destroy_mid_shutdown_completes_cleanup_and_warm_kill_failure_retains_permit() {
        struct GatedShutdownSession {
            inner: Box<dyn VmSessionPort>,
            shutdown_entered: Arc<tokio::sync::Notify>,
            release_shutdown: Arc<tokio::sync::Notify>,
        }
        #[async_trait::async_trait]
        impl VmSessionPort for GatedShutdownSession {
            fn pid(&self) -> u32 { self.inner.pid() }
            fn start_token(&self) -> u64 { self.inner.start_token() }
            fn artifact_paths(&self) -> &[PathBuf] { self.inner.artifact_paths() }
            fn is_alive(&self) -> bool { self.inner.is_alive() }
            fn current_rss_bytes(&self) -> Option<u64> { self.inner.current_rss_bytes() }
            async fn exec_stream(&self, r: ExecRequest) -> Result<ExecStream, SandboxError> {
                self.inner.exec_stream(r).await
            }
            async fn open_tunnel(&self, t: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
                self.inner.open_tunnel(t).await
            }
            async fn enable_egress_proxy(
                &self,
                p: u16,
            ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> {
                self.inner.enable_egress_proxy(p).await
            }
            async fn copy_in_tar(&self, d: &str, t: Vec<u8>, m: u64) -> Result<u64, SandboxError> {
                self.inner.copy_in_tar(d, t, m).await
            }
            async fn copy_out_tar(&self, s: &str, m: u64) -> Result<Vec<u8>, SandboxError> {
                self.inner.copy_out_tar(s, m).await
            }
            async fn graceful_shutdown(&self, timeout: Duration) -> Result<bool, SandboxError> {
                self.shutdown_entered.notify_one();
                self.release_shutdown.notified().await;
                self.inner.graceful_shutdown(timeout).await
            }
            async fn force_kill(&self) -> Result<(), SandboxError> {
                self.inner.force_kill().await
            }
        }
        struct GatedShutdownVm {
            inner: MockVmRuntime,
            shutdown_entered: Arc<tokio::sync::Notify>,
            release_shutdown: Arc<tokio::sync::Notify>,
            gate_next: AtomicBool,
        }
        #[async_trait::async_trait]
        impl VmRuntimePort for GatedShutdownVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                let mut out = self.inner.boot_vm(cfg).await?;
                if self.gate_next.swap(false, Ordering::AcqRel) {
                    out.session = Box::new(GatedShutdownSession {
                        inner: out.session,
                        shutdown_entered: Arc::clone(&self.shutdown_entered),
                        release_shutdown: Arc::clone(&self.release_shutdown),
                    });
                }
                Ok(out)
            }
            async fn kill_orphan_process(&self, p: u32, t: u64) -> Result<bool, SandboxError> {
                self.inner.kill_orphan_process(p, t).await
            }
        }

        let tmp = TestTempDir::new("mgr-cancel-destroy-and-warm-kill-fail");
        let overlay = Arc::new(MockOverlayStore::default());
        let shutdown_entered = Arc::new(tokio::sync::Notify::new());
        let release_shutdown = Arc::new(tokio::sync::Notify::new());
        let vm = Arc::new(GatedShutdownVm {
            inner: MockVmRuntime::new(true),
            shutdown_entered: Arc::clone(&shutdown_entered),
            release_shutdown: Arc::clone(&release_shutdown),
            gate_next: AtomicBool::new(true),
        });
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.admission.max_concurrent_sandboxes = Some(2);
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay.clone(), vm).unwrap());

        // 1. Cancel `destroy()` mid-shutdown: permit stays held while gated and teardown completes after release.
        let lease = mgr.spawn(valid_spec(Duration::from_secs(60))).await.unwrap();
        let mgr_destroy = Arc::clone(&mgr);
        let id = lease.id.clone();
        let destroy_task = tokio::spawn(async move { mgr_destroy.destroy(&id).await });
        shutdown_entered.notified().await;
        destroy_task.abort();
        let _ = destroy_task.await;
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 1);
        release_shutdown.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if mgr.list_active_sandboxes().is_empty()
                    && mgr.current_admission_usage().active_sandboxes == 0
                    && mgr.journal.load_records().unwrap().is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled destroy must finish teardown");

        // 2. Warm disposal where `force_kill` fails while VM is alive retains permit via `active`.
        struct LiveUnkillableWarm(AtomicBool);
        #[async_trait::async_trait]
        impl VmSessionPort for LiveUnkillableWarm {
            fn pid(&self) -> u32 { 9191 }
            fn start_token(&self) -> u64 { 9191 }
            fn artifact_paths(&self) -> &[PathBuf] { &[] }
            fn is_alive(&self) -> bool { self.0.load(Ordering::Acquire) }
            fn current_rss_bytes(&self) -> Option<u64> { None }
            async fn graceful_shutdown(&self, _: Duration) -> Result<bool, SandboxError> { Ok(false) }
            async fn force_kill(&self) -> Result<(), SandboxError> {
                Err(SandboxError::Transport("simulated EPERM".to_owned()))
            }
            async fn exec_stream(&self, _: ExecRequest) -> Result<ExecStream, SandboxError> { unreachable!() }
            async fn copy_in_tar(&self, _: &str, _: Vec<u8>, _: u64) -> Result<u64, SandboxError> { unreachable!() }
            async fn copy_out_tar(&self, _: &str, _: u64) -> Result<Vec<u8>, SandboxError> { unreachable!() }
            async fn open_tunnel(&self, _: StreamTargetWire) -> Result<TunnelStream, SandboxError> { unreachable!() }
            async fn enable_egress_proxy(&self, _: u16) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> { unreachable!() }
        }
        let mut live_entry = {
            assert_eq!(mgr.warm_up().await.unwrap(), 1);
            mgr.warm_pool.pop_one_for_eviction().unwrap()
        };
        let live_id = live_entry.sandbox_id.clone();
        let live_sess = Arc::new(LiveUnkillableWarm(AtomicBool::new(true)));
        live_entry.session = live_sess.clone();
        assert!(mgr.dispose_warm_entry_checked(live_entry).await.is_err());
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 1);
        assert!(mgr.list_active_sandboxes().iter().any(|s| s.id == live_id));

        // Once dead, sweeper cleans it up and releases permit.
        live_sess.0.store(false, Ordering::Release);
        assert_eq!(mgr.sweep_expired_leases().await, 1);
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 0);

        // 3. Warm disposal where `force_kill` returns Err after VM exits still cleans overlay/journal.
        struct DeadAfterKillErrWarm(AtomicBool, AtomicBool);
        #[async_trait::async_trait]
        impl VmSessionPort for DeadAfterKillErrWarm {
            fn pid(&self) -> u32 { 9292 }
            fn start_token(&self) -> u64 { 9292 }
            fn artifact_paths(&self) -> &[PathBuf] { &[] }
            fn is_alive(&self) -> bool { self.0.load(Ordering::Acquire) }
            fn current_rss_bytes(&self) -> Option<u64> { None }
            async fn graceful_shutdown(&self, _: Duration) -> Result<bool, SandboxError> { Ok(false) }
            async fn force_kill(&self) -> Result<(), SandboxError> {
                self.1.store(true, Ordering::Release);
                self.0.store(false, Ordering::Release);
                Err(SandboxError::Transport("simulated ESRCH".to_owned()))
            }
            async fn exec_stream(&self, _: ExecRequest) -> Result<ExecStream, SandboxError> { unreachable!() }
            async fn copy_in_tar(&self, _: &str, _: Vec<u8>, _: u64) -> Result<u64, SandboxError> { unreachable!() }
            async fn copy_out_tar(&self, _: &str, _: u64) -> Result<Vec<u8>, SandboxError> { unreachable!() }
            async fn open_tunnel(&self, _: StreamTargetWire) -> Result<TunnelStream, SandboxError> { unreachable!() }
            async fn enable_egress_proxy(&self, _: u16) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> { unreachable!() }
        }
        let mut exited_entry = {
            assert_eq!(mgr.warm_up().await.unwrap(), 1);
            mgr.warm_pool.pop_one_for_eviction().unwrap()
        };
        let exited_overlay = exited_entry.prepared.overlay_path.clone();
        let dead_sess = Arc::new(DeadAfterKillErrWarm(
            AtomicBool::new(true),
            AtomicBool::new(false),
        ));
        exited_entry.session = dead_sess.clone();
        assert!(mgr.dispose_warm_entry_checked(exited_entry).await.is_err());
        assert!(dead_sess.1.load(Ordering::Acquire));
        assert!(overlay.removed_paths().contains(&exited_overlay));
        assert_eq!(mgr.current_admission_usage().active_sandboxes, 0);
        assert!(mgr.journal.load_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconcile_startup_skips_in_flight_destroy_sandboxes() {
        let tmp = TestTempDir::new("mgr-reconcile-inflight-destroy");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mgr = LocalRuntimeManager::new(base_config(tmp.path().join("state")), overlay, vm.clone())
            .unwrap();

        let id = SandboxId::new("sbx-inflight-destroy");
        let orphan_file = tmp.path().join("still-destroying.tmp");
        fs::write(&orphan_file, b"keep").unwrap();
        mgr.journal
            .write_record(&JournalRecord {
                sandbox_id: id.clone(),
                state: JournalLifecycleState::Destroying,
                pid: Some(4111),
                start_token: Some(17),
                artifact_paths: vec![orphan_file.clone()],
                expires_at_unix_ms: 0,
            })
            .unwrap();
        lock_unpoisoned(&vm.state).live_orphans.insert((4111, 17));
        let (tx, _rx) = watch::channel(false);
        lock_unpoisoned(&mgr.in_flight_destroys).insert(id.clone(), tx);

        let skipped = mgr.reconcile_startup().await.unwrap();
        assert_eq!(skipped.orphans_killed, 0);
        assert_eq!(skipped.cleaned, 0);
        assert!(orphan_file.exists(), "artifact owned by in-flight destroy must remain");
        assert_eq!(mgr.journal.load_records().unwrap().len(), 1);

        lock_unpoisoned(&mgr.in_flight_destroys).remove(&id);
        let reaped = mgr.reconcile_startup().await.unwrap();
        assert_eq!(reaped.orphans_killed, 1);
        assert_eq!(reaped.cleaned, 1);
        assert!(!orphan_file.exists());
        assert!(mgr.journal.load_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn drain_warm_pool_waits_for_transitioning_checkout_or_eviction() {
        let tmp = TestTempDir::new("mgr-drain-waits-transitioning");
        let overlay = Arc::new(MockOverlayStore::default());
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = Arc::new(LocalRuntimeManager::new(cfg, overlay, vm).unwrap());

        assert_eq!(mgr.warm_up().await.unwrap(), 1);
        let transitioning_entry = mgr.warm_pool.pop_one_for_eviction().unwrap();

        let mgr_drain = Arc::clone(&mgr);
        let drain_task = tokio::spawn(async move { mgr_drain.drain_warm_pool().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !drain_task.is_finished(),
            "drain_warm_pool must wait for active transitioning warm VM"
        );

        mgr.dispose_warm_entry(transitioning_entry).await;
        let drained = tokio::time::timeout(Duration::from_secs(2), drain_task)
            .await
            .expect("drain_warm_pool unblocked once transitioning finished")
            .unwrap()
            .unwrap();
        assert_eq!(drained, 0);
    }

    #[tokio::test]
    async fn cancelled_boot_waits_for_blocking_hook_completion_and_kills_late_pid() {
        struct LatePidBlockingVm {
            boot_started: Arc<tokio::sync::Notify>,
            allow_late_pid: Arc<std::sync::atomic::AtomicBool>,
            kills: Arc<Mutex<Vec<(u32, u64)>>>,
        }
        #[async_trait::async_trait]
        impl VmRuntimePort for LatePidBlockingVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                let boot_started = Arc::clone(&self.boot_started);
                let allow_late_pid = Arc::clone(&self.allow_late_pid);
                tokio::task::spawn_blocking(move || {
                    cfg.record_boot_progress(None, &[])?;
                    boot_started.notify_one();
                    while !allow_late_pid.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    // Delay briefly after cancel so `BootHookDoneGuard` holds `BootCancellationGuard`.
                    std::thread::sleep(Duration::from_millis(30));
                    cfg.record_boot_progress(Some((8888, 9999)), &[])?;
                    unreachable!("cancelled progress hook must return Err")
                })
                .await
                .map_err(|e| SandboxError::Internal(e.to_string()))?
            }

            async fn kill_orphan_process(&self, pid: u32, token: u64) -> Result<bool, SandboxError> {
                lock_unpoisoned(&self.kills).push((pid, token));
                Ok(true)
            }
        }

        let tmp = TestTempDir::new("mgr-cancel-late-pid");
        let overlay = Arc::new(MockOverlayStore::default());
        let boot_started = Arc::new(tokio::sync::Notify::new());
        let allow_late_pid = Arc::new(AtomicBool::new(false));
        let kills = Arc::new(Mutex::new(Vec::new()));
        let vm = Arc::new(LatePidBlockingVm {
            boot_started: Arc::clone(&boot_started),
            allow_late_pid: Arc::clone(&allow_late_pid),
            kills: Arc::clone(&kills),
        });
        let mgr = Arc::new(LocalRuntimeManager::new(base_config(tmp.path().join("state")), overlay, vm).unwrap());

        let mgr_spawn = Arc::clone(&mgr);
        let spawn_task = tokio::spawn(async move {
            mgr_spawn.spawn(valid_spec(Duration::from_secs(60))).await
        });
        boot_started.notified().await;
        spawn_task.abort();
        let _ = spawn_task.await;

        // While blocking boot hasn't finished, permit & cleanup remain held; release late PID now.
        allow_late_pid.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !lock_unpoisoned(&kills).is_empty()
                    && mgr.current_admission_usage().active_sandboxes == 0
                    && mgr.journal.load_records().unwrap().is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled boot must wait for blocking thread, kill late PID, and rollback");
        assert_eq!(lock_unpoisoned(&kills).as_slice(), &[(8888, 9999)]);
    }

    #[tokio::test]
    async fn boot_vm_error_reaps_recorded_pid_and_preserves_journal_if_kill_fails() {
        struct FailAfterPidVm {
            fail_kill: AtomicBool,
            kills: Arc<Mutex<Vec<(u32, u64)>>>,
        }
        #[async_trait::async_trait]
        impl VmRuntimePort for FailAfterPidVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                cfg.record_boot_progress(Some((7777, 5555)), &[])?;
                Err(SandboxError::Transport("simulated post-spawn handshake error".to_owned()))
            }

            async fn kill_orphan_process(&self, pid: u32, token: u64) -> Result<bool, SandboxError> {
                lock_unpoisoned(&self.kills).push((pid, token));
                if self.fail_kill.load(Ordering::Acquire) {
                    Err(SandboxError::Transport("simulated EPERM".to_owned()))
                } else {
                    Ok(true)
                }
            }
        }

        // Case A: kill fails -> preserve Spawning journal with (7777, 5555) for startup reconciler.
        let tmp_fail = TestTempDir::new("mgr-boot-err-kill-fails");
        let vm_fail = Arc::new(FailAfterPidVm {
            fail_kill: AtomicBool::new(true),
            kills: Arc::new(Mutex::new(Vec::new())),
        });
        let mgr_fail = LocalRuntimeManager::new(
            base_config(tmp_fail.path().join("state")),
            Arc::new(MockOverlayStore::default()),
            vm_fail.clone(),
        )
        .unwrap();
        assert!(mgr_fail.spawn(valid_spec(Duration::from_secs(60))).await.is_err());
        assert_eq!(lock_unpoisoned(&vm_fail.kills).as_slice(), &[(7777, 5555)]);
        let recs = mgr_fail.journal.load_records().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].pid, Some(7777));
        assert_eq!(recs[0].start_token, Some(5555));

        // Case B: kill succeeds -> overlay & journal are cleaned up cleanly.
        let tmp_ok = TestTempDir::new("mgr-boot-err-kill-ok");
        let overlay_ok = Arc::new(MockOverlayStore::default());
        let vm_ok = Arc::new(FailAfterPidVm {
            fail_kill: AtomicBool::new(false),
            kills: Arc::new(Mutex::new(Vec::new())),
        });
        let mgr_ok = LocalRuntimeManager::new(
            base_config(tmp_ok.path().join("state")),
            overlay_ok.clone(),
            vm_ok.clone(),
        )
        .unwrap();
        assert!(mgr_ok.spawn(valid_spec(Duration::from_secs(60))).await.is_err());
        assert_eq!(lock_unpoisoned(&vm_ok.kills).as_slice(), &[(7777, 5555)]);
        assert!(mgr_ok.journal.load_records().unwrap().is_empty());
        assert!(!overlay_ok.removed_paths().is_empty());
    }

    #[tokio::test]
    async fn dispose_warm_entry_drops_session_before_overlay_cleanup() {
        struct DropCheckOverlay {
            inner: MockOverlayStore,
            session_dropped: Arc<AtomicBool>,
            session_was_dropped_before_remove: AtomicBool,
        }
        #[async_trait::async_trait]
        impl DiskOverlayPort for DropCheckOverlay {
            async fn prepare_overlay(
                &self,
                sandbox_id: &SandboxId,
                spec: &SandboxSpec,
                work_dir: &Path,
            ) -> Result<PreparedOverlay, SandboxError> {
                self.inner.prepare_overlay(sandbox_id, spec, work_dir).await
            }

            async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
                self.session_was_dropped_before_remove.store(
                    self.session_dropped.load(Ordering::Acquire),
                    Ordering::Release,
                );
                self.inner.remove_overlay(overlay_path).await
            }
        }
        struct DropOrderSession(Arc<AtomicBool>);
        impl Drop for DropOrderSession {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        #[async_trait::async_trait]
        impl VmSessionPort for DropOrderSession {
            fn pid(&self) -> u32 { 5050 }
            fn start_token(&self) -> u64 { 5050 }
            fn artifact_paths(&self) -> &[PathBuf] { &[] }
            fn is_alive(&self) -> bool { false }
            fn current_rss_bytes(&self) -> Option<u64> { None }
            async fn graceful_shutdown(&self, _: Duration) -> Result<bool, SandboxError> { Ok(false) }
            async fn force_kill(&self) -> Result<(), SandboxError> { Ok(()) }
            async fn exec_stream(&self, _: ExecRequest) -> Result<ExecStream, SandboxError> { unreachable!() }
            async fn copy_in_tar(&self, _: &str, _: Vec<u8>, _: u64) -> Result<u64, SandboxError> { unreachable!() }
            async fn copy_out_tar(&self, _: &str, _: u64) -> Result<Vec<u8>, SandboxError> { unreachable!() }
            async fn open_tunnel(&self, _: StreamTargetWire) -> Result<TunnelStream, SandboxError> { unreachable!() }
            async fn enable_egress_proxy(&self, _: u16) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError> { unreachable!() }
        }

        let tmp = TestTempDir::new("mgr-warm-drop-before-rm");
        let session_dropped = Arc::new(AtomicBool::new(false));
        let overlay = Arc::new(DropCheckOverlay {
            inner: MockOverlayStore::default(),
            session_dropped: Arc::clone(&session_dropped),
            session_was_dropped_before_remove: AtomicBool::new(false),
        });
        let vm = Arc::new(MockVmRuntime::new(true));
        let mut cfg = base_config(tmp.path().join("state"));
        cfg.warm_pool.target_size = 1;
        cfg.warm_pool.template_spec = Some(valid_spec(Duration::from_secs(60)));
        let mgr = LocalRuntimeManager::new(cfg, overlay.clone(), vm).unwrap();

        assert_eq!(mgr.warm_up().await.unwrap(), 1);
        let mut entry = mgr.warm_pool.pop_one_for_eviction().unwrap();
        entry.session = Arc::new(DropOrderSession(Arc::clone(&session_dropped)));
        mgr.dispose_warm_entry(entry).await;

        assert!(
            overlay.session_was_dropped_before_remove.load(Ordering::Acquire),
            "TransitioningVm must hold Weak so VmSessionPort drops before remove_overlay"
        );
    }

    #[tokio::test]
    async fn on_boot_progress_retains_external_artifacts_across_fallback_and_concurrent_drains() {
        struct TwoAttemptVm {
            ext_path: PathBuf,
            saw_ext_after_reset: AtomicBool,
            journal: JournalStore,
        }
        #[async_trait::async_trait]
        impl VmRuntimePort for TwoAttemptVm {
            async fn boot_vm(&self, cfg: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
                fs::write(&self.ext_path, b"ext").unwrap();
                cfg.record_boot_progress(Some((1001, 11)), std::slice::from_ref(&self.ext_path))?;
                // Second attempt resets pid to None with empty artifacts; journal must still keep ext_path.
                cfg.record_boot_progress(None, &[])?;
                if let Ok(Some(rec)) = self.journal.load_record(&cfg.sandbox_id) {
                    self.saw_ext_after_reset
                        .store(rec.artifact_paths.contains(&self.ext_path), Ordering::Release);
                }
                Err(SandboxError::Transport("simulated fallback fail".to_owned()))
            }

            async fn kill_orphan_process(&self, _: u32, _: u64) -> Result<bool, SandboxError> {
                Ok(false)
            }
        }

        let tmp = TestTempDir::new("mgr-fallback-artifacts");
        let state_dir = tmp.path().join("state");
        let ext_path = tmp.path().join("attempt1-ext.sock");
        let overlay = Arc::new(MockOverlayStore::default());
        let journal = JournalStore::new(&state_dir.join("journals")).unwrap();
        let vm = Arc::new(TwoAttemptVm {
            ext_path: ext_path.clone(),
            saw_ext_after_reset: AtomicBool::new(false),
            journal,
        });
        let mgr = LocalRuntimeManager::new(base_config(state_dir), overlay, vm.clone()).unwrap();

        assert!(mgr.spawn(valid_spec(Duration::from_secs(60))).await.is_err());
        assert!(
            vm.saw_ext_after_reset.load(Ordering::Acquire),
            "Attempt 2 progress reset must retain Attempt 1 external artifact paths"
        );
        assert!(!ext_path.exists(), "retained external artifact must be cleaned up");

        // Concurrent drain guard counter test.
        mgr.warm_pool.begin_drain();
        assert_eq!(mgr.drain_warm_pool().await.unwrap(), 0);
        assert!(
            mgr.warm_pool.is_draining(),
            "draining must stay active until outer drainer finishes"
        );
        mgr.warm_pool.end_drain();
        assert!(!mgr.warm_pool.is_draining());
    }
}
