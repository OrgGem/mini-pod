//! Host Warm Pool configuration, keying, metrics, and concurrency-safe ready/transition state.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use sandbox_core::{
    AccelerationPolicy, CapabilityReport, IsolationMode, ResourceBudget, SandboxError, SandboxId,
    SandboxSpec,
};
use tokio::sync::{watch, Notify};
use tokio::task::AbortHandle;

use crate::admission::AdmissionPermit;
use crate::ports::{PreparedOverlay, VmSessionPort};

/// Configuration for the pre-warmed idle VM pool inside [`crate::LocalRuntimeManager`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmPoolConfig {
    pub target_size: usize,
    pub template_spec: Option<SandboxSpec>,
    pub max_idle_age: Duration,
    pub replenish_retry_delay: Duration,
}

impl Default for WarmPoolConfig {
    fn default() -> Self {
        Self {
            target_size: 0,
            template_spec: None,
            max_idle_age: Duration::from_secs(300),
            replenish_retry_delay: Duration::from_millis(250),
        }
    }
}

impl WarmPoolConfig {
    /// Validates Warm Pool configuration invariants before runtime startup.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.max_idle_age.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "warm_pool.max_idle_age must be greater than zero".to_owned(),
            ));
        }
        if self.replenish_retry_delay.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "warm_pool.replenish_retry_delay must be greater than zero".to_owned(),
            ));
        }
        if self.target_size > 0 {
            let Some(ref spec) = self.template_spec else {
                return Err(SandboxError::InvalidSpec(
                    "warm_pool.template_spec must be Some when target_size > 0".to_owned(),
                ));
            };
            validate_vm_spec(spec, "warm_pool.template_spec")?;
        }
        Ok(())
    }
}

pub(crate) fn validate_vm_spec(spec: &SandboxSpec, label: &str) -> Result<(), SandboxError> {
    if spec.isolation == IsolationMode::SharedKernelAllowed {
        return Err(SandboxError::UnsupportedIsolationMode(
            "SharedKernelAllowed is not permitted when VmRequired runtime enforcement is active"
                .to_owned(),
        ));
    }
    spec.validate_for_host_os(std::env::consts::OS)?;
    if spec.budget.virtual_disk_mb > spec.budget.host_storage_budget_mb {
        return Err(SandboxError::BudgetExceeded(format!(
            "{label} virtual_disk_mb ({} MiB) exceeds host_storage_budget_mb ({} MiB)",
            spec.budget.virtual_disk_mb, spec.budget.host_storage_budget_mb
        )));
    }
    Ok(())
}

/// Compatibility key matching `(isolation, acceleration, budget)` independent of `network` and `lease_ttl`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmPoolKey {
    pub isolation: IsolationMode,
    pub acceleration: AccelerationPolicy,
    pub budget: ResourceBudget,
}

impl WarmPoolKey {
    /// Builds a [`WarmPoolKey`] from `spec`, ignoring `network` and `lease_ttl`.
    pub fn from_spec(spec: &SandboxSpec) -> Self {
        Self {
            isolation: spec.isolation,
            acceleration: spec.acceleration,
            budget: spec.budget.clone(),
        }
    }
}

/// Point-in-time counters and gauges describing [`crate::LocalRuntimeManager`] Warm Pool activity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WarmPoolStats {
    pub ready_vms: usize,
    pub replenishing_vms: usize,
    pub total_checkouts: u64,
    pub total_cold_spawns: u64,
    pub total_evictions: u64,
    pub total_disposed_dirty: u64,
}

pub(crate) struct WarmEntry {
    pub(crate) sandbox_id: SandboxId,
    pub(crate) key: WarmPoolKey,
    pub(crate) session: Arc<dyn VmSessionPort>,
    pub(crate) work_dir: PathBuf,
    pub(crate) prepared: PreparedOverlay,
    pub(crate) artifact_paths: Vec<PathBuf>,
    pub(crate) boot_capabilities: CapabilityReport,
    pub(crate) booted_at: Instant,
    pub(crate) reserved_rss_mb: u64,
    // Drop `permit` last so session tears down before admission capacity re-opens.
    pub(crate) permit: AdmissionPermit,
}

struct TransitioningVm {
    session: Arc<dyn VmSessionPort>,
    reserved_rss_mb: u64,
}

pub(crate) struct ReplenisherHandle {
    pub(crate) abort_handle: AbortHandle,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) done_rx: watch::Receiver<bool>,
}

#[derive(Default)]
struct WarmPoolState {
    ready: VecDeque<WarmEntry>,
    transitioning: std::collections::HashMap<SandboxId, TransitioningVm>,
    booting_ids: HashSet<SandboxId>,
    replenishing_vms: usize,
    total_checkouts: u64,
    total_cold_spawns: u64,
    total_evictions: u64,
    total_disposed_dirty: u64,
    draining: bool,
}

pub(crate) enum CheckoutPop {
    None,
    ExpiredOrDead(WarmEntry),
    Candidate(WarmEntry),
}

pub(crate) struct WarmReplenishGuard {
    store: WarmPoolStore,
    sandbox_id: SandboxId,
    armed: bool,
}

impl Drop for WarmReplenishGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let notify_done = {
            let mut state = lock_unpoisoned(&self.store.inner);
            state.replenishing_vms = state.replenishing_vms.saturating_sub(1);
            state.booting_ids.remove(&self.sandbox_id);
            state.replenishing_vms == 0
        };
        if notify_done {
            self.store.replenish_done_notify.notify_waiters();
        }
    }
}

#[derive(Clone)]
pub(crate) struct WarmPoolStore {
    inner: Arc<Mutex<WarmPoolState>>,
    replenisher: Arc<Mutex<Option<ReplenisherHandle>>>,
    replenish_notify: Arc<Notify>,
    replenish_done_notify: Arc<Notify>,
}

#[derive(Clone)]
pub(crate) struct WeakWarmPoolStore {
    inner: Weak<Mutex<WarmPoolState>>,
}

impl WeakWarmPoolStore {
    pub(crate) fn collect_rss_samples(&self, dst: &mut Vec<(Arc<dyn VmSessionPort>, u64)>) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let state = lock_unpoisoned(&inner);
        dst.extend(
            state
                .ready
                .iter()
                .map(|entry| (Arc::clone(&entry.session), entry.reserved_rss_mb)),
        );
        dst.extend(
            state
                .transitioning
                .values()
                .map(|vm| (Arc::clone(&vm.session), vm.reserved_rss_mb)),
        );
    }
}

impl WarmPoolStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(WarmPoolState::default())),
            replenisher: Arc::new(Mutex::new(None)),
            replenish_notify: Arc::new(Notify::new()),
            replenish_done_notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn downgrade(&self) -> WeakWarmPoolStore {
        WeakWarmPoolStore {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn stats(&self) -> WarmPoolStats {
        let state = lock_unpoisoned(&self.inner);
        WarmPoolStats {
            ready_vms: state.ready.len(),
            replenishing_vms: state.replenishing_vms,
            total_checkouts: state.total_checkouts,
            total_cold_spawns: state.total_cold_spawns,
            total_evictions: state.total_evictions,
            total_disposed_dirty: state.total_disposed_dirty,
        }
    }

    pub(crate) fn ready_len(&self) -> usize {
        lock_unpoisoned(&self.inner).ready.len()
    }

    pub(crate) fn is_draining(&self) -> bool {
        lock_unpoisoned(&self.inner).draining
    }

    pub(crate) fn set_draining(&self, draining: bool) {
        lock_unpoisoned(&self.inner).draining = draining;
    }

    pub(crate) fn contains_live_id(&self, id: &SandboxId) -> bool {
        let state = lock_unpoisoned(&self.inner);
        state.ready.iter().any(|entry| &entry.sandbox_id == id)
            || state.transitioning.contains_key(id)
            || state.booting_ids.contains(id)
    }

    pub(crate) fn notify_replenisher(&self) {
        self.replenish_notify.notify_one();
    }

    pub(crate) fn replenish_notify(&self) -> &Arc<Notify> {
        &self.replenish_notify
    }

    pub(crate) fn try_begin_replenish(
        &self,
        target_size: usize,
        sandbox_id: SandboxId,
    ) -> Option<WarmReplenishGuard> {
        let mut state = lock_unpoisoned(&self.inner);
        if state.draining || state.ready.len().saturating_add(state.replenishing_vms) >= target_size
        {
            return None;
        }
        state.replenishing_vms = state.replenishing_vms.saturating_add(1);
        state.booting_ids.insert(sandbox_id.clone());
        Some(WarmReplenishGuard {
            store: self.clone(),
            sandbox_id,
            armed: true,
        })
    }

    /// Parks `entry` into the ready queue unless draining or at capacity, returning `Some(entry)`
    /// for out-of-lock disposal when rejected.
    pub(crate) fn park_from_replenish(
        &self,
        mut guard: WarmReplenishGuard,
        entry: WarmEntry,
        target_size: usize,
    ) -> Option<WarmEntry> {
        let mut notify_done = false;
        let rejected = {
            let mut state = lock_unpoisoned(&self.inner);
            guard.armed = false;
            state.replenishing_vms = state.replenishing_vms.saturating_sub(1);
            state.booting_ids.remove(&guard.sandbox_id);
            if state.replenishing_vms == 0 {
                notify_done = true;
            }
            if state.draining || state.ready.len() >= target_size {
                Some(entry)
            } else {
                state.ready.push_back(entry);
                None
            }
        };
        if notify_done {
            self.replenish_done_notify.notify_waiters();
        }
        rejected
    }

    pub(crate) fn pop_for_checkout(&self, key: &WarmPoolKey, max_idle_age: Duration) -> CheckoutPop {
        let mut state = lock_unpoisoned(&self.inner);
        if state.draining {
            return CheckoutPop::None;
        }
        let Some(pos) = state.ready.iter().position(|entry| entry.key == *key) else {
            return CheckoutPop::None;
        };
        let Some(entry) = state.ready.remove(pos) else {
            return CheckoutPop::None;
        };
        if !entry.session.is_alive() || entry.booted_at.elapsed() >= max_idle_age {
            state.total_evictions = state.total_evictions.saturating_add(1);
            return CheckoutPop::ExpiredOrDead(entry);
        }
        state.transitioning.insert(
            entry.sandbox_id.clone(),
            TransitioningVm {
                session: Arc::clone(&entry.session),
                reserved_rss_mb: entry.reserved_rss_mb,
            },
        );
        CheckoutPop::Candidate(entry)
    }

    pub(crate) fn commit_checkout(&self, sandbox_id: &SandboxId) {
        let mut state = lock_unpoisoned(&self.inner);
        state.transitioning.remove(sandbox_id);
        state.total_checkouts = state.total_checkouts.saturating_add(1);
    }

    pub(crate) fn abort_checkout(&self, sandbox_id: &SandboxId) {
        let mut state = lock_unpoisoned(&self.inner);
        state.transitioning.remove(sandbox_id);
        state.total_disposed_dirty = state.total_disposed_dirty.saturating_add(1);
    }

    pub(crate) fn pop_one_for_eviction(&self) -> Option<WarmEntry> {
        let mut state = lock_unpoisoned(&self.inner);
        let entry = state.ready.pop_front()?;
        state.total_evictions = state.total_evictions.saturating_add(1);
        Some(entry)
    }

    pub(crate) fn drain_expired(&self, max_idle_age: Duration) -> Vec<WarmEntry> {
        let mut state = lock_unpoisoned(&self.inner);
        let len = state.ready.len();
        let mut kept = VecDeque::with_capacity(len);
        let mut expired = Vec::new();
        while let Some(entry) = state.ready.pop_front() {
            if !entry.session.is_alive() || entry.booted_at.elapsed() >= max_idle_age {
                expired.push(entry);
            } else {
                kept.push_back(entry);
            }
        }
        state.ready = kept;
        state.total_evictions = state.total_evictions.saturating_add(expired.len() as u64);
        expired
    }

    pub(crate) fn drain_ready(&self) -> Vec<WarmEntry> {
        let mut state = lock_unpoisoned(&self.inner);
        state.ready.drain(..).collect()
    }

    pub(crate) fn clear_ready_for_drop(&self) -> Vec<WarmEntry> {
        let mut state = lock_unpoisoned(&self.inner);
        state.draining = true;
        state.ready.drain(..).collect()
    }

    pub(crate) fn record_cold_spawn(&self) {
        let mut state = lock_unpoisoned(&self.inner);
        state.total_cold_spawns = state.total_cold_spawns.saturating_add(1);
    }

    pub(crate) fn record_disposed_dirty(&self) {
        let mut state = lock_unpoisoned(&self.inner);
        state.total_disposed_dirty = state.total_disposed_dirty.saturating_add(1);
    }

    pub(crate) async fn wait_for_no_replenishing(&self) {
        loop {
            let notified = self.replenish_done_notify.notified();
            if lock_unpoisoned(&self.inner).replenishing_vms == 0 {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn replace_replenisher(&self, handle: ReplenisherHandle) {
        let prev = lock_unpoisoned(&self.replenisher).replace(handle);
        if let Some(prev_handle) = prev {
            let _ = prev_handle.shutdown_tx.send(true);
            prev_handle.abort_handle.abort();
        }
    }

    pub(crate) fn take_replenisher(&self) -> Option<ReplenisherHandle> {
        lock_unpoisoned(&self.replenisher).take()
    }

    pub(crate) fn abort_replenisher(&self) {
        if let Some(handle) = self.take_replenisher() {
            let _ = handle.shutdown_tx.send(true);
            handle.abort_handle.abort();
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_core::{EgressRule, NetworkPolicy};

    fn sample_spec() -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: Some(1000),
                guest_ram_mb: 256,
                host_rss_budget_mb: Some(512),
                virtual_disk_mb: 512,
                host_storage_budget_mb: 1024,
            },
            lease_ttl: Duration::from_secs(60),
        }
    }

    #[test]
    fn warm_pool_config_validation_enforces_invariants() {
        let default_cfg = WarmPoolConfig::default();
        assert_eq!(default_cfg.target_size, 0);
        assert_eq!(default_cfg.template_spec, None);
        assert_eq!(default_cfg.max_idle_age, Duration::from_secs(300));
        assert_eq!(default_cfg.replenish_retry_delay, Duration::from_millis(250));
        assert!(default_cfg.validate().is_ok());

        let zero_age = WarmPoolConfig {
            max_idle_age: Duration::ZERO,
            ..Default::default()
        };
        assert!(matches!(zero_age.validate(), Err(SandboxError::InvalidSpec(_))));

        let zero_retry = WarmPoolConfig {
            replenish_retry_delay: Duration::ZERO,
            ..Default::default()
        };
        assert!(matches!(
            zero_retry.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let missing_template = WarmPoolConfig {
            target_size: 1,
            template_spec: None,
            ..Default::default()
        };
        assert!(matches!(
            missing_template.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut shared_spec = sample_spec();
        shared_spec.isolation = IsolationMode::SharedKernelAllowed;
        let shared_cfg = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(shared_spec),
            ..Default::default()
        };
        assert!(matches!(
            shared_cfg.validate(),
            Err(SandboxError::UnsupportedIsolationMode(_))
        ));

        let mut disk_over = sample_spec();
        disk_over.budget.virtual_disk_mb = 2048;
        disk_over.budget.host_storage_budget_mb = 1024;
        let disk_over_cfg = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(disk_over),
            ..Default::default()
        };
        assert!(matches!(
            disk_over_cfg.validate(),
            Err(SandboxError::BudgetExceeded(_))
        ));

        let mut bad_net = sample_spec();
        bad_net.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "127.0.0.1".to_owned(),
                port: 443,
            }],
        };
        let bad_net_cfg = WarmPoolConfig {
            target_size: 1,
            template_spec: Some(bad_net),
            ..Default::default()
        };
        assert!(matches!(
            bad_net_cfg.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let ok_cfg = WarmPoolConfig {
            target_size: 2,
            template_spec: Some(sample_spec()),
            ..Default::default()
        };
        assert!(ok_cfg.validate().is_ok());
    }

    #[test]
    fn warm_pool_key_ignores_network_and_lease_ttl_but_distinguishes_budget_and_accel() {
        let base = sample_spec();
        let base_key = WarmPoolKey::from_spec(&base);

        let mut internet_short = base.clone();
        internet_short.network = NetworkPolicy::InternetOnly;
        internet_short.lease_ttl = Duration::from_secs(5);
        assert_eq!(WarmPoolKey::from_spec(&internet_short), base_key);

        let mut allowlist = base.clone();
        allowlist.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "api.example.com".to_owned(),
                port: 443,
            }],
        };
        assert_eq!(WarmPoolKey::from_spec(&allowlist), base_key);

        let mut unrestricted = base.clone();
        unrestricted.network = NetworkPolicy::Unrestricted;
        assert_eq!(WarmPoolKey::from_spec(&unrestricted), base_key);

        let mut diff_accel = base.clone();
        diff_accel.acceleration = AccelerationPolicy::SoftwareOnly;
        assert_ne!(WarmPoolKey::from_spec(&diff_accel), base_key);

        let mut diff_ram = base;
        diff_ram.budget.guest_ram_mb = 512;
        assert_ne!(WarmPoolKey::from_spec(&diff_ram), base_key);
    }
}
