//! Host admission control: static resource reservations, live RSS pressure checks,
//! and bounded cancellation-safe FIFO wait queue.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sandbox_core::{SandboxError, SandboxSpec};
use tokio::sync::Notify;
use tokio::time::Instant;

/// Host-wide admission ceilings and optional bounded FIFO queueing policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionLimits {
    pub max_concurrent_sandboxes: Option<usize>,
    pub max_total_host_rss_mb: Option<u64>,
    pub max_total_host_storage_mb: Option<u64>,
    pub max_total_host_cpu_millicores: Option<u64>,
    pub admission_queue_timeout: Duration,
    pub max_admission_queue_depth: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_concurrent_sandboxes: None,
            max_total_host_rss_mb: None,
            max_total_host_storage_mb: None,
            max_total_host_cpu_millicores: None,
            admission_queue_timeout: Duration::ZERO,
            max_admission_queue_depth: 64,
        }
    }
}

impl AdmissionLimits {
    /// Rejects explicit `Some(0)` ceilings that would deny every sandbox unconditionally.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.max_concurrent_sandboxes == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "max_concurrent_sandboxes cannot be Some(0)".to_owned(),
            ));
        }
        if self.max_total_host_rss_mb == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "max_total_host_rss_mb cannot be Some(0)".to_owned(),
            ));
        }
        if self.max_total_host_storage_mb == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "max_total_host_storage_mb cannot be Some(0)".to_owned(),
            ));
        }
        if self.max_total_host_cpu_millicores == Some(0) {
            return Err(SandboxError::InvalidSpec(
                "max_total_host_cpu_millicores cannot be Some(0)".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Snapshot of currently reserved and effective host admission resources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionUsage {
    pub active_sandboxes: usize,
    pub reserved_host_rss_mb: u64,
    pub effective_host_rss_mb: u64,
    pub reserved_host_storage_mb: u64,
    pub reserved_host_cpu_millicores: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResourceDemand {
    pub rss_mb: u64,
    pub storage_mb: u64,
    pub cpu_millicores: u64,
}

impl ResourceDemand {
    pub(crate) fn from_spec(spec: &SandboxSpec) -> Self {
        Self {
            rss_mb: u64::from(
                spec.budget
                    .host_rss_budget_mb
                    .unwrap_or(spec.budget.guest_ram_mb),
            ),
            storage_mb: u64::from(spec.budget.host_storage_budget_mb),
            cpu_millicores: u64::from(
                spec.budget
                    .host_cpu_quota_Millicores
                    .unwrap_or_else(|| u32::from(spec.budget.guest_vcpus) * 1000),
            ),
        }
    }
}

struct Waiter {
    id: u64,
    notify: Notify,
}

struct AdmissionState {
    reserved_count: usize,
    reserved_host_rss_mb: u64,
    reserved_host_storage_mb: u64,
    reserved_host_cpu_millicores: u64,
    waiters: VecDeque<Arc<Waiter>>,
    next_ticket_id: u64,
}

impl AdmissionState {
    fn reserve(&mut self, demand: ResourceDemand) {
        self.reserved_count = self.reserved_count.saturating_add(1);
        self.reserved_host_rss_mb = self.reserved_host_rss_mb.saturating_add(demand.rss_mb);
        self.reserved_host_storage_mb =
            self.reserved_host_storage_mb.saturating_add(demand.storage_mb);
        self.reserved_host_cpu_millicores = self
            .reserved_host_cpu_millicores
            .saturating_add(demand.cpu_millicores);
    }

    fn release(&mut self, demand: ResourceDemand) {
        self.reserved_count = self.reserved_count.saturating_sub(1);
        self.reserved_host_rss_mb = self.reserved_host_rss_mb.saturating_sub(demand.rss_mb);
        self.reserved_host_storage_mb =
            self.reserved_host_storage_mb.saturating_sub(demand.storage_mb);
        self.reserved_host_cpu_millicores = self
            .reserved_host_cpu_millicores
            .saturating_sub(demand.cpu_millicores);
    }
}

type ObservedRssFn = Arc<dyn Fn() -> u64 + Send + Sync>;

struct AdmissionInner {
    limits: AdmissionLimits,
    observed_rss_mb: ObservedRssFn,
    state: Mutex<AdmissionState>,
}

impl AdmissionInner {
    fn check_individual_cap(&self, demand: ResourceDemand) -> Result<(), SandboxError> {
        if let Some(max_rss) = self.limits.max_total_host_rss_mb {
            if demand.rss_mb > max_rss {
                return Err(SandboxError::AdmissionRejected(format!(
                    "sandbox host RSS demand ({} MiB) exceeds max_total_host_rss_mb ({max_rss} MiB)",
                    demand.rss_mb
                )));
            }
        }
        if let Some(max_storage) = self.limits.max_total_host_storage_mb {
            if demand.storage_mb > max_storage {
                return Err(SandboxError::AdmissionRejected(format!(
                    "sandbox host storage demand ({} MiB) exceeds max_total_host_storage_mb ({max_storage} MiB)",
                    demand.storage_mb
                )));
            }
        }
        if let Some(max_cpu) = self.limits.max_total_host_cpu_millicores {
            if demand.cpu_millicores > max_cpu {
                return Err(SandboxError::AdmissionRejected(format!(
                    "sandbox host CPU demand ({} millicores) exceeds max_total_host_cpu_millicores ({max_cpu} millicores)",
                    demand.cpu_millicores
                )));
            }
        }
        Ok(())
    }

    fn can_admit(&self, state: &AdmissionState, demand: ResourceDemand) -> Result<(), String> {
        if let Some(max_count) = self.limits.max_concurrent_sandboxes {
            if state.reserved_count.saturating_add(1) > max_count {
                return Err(format!(
                    "max_concurrent_sandboxes limit ({max_count}) reached"
                ));
            }
        }
        if let Some(max_rss) = self.limits.max_total_host_rss_mb {
            let observed_live = (self.observed_rss_mb)();
            let live_total_mb = state.reserved_host_rss_mb.max(observed_live);
            if live_total_mb.saturating_add(demand.rss_mb) > max_rss {
                return Err(format!(
                    "host RSS limit ({max_rss} MiB) exceeded: live_total={live_total_mb} MiB, requested={} MiB",
                    demand.rss_mb
                ));
            }
        }
        if let Some(max_storage) = self.limits.max_total_host_storage_mb {
            if state
                .reserved_host_storage_mb
                .saturating_add(demand.storage_mb)
                > max_storage
            {
                return Err(format!(
                    "host storage limit ({max_storage} MiB) exceeded: reserved={} MiB, requested={} MiB",
                    state.reserved_host_storage_mb, demand.storage_mb
                ));
            }
        }
        if let Some(max_cpu) = self.limits.max_total_host_cpu_millicores {
            if state
                .reserved_host_cpu_millicores
                .saturating_add(demand.cpu_millicores)
                > max_cpu
            {
                return Err(format!(
                    "host CPU limit ({max_cpu} millicores) exceeded: reserved={} millicores, requested={} millicores",
                    state.reserved_host_cpu_millicores, demand.cpu_millicores
                ));
            }
        }
        Ok(())
    }
}

/// RAII reservation permit held across spawn and active sandbox lifetime.
pub(crate) struct AdmissionPermit {
    inner: Arc<AdmissionInner>,
    demand: ResourceDemand,
}

impl AdmissionPermit {
    pub(crate) fn demand(&self) -> ResourceDemand {
        self.demand
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = lock_unpoisoned(&self.inner.state);
        state.release(self.demand);
        notify_head_waiter(&state);
    }
}

struct WaiterGuard {
    inner: Arc<AdmissionInner>,
    ticket_id: u64,
    armed: bool,
}

impl WaiterGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = lock_unpoisoned(&self.inner.state);
        if let Some(pos) = state.waiters.iter().position(|w| w.id == self.ticket_id) {
            state.waiters.remove(pos);
            if pos == 0 {
                notify_head_waiter(&state);
            }
        }
    }
}

/// Coordinates host-wide sandbox concurrency and physical resource reservations.
#[derive(Clone)]
pub(crate) struct AdmissionController {
    inner: Arc<AdmissionInner>,
}

impl AdmissionController {
    pub(crate) fn new(limits: AdmissionLimits, observed_rss_mb: ObservedRssFn) -> Self {
        Self {
            inner: Arc::new(AdmissionInner {
                limits,
                observed_rss_mb,
                state: Mutex::new(AdmissionState {
                    reserved_count: 0,
                    reserved_host_rss_mb: 0,
                    reserved_host_storage_mb: 0,
                    reserved_host_cpu_millicores: 0,
                    waiters: VecDeque::new(),
                    next_ticket_id: 1,
                }),
            }),
        }
    }

    pub(crate) fn usage(&self) -> AdmissionUsage {
        let state = lock_unpoisoned(&self.inner.state);
        let observed_live_rss_mb = (self.inner.observed_rss_mb)();
        AdmissionUsage {
            active_sandboxes: state.reserved_count,
            reserved_host_rss_mb: state.reserved_host_rss_mb,
            effective_host_rss_mb: state.reserved_host_rss_mb.max(observed_live_rss_mb),
            reserved_host_storage_mb: state.reserved_host_storage_mb,
            reserved_host_cpu_millicores: state.reserved_host_cpu_millicores,
        }
    }

    pub(crate) fn has_waiters(&self) -> bool {
        let state = lock_unpoisoned(&self.inner.state);
        !state.waiters.is_empty()
    }

    pub(crate) fn check_individual_cap(&self, spec: &SandboxSpec) -> Result<(), SandboxError> {
        self.inner
            .check_individual_cap(ResourceDemand::from_spec(spec))
    }

    /// Read-only check whether admitting `spec` right now would exceed configured ceilings.
    pub(crate) fn would_exceed_with(&self, spec: &SandboxSpec) -> bool {
        let demand = ResourceDemand::from_spec(spec);
        let state = lock_unpoisoned(&self.inner.state);
        self.inner.can_admit(&state, demand).is_err()
    }

    /// Non-blocking admission check for background Warm Pool replenishment.
    ///
    /// Foreground FIFO waiters always preempt background reservations so queued user spawns
    /// acquire released capacity first.
    pub(crate) fn try_acquire_background(&self, spec: &SandboxSpec) -> Option<AdmissionPermit> {
        let demand = ResourceDemand::from_spec(spec);
        if self.inner.check_individual_cap(demand).is_err() {
            return None;
        }
        let mut state = lock_unpoisoned(&self.inner.state);
        if !state.waiters.is_empty() || self.inner.can_admit(&state, demand).is_err() {
            return None;
        }
        state.reserve(demand);
        Some(AdmissionPermit {
            inner: Arc::clone(&self.inner),
            demand,
        })
    }

    pub(crate) async fn acquire(&self, spec: &SandboxSpec) -> Result<AdmissionPermit, SandboxError> {
        let demand = ResourceDemand::from_spec(spec);
        self.inner.check_individual_cap(demand)?;

        let (ticket_id, waiter, mut guard) = {
            let mut state = lock_unpoisoned(&self.inner.state);
            if state.waiters.is_empty() {
                match self.inner.can_admit(&state, demand) {
                    Ok(()) => {
                        state.reserve(demand);
                        return Ok(AdmissionPermit {
                            inner: Arc::clone(&self.inner),
                            demand,
                        });
                    }
                    Err(reason) if self.inner.limits.admission_queue_timeout.is_zero() => {
                        return Err(SandboxError::AdmissionRejected(reason));
                    }
                    Err(_) => {}
                }
            } else if self.inner.limits.admission_queue_timeout.is_zero() {
                return Err(SandboxError::AdmissionRejected(
                    "admission queue already has waiting requests".to_owned(),
                ));
            }

            if state.waiters.len() >= self.inner.limits.max_admission_queue_depth {
                return Err(SandboxError::AdmissionRejected(format!(
                    "admission queue depth limit ({}) reached",
                    self.inner.limits.max_admission_queue_depth
                )));
            }

            let ticket_id = state.next_ticket_id;
            state.next_ticket_id = state.next_ticket_id.wrapping_add(1);
            let waiter = Arc::new(Waiter {
                id: ticket_id,
                notify: Notify::new(),
            });
            state.waiters.push_back(Arc::clone(&waiter));
            let guard = WaiterGuard {
                inner: Arc::clone(&self.inner),
                ticket_id,
                armed: true,
            };
            (ticket_id, waiter, guard)
        };

        let deadline = Instant::now()
            .checked_add(self.inner.limits.admission_queue_timeout)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400 * 365));
        loop {
            let (notified, reject_reason) = {
                let mut state = lock_unpoisoned(&self.inner.state);
                let is_head = state.waiters.front().is_some_and(|head| head.id == ticket_id);
                if is_head {
                    match self.inner.can_admit(&state, demand) {
                        Ok(()) => {
                            state.waiters.pop_front();
                            state.reserve(demand);
                            guard.disarm();
                            notify_head_waiter(&state);
                            return Ok(AdmissionPermit {
                                inner: Arc::clone(&self.inner),
                                demand,
                            });
                        }
                        Err(reason) => (waiter.notify.notified(), reason),
                    }
                } else {
                    (
                        waiter.notify.notified(),
                        "waiting behind earlier queued admission requests".to_owned(),
                    )
                }
            };

            let now = Instant::now();
            if now >= deadline {
                return Err(SandboxError::AdmissionRejected(format!(
                    "admission timed out after {:?}: {reject_reason}",
                    self.inner.limits.admission_queue_timeout
                )));
            }

            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(SandboxError::AdmissionRejected(format!(
                    "admission timed out after {:?}: {reject_reason}",
                    self.inner.limits.admission_queue_timeout
                )));
            }
        }
    }
}

fn notify_head_waiter(state: &AdmissionState) {
    if let Some(head) = state.waiters.front() {
        head.notify.notify_one();
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

    use std::sync::atomic::{AtomicU64, Ordering};

    use sandbox_core::{AccelerationPolicy, IsolationMode, NetworkPolicy, ResourceBudget};

    fn test_spec(
        vcpus: u8,
        cpu_millicores: Option<u32>,
        guest_ram_mb: u32,
        host_rss_mb: Option<u32>,
        host_storage_mb: u32,
    ) -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            budget: ResourceBudget {
                guest_vcpus: vcpus,
                host_cpu_quota_Millicores: cpu_millicores,
                guest_ram_mb,
                host_rss_budget_mb: host_rss_mb,
                virtual_disk_mb: host_storage_mb.min(256),
                host_storage_budget_mb: host_storage_mb,
            },
            lease_ttl: Duration::from_secs(30),
        }
    }

    #[test]
    fn limits_default_and_rejects_zero_caps() {
        let def = AdmissionLimits::default();
        assert_eq!(def.max_concurrent_sandboxes, None);
        assert_eq!(def.max_total_host_rss_mb, None);
        assert_eq!(def.max_total_host_storage_mb, None);
        assert_eq!(def.max_total_host_cpu_millicores, None);
        assert_eq!(def.admission_queue_timeout, Duration::ZERO);
        assert_eq!(def.max_admission_queue_depth, 64);
        assert!(def.validate().is_ok());

        for mut bad in [def.clone(), def.clone(), def.clone(), def] {
            if bad.max_concurrent_sandboxes.is_none() {
                bad.max_concurrent_sandboxes = Some(0);
            }
            assert!(matches!(bad.validate(), Err(SandboxError::InvalidSpec(_))));
        }

        let zero_rss = AdmissionLimits {
            max_total_host_rss_mb: Some(0),
            ..Default::default()
        };
        let zero_storage = AdmissionLimits {
            max_total_host_storage_mb: Some(0),
            ..Default::default()
        };
        let zero_cpu = AdmissionLimits {
            max_total_host_cpu_millicores: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            zero_rss.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            zero_storage.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            zero_cpu.validate(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn zero_timeout_rejects_exhausted_dimensions_and_falls_back_to_guest_floors() {
        // Check floor fallbacks: host_rss_budget_mb=None -> guest_ram_mb; cpu=None -> vcpus*1000.
        let limits = AdmissionLimits {
            max_concurrent_sandboxes: Some(2),
            max_total_host_rss_mb: Some(512),
            max_total_host_storage_mb: Some(1024),
            max_total_host_cpu_millicores: Some(2000),
            admission_queue_timeout: Duration::ZERO,
            max_admission_queue_depth: 8,
        };
        let ctrl = AdmissionController::new(limits, Arc::new(|| 0));
        let p1 = ctrl
            .acquire(&test_spec(1, None, 256, None, 512))
            .await
            .unwrap();
        assert_eq!(
            ctrl.usage(),
            AdmissionUsage {
                active_sandboxes: 1,
                reserved_host_rss_mb: 256,
                effective_host_rss_mb: 256,
                reserved_host_storage_mb: 512,
                reserved_host_cpu_millicores: 1000,
            }
        );

        // Exceeds RSS (256 + 300 > 512)
        assert!(matches!(
            ctrl.acquire(&test_spec(1, Some(500), 256, Some(300), 256))
                .await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        // Exceeds storage (512 + 600 > 1024)
        assert!(matches!(
            ctrl.acquire(&test_spec(1, Some(500), 128, Some(128), 600))
                .await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        // Exceeds CPU (1000 + 1500 > 2000)
        assert!(matches!(
            ctrl.acquire(&test_spec(1, Some(1500), 128, Some(128), 256))
                .await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        let p2 = ctrl
            .acquire(&test_spec(1, Some(1000), 256, Some(256), 512))
            .await
            .unwrap();
        // Exceeds max_concurrent_sandboxes (2)
        assert!(matches!(
            ctrl.acquire(&test_spec(1, Some(1), 1, Some(1), 1)).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        drop(p1);
        drop(p2);
        assert_eq!(ctrl.usage(), AdmissionUsage::default());
    }

    #[tokio::test]
    async fn live_rss_overage_blocks_new_admissions_until_released() {
        let observed_rss = Arc::new(AtomicU64::new(0));
        let observed_ref = Arc::clone(&observed_rss);
        let ctrl = AdmissionController::new(
            AdmissionLimits {
                max_total_host_rss_mb: Some(512),
                ..Default::default()
            },
            Arc::new(move || observed_ref.load(Ordering::Acquire)),
        );

        let p1 = ctrl
            .acquire(&test_spec(1, Some(500), 128, Some(200), 256))
            .await
            .unwrap();
        // Observed live RSS exceeds static 200 MiB reservation -> effective total is 400 MiB.
        observed_rss.store(400, Ordering::Release);
        assert!(matches!(
            ctrl.acquire(&test_spec(1, Some(500), 128, Some(200), 256))
                .await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Once live pressure subsides or permit releases, admission succeeds.
        observed_rss.store(200, Ordering::Release);
        let p2 = ctrl
            .acquire(&test_spec(1, Some(500), 128, Some(200), 256))
            .await
            .unwrap();
        drop(p1);
        drop(p2);
    }

    #[tokio::test]
    async fn fifo_queue_admits_in_order_handles_cancel_timeout_and_depth_cap() {
        let ctrl = AdmissionController::new(
            AdmissionLimits {
                max_concurrent_sandboxes: Some(1),
                admission_queue_timeout: Duration::from_secs(2),
                max_admission_queue_depth: 2,
                ..Default::default()
            },
            Arc::new(|| 0),
        );
        let spec = test_spec(1, Some(500), 128, Some(128), 256);

        let p1 = ctrl.acquire(&spec).await.unwrap();

        // Spawn waiter #1 (will be cancelled while queued) and waiter #2 (should be admitted!).
        let ctrl_w1 = ctrl.clone();
        let spec_w1 = spec.clone();
        let w1 = tokio::spawn(async move { ctrl_w1.acquire(&spec_w1).await });
        tokio::task::yield_now().await;

        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let ctrl_w2 = ctrl.clone();
        let spec_w2 = spec.clone();
        let order_w2 = Arc::clone(&order);
        let w2 = tokio::spawn(async move {
            let p = ctrl_w2.acquire(&spec_w2).await?;
            lock_unpoisoned(&order_w2).push("w2");
            Ok::<_, SandboxError>(p)
        });
        tokio::task::yield_now().await;

        // Queue depth is now 2 (w1 + w2) -> 3rd waiter must immediately fail with AdmissionRejected.
        assert!(matches!(
            ctrl.acquire(&spec).await,
            Err(SandboxError::AdmissionRejected(_))
        ));

        // Cancel w1 while queued; must not stall w2 when p1 releases!
        w1.abort();
        let _ = w1.await;

        // Also queue w3 behind w2; verify strict FIFO ("w2" before "w3").
        let ctrl_w3 = ctrl.clone();
        let spec_w3 = spec.clone();
        let order_w3 = Arc::clone(&order);
        let w3 = tokio::spawn(async move {
            let p = ctrl_w3.acquire(&spec_w3).await?;
            lock_unpoisoned(&order_w3).push("w3");
            Ok::<_, SandboxError>(p)
        });
        tokio::task::yield_now().await;

        drop(p1);
        let p2 = w2.await.unwrap().unwrap();
        tokio::task::yield_now().await;
        // w3 must still be waiting until p2 drops!
        assert_eq!(*lock_unpoisoned(&order), vec!["w2"]);

        drop(p2);
        let p3 = w3.await.unwrap().unwrap();
        assert_eq!(*lock_unpoisoned(&order), vec!["w2", "w3"]);

        // Queue timeout returns AdmissionRejected cleanly and leaves zero usage after drop.
        let ctrl_short = AdmissionController::new(
            AdmissionLimits {
                max_concurrent_sandboxes: Some(1),
                admission_queue_timeout: Duration::from_millis(30),
                max_admission_queue_depth: 4,
                ..Default::default()
            },
            Arc::new(|| 0),
        );
        let hold = ctrl_short.acquire(&spec).await.unwrap();
        assert!(matches!(
            ctrl_short.acquire(&spec).await,
            Err(SandboxError::AdmissionRejected(_))
        ));
        drop(hold);
        drop(p3);
        assert_eq!(ctrl.usage(), AdmissionUsage::default());
        assert_eq!(ctrl_short.usage(), AdmissionUsage::default());
    }

    #[tokio::test]
    async fn background_admission_succeeds_with_headroom_rejects_saturation_and_preempts_for_waiters()
    {
        let ctrl = AdmissionController::new(
            AdmissionLimits {
                max_concurrent_sandboxes: Some(2),
                max_total_host_rss_mb: Some(512),
                max_total_host_storage_mb: Some(1024),
                max_total_host_cpu_millicores: Some(2000),
                admission_queue_timeout: Duration::from_secs(2),
                max_admission_queue_depth: 8,
            },
            Arc::new(|| 0),
        );

        assert!(!ctrl.has_waiters());

        // Individual cap exceeded -> None.
        let oversized = test_spec(1, Some(500), 512, Some(768), 256);
        assert!(ctrl.try_acquire_background(&oversized).is_none());

        // Headroom available and no waiters -> background acquisition succeeds.
        let half_spec = test_spec(1, Some(1000), 256, Some(256), 512);
        let bg1 = ctrl
            .try_acquire_background(&half_spec)
            .expect("background permit 1 should succeed");
        assert_eq!(ctrl.usage().active_sandboxes, 1);

        let bg2 = ctrl
            .try_acquire_background(&half_spec)
            .expect("background permit 2 should succeed");
        assert_eq!(ctrl.usage().active_sandboxes, 2);

        // Saturated by max_concurrent_sandboxes -> None.
        let small_spec = test_spec(1, Some(250), 128, Some(128), 128);
        assert!(ctrl.try_acquire_background(&small_spec).is_none());

        // Free one slot: now 256 MiB RSS remain, so 300 MiB foreground request must queue,
        // while 128 MiB background demand would fit on capacity alone.
        drop(bg2);
        let fg_spec = test_spec(1, Some(500), 256, Some(300), 256);
        let ctrl_fg = ctrl.clone();
        let fg_waiter = tokio::spawn(async move { ctrl_fg.acquire(&fg_spec).await });
        tokio::task::yield_now().await;

        assert!(ctrl.has_waiters());
        assert!(
            ctrl.try_acquire_background(&small_spec).is_none(),
            "foreground FIFO waiter must preempt background replenishment even when small headroom exists"
        );

        // Release bg1; while fg_waiter is still queued in waiters, background acquisition still returns None.
        drop(bg1);
        assert!(ctrl.has_waiters());
        assert!(ctrl.try_acquire_background(&small_spec).is_none());

        let fg_permit = fg_waiter.await.unwrap().unwrap();
        assert!(!ctrl.has_waiters());
        assert_eq!(ctrl.usage().active_sandboxes, 1);
        assert_eq!(ctrl.usage().reserved_host_rss_mb, 300);

        drop(fg_permit);
        let bg3 = ctrl
            .try_acquire_background(&small_spec)
            .expect("background permit should succeed once foreground waiters drain");
        drop(bg3);
        assert_eq!(ctrl.usage(), AdmissionUsage::default());
    }

    #[tokio::test]
    async fn would_exceed_with_tracks_static_and_live_rss_without_enqueuing_waiters() {
        let observed_rss = Arc::new(AtomicU64::new(0));
        let observed_ref = Arc::clone(&observed_rss);
        let ctrl = AdmissionController::new(
            AdmissionLimits {
                max_concurrent_sandboxes: Some(2),
                max_total_host_rss_mb: Some(512),
                max_total_host_storage_mb: Some(1024),
                max_total_host_cpu_millicores: Some(2000),
                admission_queue_timeout: Duration::from_secs(1),
                max_admission_queue_depth: 4,
            },
            Arc::new(move || observed_ref.load(Ordering::Acquire)),
        );

        let spec = test_spec(1, Some(1000), 256, Some(256), 512);
        assert!(!ctrl.would_exceed_with(&spec));
        assert!(!ctrl.has_waiters());

        let p1 = ctrl.acquire(&spec).await.unwrap();
        assert!(!ctrl.would_exceed_with(&spec));

        // Live RSS spike above reserved (400 + 256 > 512) triggers would_exceed_with without queueing.
        observed_rss.store(400, Ordering::Release);
        assert!(ctrl.would_exceed_with(&spec));
        assert!(!ctrl.has_waiters());

        observed_rss.store(256, Ordering::Release);
        let p2 = ctrl.acquire(&spec).await.unwrap();
        // Concurrent sandbox cap (2) reached.
        let tiny = test_spec(1, Some(100), 64, Some(64), 64);
        assert!(ctrl.would_exceed_with(&tiny));
        assert!(!ctrl.has_waiters());

        drop(p1);
        drop(p2);
        assert!(!ctrl.would_exceed_with(&spec));
    }
}
