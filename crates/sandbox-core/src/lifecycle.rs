//! Sandbox identity, specification invariants, lease, state machine, and destroy status.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::SandboxError;
use crate::policy::{
    normalize_egress_domain, AccelerationPolicy, EnforcementLevel, IsolationMode, NetworkPolicy,
    ResourceBudget,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxId(pub String);

impl SandboxId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxState {
    Creating,
    Ready,
    Active,
    Destroying,
    ProcessExited,
    Cleaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityReport {
    pub cpu_quota: EnforcementLevel,
    pub host_rss: EnforcementLevel,
    pub host_storage: EnforcementLevel,
    pub egress_filter: EnforcementLevel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSpec {
    pub isolation: IsolationMode,
    pub acceleration: AccelerationPolicy,
    pub network: NetworkPolicy,
    pub budget: ResourceBudget,
    pub lease_ttl: Duration,
}

impl SandboxSpec {
    /// Validates domain invariants for the target host OS (`"linux"`, `"windows"`, `"macos"`).
    pub fn validate_for_host_os(&self, host_os: &str) -> Result<(), SandboxError> {
        if self.isolation == IsolationMode::SharedKernelAllowed && host_os != "linux" {
            return Err(SandboxError::UnsupportedIsolationMode(format!(
                "SharedKernelAllowed requires Linux user namespaces; unsupported on {host_os}"
            )));
        }
        if self.budget.guest_vcpus == 0 {
            return Err(SandboxError::InvalidSpec(
                "guest_vcpus must be at least 1".to_string(),
            ));
        }
        if self.budget.guest_ram_mb == 0 {
            return Err(SandboxError::InvalidSpec(
                "guest_ram_mb must be greater than 0".to_string(),
            ));
        }
        if self.budget.virtual_disk_mb == 0 || self.budget.host_storage_budget_mb == 0 {
            return Err(SandboxError::InvalidSpec(
                "virtual_disk_mb and host_storage_budget_mb must be greater than 0".to_string(),
            ));
        }
        if let Some(host_rss_mb) = self.budget.host_rss_budget_mb {
            if host_rss_mb < self.budget.guest_ram_mb {
                return Err(SandboxError::InvalidSpec(
                    "host_rss_budget_mb cannot be smaller than guest_ram_mb".to_string(),
                ));
            }
        }
        if self.lease_ttl.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "lease_ttl must be greater than zero".to_string(),
            ));
        }
        if let NetworkPolicy::DomainAllowList { rules } = &self.network {
            for rule in rules {
                if rule.port == 0 {
                    return Err(SandboxError::InvalidSpec(
                        "egress rule port must be greater than zero".to_string(),
                    ));
                }
                normalize_egress_domain(&rule.domain)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxLease {
    pub id: SandboxId,
    pub ttl: Duration,
    pub capabilities: CapabilityReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestroyStatus {
    ProcessExited { remaining_artifacts: Vec<PathBuf> },
    AllResourcesCleaned,
}
