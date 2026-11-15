#![forbid(unsafe_code)]
//! Domain types, policy contracts, capability reporting, and lifecycle invariants for `mini-pod`.

pub mod arch;
pub mod error;
pub mod exec;
pub mod lifecycle;
pub mod policy;

pub use arch::GuestArch;
pub use error::SandboxError;
pub use exec::{ExecExitStatus, ExecRequest, ExecTarget};
pub use lifecycle::{
    CapabilityReport, DestroyStatus, SandboxId, SandboxLease, SandboxSpec, SandboxState,
};
pub use policy::{
    AccelerationPolicy, EgressRule, EnforcementLevel, IsolationMode, NetworkPolicy, ResourceBudget,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_spec() -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::default(),
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: Some(1000),
                guest_ram_mb: 256,
                host_rss_budget_mb: Some(512),
                virtual_disk_mb: 1024,
                host_storage_budget_mb: 2048,
            },
            lease_ttl: Duration::from_secs(60),
        }
    }

    #[test]
    fn default_network_policy_is_isolated() {
        assert_eq!(NetworkPolicy::default(), NetworkPolicy::Isolated);
    }

    #[test]
    fn shared_kernel_allowed_only_on_linux() {
        let mut spec = valid_spec();
        spec.isolation = IsolationMode::SharedKernelAllowed;

        assert!(matches!(
            spec.validate_for_host_os("windows"),
            Err(SandboxError::UnsupportedIsolationMode(_))
        ));
        assert!(matches!(
            spec.validate_for_host_os("macos"),
            Err(SandboxError::UnsupportedIsolationMode(_))
        ));
        assert!(spec.validate_for_host_os("linux").is_ok());
    }

    #[test]
    fn resource_budget_invariants_are_enforced() {
        let mut spec = valid_spec();
        assert!(spec.validate_for_host_os("windows").is_ok());

        spec.budget.host_rss_budget_mb = None;
        assert!(spec.validate_for_host_os("windows").is_ok());

        spec.budget.host_rss_budget_mb = Some(128);
        assert!(matches!(
            spec.validate_for_host_os("windows"),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut zero_vcpu = valid_spec();
        zero_vcpu.budget.guest_vcpus = 0;
        assert!(matches!(
            zero_vcpu.validate_for_host_os("linux"),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut zero_ttl = valid_spec();
        zero_ttl.lease_ttl = Duration::ZERO;
        assert!(matches!(
            zero_ttl.validate_for_host_os("linux"),
            Err(SandboxError::InvalidSpec(_))
        ));
    }
}
