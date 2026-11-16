#![forbid(unsafe_code)]
//! Domain types, policy contracts, capability reporting, and lifecycle invariants for `mini-pod`.

pub mod arch;
pub mod error;
pub mod exec;
pub mod lifecycle;
pub mod policy;
#[cfg(feature = "safe-tar")]
pub mod safe_tar;

pub use arch::GuestArch;
pub use error::SandboxError;
pub use exec::{ExecExitStatus, ExecRequest, ExecTarget};
pub use lifecycle::{
    CapabilityReport, DestroyStatus, SandboxId, SandboxLease, SandboxSpec, SandboxState,
};
pub use policy::{
    domain_matches_rule, normalize_egress_domain, AccelerationPolicy, EgressRule, EnforcementLevel,
    IsolationMode, NetworkPolicy, ResourceBudget,
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

    #[test]
    fn egress_domain_normalization_accepts_valid_exact_and_wildcards() {
        assert_eq!(normalize_egress_domain("example.com").unwrap(), "example.com");
        assert_eq!(
            normalize_egress_domain("API.Example.COM.").unwrap(),
            "api.example.com"
        );
        assert_eq!(
            normalize_egress_domain("*.Example.ORG.").unwrap(),
            "*.example.org"
        );
        assert_eq!(
            normalize_egress_domain("a-1.b2.localhost").unwrap(),
            "a-1.b2.localhost"
        );

        let label63 = "a".repeat(63);
        assert!(normalize_egress_domain(&format!("{label63}.com")).is_ok());

        // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let max_domain = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(max_domain.len(), 253);
        assert!(normalize_egress_domain(&max_domain).is_ok());
    }

    #[test]
    fn egress_domain_normalization_rejects_invalid_and_ip_literals() {
        let label64 = "a".repeat(64);
        let too_long = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62));
        assert_eq!(too_long.len(), 254);

        let invalid_cases = [
            "",
            ".",
            "..",
            ".example.com",
            "example.com..",
            "a..b.com",
            " example.com",
            "example.com ",
            "exa mple.com",
            "example.com\n",
            "example.com/path",
            "example.com:443",
            "user@example.com",
            "[::1]",
            "::1",
            "127.0.0.1",
            "127.0.0.1.",
            "*.127.0.0.1",
            "127.1",
            "2130706433",
            "*",
            "*.",
            "*..",
            "*.*.example.com",
            "foo*.example.com",
            "api.*.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "bad_name.example.com",
            "bücher.example",
            &format!("{label64}.com"),
            &too_long,
        ];

        for candidate in invalid_cases {
            assert!(
                matches!(
                    normalize_egress_domain(candidate),
                    Err(SandboxError::InvalidSpec(_))
                ),
                "expected '{candidate}' to be rejected"
            );
        }
    }

    #[test]
    fn egress_domain_wildcard_matching_enforces_subdomain_boundaries() {
        assert!(domain_matches_rule("Example.COM.", "example.com"));
        assert!(!domain_matches_rule("example.com", "api.example.com"));

        assert!(domain_matches_rule("*.example.com", "api.example.com"));
        assert!(domain_matches_rule("*.Example.COM.", "A.B.example.com."));
        assert!(!domain_matches_rule("*.example.com", "example.com"));
        assert!(!domain_matches_rule("*.example.com", "evil-example.com"));
        assert!(!domain_matches_rule("*.example.com", "*.example.com"));
        assert!(!domain_matches_rule("*.example.com", "127.0.0.1"));
        assert!(!domain_matches_rule("bad/domain", "bad/domain"));
    }

    #[test]
    fn validate_for_host_os_validates_domain_allow_list_rules() {
        let mut empty_allow_list = valid_spec();
        empty_allow_list.network = NetworkPolicy::DomainAllowList { rules: vec![] };
        assert!(empty_allow_list.validate_for_host_os("linux").is_ok());

        let mut valid_allow_list = valid_spec();
        valid_allow_list.network = NetworkPolicy::DomainAllowList {
            rules: vec![
                EgressRule {
                    domain: "API.Example.COM.".to_string(),
                    port: 443,
                },
                EgressRule {
                    domain: "*.crates.io".to_string(),
                    port: 443,
                },
            ],
        };
        assert!(valid_allow_list.validate_for_host_os("windows").is_ok());

        let mut zero_port = valid_spec();
        zero_port.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "example.com".to_string(),
                port: 0,
            }],
        };
        assert!(matches!(
            zero_port.validate_for_host_os("linux"),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut bad_domain = valid_spec();
        bad_domain.network = NetworkPolicy::DomainAllowList {
            rules: vec![EgressRule {
                domain: "127.0.0.1".to_string(),
                port: 443,
            }],
        };
        assert!(matches!(
            bad_domain.validate_for_host_os("linux"),
            Err(SandboxError::InvalidSpec(_))
        ));
    }
}
