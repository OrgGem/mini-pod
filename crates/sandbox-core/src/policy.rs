//! Core isolation, network, acceleration, and resource budget policy types.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationMode {
    VmRequired,
    SharedKernelAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccelerationPolicy {
    Required,
    Preferred,
    SoftwareOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRule {
    pub domain: String,
    pub port: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    #[default]
    Isolated,
    InternetOnly,
    DomainAllowList { rules: Vec<EgressRule> },
    Unrestricted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementLevel {
    HardLimit,
    BestEffort,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceBudget {
    pub guest_vcpus: u8,
    #[allow(non_snake_case)]
    pub host_cpu_quota_Millicores: Option<u32>,
    pub guest_ram_mb: u32,
    pub host_rss_budget_mb: Option<u32>,
    pub virtual_disk_mb: u32,
    pub host_storage_budget_mb: u32,
}
