//! Core isolation, network, acceleration, and resource budget policy types.

use std::net::IpAddr;

use crate::error::SandboxError;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

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

/// Validates and normalizes an egress domain pattern (optional `*.` prefix, optional single trailing `.`).
pub fn normalize_egress_domain(domain: &str) -> Result<String, SandboxError> {
    if domain.is_empty() || domain.contains("..") {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid egress domain '{domain}'"
        )));
    }
    if domain.bytes().any(|b| {
        !b.is_ascii()
            || b.is_ascii_whitespace()
            || matches!(b, b'/' | b':' | b'@' | b'[' | b']')
    }) {
        return Err(SandboxError::InvalidSpec(format!(
            "egress domain '{domain}' contains disallowed characters"
        )));
    }

    let trimmed = domain.strip_suffix('.').unwrap_or(domain);
    if trimmed.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "egress domain cannot be empty".to_string(),
        ));
    }

    let (wildcard_prefix, host_part) = match trimmed.strip_prefix("*.") {
        Some(rest) => ("*.", rest),
        None => ("", trimmed),
    };
    if host_part.is_empty() || host_part.contains('*') {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid wildcard placement in egress domain '{domain}'"
        )));
    }
    if host_part.parse::<IpAddr>().is_ok() {
        return Err(SandboxError::InvalidSpec(format!(
            "egress domain '{domain}' cannot be a raw IP literal"
        )));
    }

    let lower = host_part.to_ascii_lowercase();
    let normalized = if wildcard_prefix.is_empty() {
        lower
    } else {
        format!("{wildcard_prefix}{lower}")
    };
    if normalized.len() > MAX_DOMAIN_LEN {
        return Err(SandboxError::InvalidSpec(format!(
            "egress domain '{domain}' exceeds {MAX_DOMAIN_LEN} characters"
        )));
    }

    let host_labels_str = normalized.strip_prefix("*.").unwrap_or(&normalized);
    let mut last_label = "";
    for label in host_labels_str.split('.') {
        if !is_valid_dns_label(label) {
            return Err(SandboxError::InvalidSpec(format!(
                "invalid DNS label '{label}' in egress domain '{domain}'"
            )));
        }
        last_label = label;
    }
    // Reject all-numeric TLDs (e.g. `127.1` or decimal IPv4 forms like `2130706433`).
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SandboxError::InvalidSpec(format!(
            "egress domain '{domain}' cannot end with an all-numeric label"
        )));
    }

    Ok(normalized)
}

/// Returns `true` when concrete `host` satisfies `rule_domain` (`*.example.com` matches subdomains only).
pub fn domain_matches_rule(rule_domain: &str, host: &str) -> bool {
    let Ok(norm_rule) = normalize_egress_domain(rule_domain) else {
        return false;
    };
    let Ok(norm_host) = normalize_egress_domain(host) else {
        return false;
    };
    if norm_host.starts_with("*.") {
        return false;
    }
    if let Some(suffix) = norm_rule.strip_prefix("*.") {
        norm_host.len() > suffix.len()
            && norm_host.ends_with(suffix)
            && norm_host.as_bytes()[norm_host.len() - suffix.len() - 1] == b'.'
    } else {
        norm_host == norm_rule
    }
}

fn is_valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
