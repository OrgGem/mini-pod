//! Domain errors for sandbox lifecycle, policy, and isolation enforcement.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxError {
    InvalidSpec(String),
    UnsupportedIsolationMode(String),
    BinaryExecutionBlocked(String),
    AccelerationUnavailable(String),
    NotFound(String),
    LeaseExpired(String),
    AdmissionRejected(String),
    BudgetExceeded(String),
    PolicyViolation(String),
    Transport(String),
    Internal(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(msg) => write!(f, "invalid sandbox spec: {msg}"),
            Self::UnsupportedIsolationMode(msg) => write!(f, "unsupported isolation mode: {msg}"),
            Self::BinaryExecutionBlocked(msg) => write!(f, "binary execution blocked: {msg}"),
            Self::AccelerationUnavailable(msg) => write!(f, "acceleration unavailable: {msg}"),
            Self::NotFound(msg) => write!(f, "sandbox not found: {msg}"),
            Self::LeaseExpired(msg) => write!(f, "sandbox lease expired: {msg}"),
            Self::AdmissionRejected(msg) => write!(f, "admission rejected: {msg}"),
            Self::BudgetExceeded(msg) => write!(f, "resource budget exceeded: {msg}"),
            Self::PolicyViolation(msg) => write!(f, "policy violation: {msg}"),
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for SandboxError {}
