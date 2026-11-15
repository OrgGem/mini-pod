//! Execution target, request, and exit status contracts.

use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecTarget {
    Guest,
    Container { id_or_name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecRequest {
    pub target: ExecTarget,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub deadline: Duration,
    pub stdout_budget_bytes: u64,
    pub stderr_budget_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecExitStatus {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}
