//! Separated 4-metric benchmark data model and Markdown report formatter (`BRD.md` Release Gate #1).
//!
//! Keeps Cold Boot, Warm Checkout, Snapshot Restore (post-MVP), and Container-Ready
//! measurements structurally distinct so warm-pool targets cannot mask cold-boot or
//! container-startup latencies.

use std::fmt::Write as _;
use std::time::Duration;

use sandbox_core::SandboxError;

/// Default p50 target latency in milliseconds for Warm Pool checkout (`BRD.md` Section 4.1 & 6).
pub const DEFAULT_WARM_POOL_TARGET_MS: f64 = 500.0;

/// Standard deferral rationale for Snapshot Restore during MVP (`BRD.md` Section 4.1 & 6).
pub const DEFAULT_SNAPSHOT_DEFERRED_REASON: &str =
    "State/Memory Snapshot deferred post-MVP per BRD.md Section 4.1 & Section 6";

const CATEGORIES: [&str; 4] = [
    "Cold Boot",
    "Warm Checkout",
    "Snapshot Restore",
    "Container-Ready",
];

/// Statistical summary of latency samples in milliseconds.
///
/// Percentiles (`p50_ms`, `p95_ms`) use the deterministic nearest-rank formula on the
/// ascending sorted sample sequence `S` of length `N >= 1`:
/// `index(p) = ceil(p * N) - 1` (0-based), with `p = 0.50` for p50 and `p = 0.95` for p95.
/// `samples_ms` preserves the caller's original measurement order.
#[derive(Clone, Debug, PartialEq)]
pub struct LatencySummary {
    pub samples_ms: Vec<f64>,
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

impl LatencySummary {
    /// Computes a [`LatencySummary`] from [`Duration`] measurements converted to milliseconds.
    pub fn from_durations(durations: &[Duration]) -> Result<Self, SandboxError> {
        let samples_ms: Vec<f64> = durations
            .iter()
            .map(|d| d.as_secs_f64() * 1_000.0)
            .collect();
        Self::from_samples_ms(&samples_ms)
    }

    /// Computes a [`LatencySummary`] from raw millisecond values.
    ///
    /// Rejects empty slices, `NaN`, infinite values, and negative values (`< 0.0`) with
    /// [`SandboxError::InvalidSpec`]. Sorts a copy via [`f64::total_cmp`] and computes
    /// `p50_ms` and `p95_ms` using nearest-rank `ceil(p * N) - 1`.
    pub fn from_samples_ms(samples_ms: &[f64]) -> Result<Self, SandboxError> {
        if samples_ms.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "benchmark latency samples cannot be empty".to_owned(),
            ));
        }

        let mut normalized = Vec::with_capacity(samples_ms.len());
        for (idx, &sample) in samples_ms.iter().enumerate() {
            if !sample.is_finite() || sample < 0.0 {
                return Err(SandboxError::InvalidSpec(format!(
                    "benchmark latency sample at index {idx} must be finite and >= 0.0 ms, got {sample}"
                )));
            }
            // Canonicalize `-0.0` to `+0.0` so display formatting and total_cmp stay clean.
            normalized.push(if sample == 0.0 { 0.0 } else { sample });
        }

        let mut sorted = normalized.clone();
        sorted.sort_by(f64::total_cmp);

        let len = sorted.len();
        let min_ms = sorted[0];
        let max_ms = sorted[len - 1];
        let p50_ms = sorted[nearest_rank_index(len, 50)];
        let p95_ms = sorted[nearest_rank_index(len, 95)];

        let len_f64 = len as f64;
        let sum: f64 = sorted.iter().sum();
        let mean_ms = if sum.is_finite() {
            sum / len_f64
        } else {
            sorted.iter().map(|&v| v / len_f64).sum()
        };

        Ok(Self {
            samples_ms: normalized,
            min_ms,
            p50_ms,
            p95_ms,
            max_ms,
            mean_ms,
        })
    }
}

/// Exact integer nearest-rank index: `ceil((percentile / 100) * len) - 1`.
/// Uses integer division instead of `f64::ceil` so exact multiples like `0.95 * 20` never drift.
fn nearest_rank_index(len: usize, percentile: usize) -> usize {
    let rank = (len as u128 * percentile as u128).div_ceil(100) as usize;
    rank.saturating_sub(1).min(len - 1)
}

/// Measurement status for a single benchmark metric slot.
#[derive(Clone, Debug, PartialEq)]
pub enum BenchmarkMetricStatus {
    Measured(LatencySummary),
    DeferredPostMvp { reason: String },
}

impl BenchmarkMetricStatus {
    /// Builds a [`Self::Measured`] status from [`Duration`] samples.
    pub fn measured_durations(durations: &[Duration]) -> Result<Self, SandboxError> {
        LatencySummary::from_durations(durations).map(Self::Measured)
    }

    /// Builds a [`Self::Measured`] status from raw millisecond samples.
    pub fn measured_samples_ms(samples_ms: &[f64]) -> Result<Self, SandboxError> {
        LatencySummary::from_samples_ms(samples_ms).map(Self::Measured)
    }

    /// Builds a [`Self::DeferredPostMvp`] status with an explicit deferral rationale.
    pub fn deferred_post_mvp(reason: impl Into<String>) -> Self {
        Self::DeferredPostMvp {
            reason: reason.into(),
        }
    }
}

/// Platform benchmark report separating Cold Boot, Warm Checkout, Snapshot Restore,
/// and Container-Ready metrics (`BRD.md` Release Gate #1).
#[derive(Clone, Debug, PartialEq)]
pub struct PlatformBenchmarkReport {
    pub platform: String,
    pub arch: String,
    pub accelerator: String,
    pub warm_pool_target_ms: f64,
    pub cold_boot_spawn: BenchmarkMetricStatus,
    pub cold_boot_first_exec: BenchmarkMetricStatus,
    pub warm_checkout_spawn: BenchmarkMetricStatus,
    pub warm_checkout_first_exec: BenchmarkMetricStatus,
    pub snapshot_restore: BenchmarkMetricStatus,
    pub container_ready_cold_podman: BenchmarkMetricStatus,
    pub container_ready_warm_vm: BenchmarkMetricStatus,
}

struct MetricEntry<'a> {
    name: &'static str,
    category: &'static str,
    status: &'a BenchmarkMetricStatus,
}

impl PlatformBenchmarkReport {
    /// Checks whether `warm_checkout_spawn` p50 meets `warm_pool_target_ms` (`<=`).
    ///
    /// Returns `None` if `warm_checkout_spawn` is [`BenchmarkMetricStatus::DeferredPostMvp`].
    pub fn warm_checkout_within_target(&self) -> Option<bool> {
        match &self.warm_checkout_spawn {
            BenchmarkMetricStatus::Measured(summary) => {
                Some(summary.p50_ms <= self.warm_pool_target_ms)
            }
            BenchmarkMetricStatus::DeferredPostMvp { .. } => None,
        }
    }

    /// Formats the report as a Markdown document with platform header, 4-category table,
    /// Warm Pool target verdict, and per-metric sample/deferral details.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let entries = self.metric_entries();
        let target_verdict = match self.warm_checkout_within_target() {
            Some(true) => "PASS",
            Some(false) => "FAIL",
            None => "DEFERRED",
        };

        let _ = writeln!(out, "# mini-pod Benchmark Report\n");
        let _ = writeln!(out, "- **Platform:** {}", flatten_line(&self.platform));
        let _ = writeln!(out, "- **Arch:** {}", flatten_line(&self.arch));
        let _ = writeln!(
            out,
            "- **Accelerator:** {}",
            flatten_line(&self.accelerator)
        );
        let _ = writeln!(
            out,
            "- **Warm Pool Target (p50):** <= {:.1} ms ({target_verdict})\n",
            self.warm_pool_target_ms
        );

        let _ = writeln!(out, "## Metrics Summary\n");
        let _ = writeln!(
            out,
            "| Metric | Category | Status | n | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |"
        );
        let _ = writeln!(
            out,
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
        );
        for entry in &entries {
            write_table_row(&mut out, entry);
        }

        let _ = writeln!(out, "\n## Separated Metric Details");
        for (idx, &category) in CATEGORIES.iter().enumerate() {
            let _ = writeln!(out, "\n### {}. {category}", idx + 1);
            if category == "Warm Checkout" {
                write_warm_target_note(&mut out, self);
            }
            for entry in entries.iter().filter(|e| e.category == category) {
                write_detail_line(&mut out, entry);
            }
        }

        out
    }

    fn metric_entries(&self) -> [MetricEntry<'_>; 7] {
        [
            MetricEntry {
                name: "cold_boot_spawn",
                category: "Cold Boot",
                status: &self.cold_boot_spawn,
            },
            MetricEntry {
                name: "cold_boot_first_exec",
                category: "Cold Boot",
                status: &self.cold_boot_first_exec,
            },
            MetricEntry {
                name: "warm_checkout_spawn",
                category: "Warm Checkout",
                status: &self.warm_checkout_spawn,
            },
            MetricEntry {
                name: "warm_checkout_first_exec",
                category: "Warm Checkout",
                status: &self.warm_checkout_first_exec,
            },
            MetricEntry {
                name: "snapshot_restore",
                category: "Snapshot Restore",
                status: &self.snapshot_restore,
            },
            MetricEntry {
                name: "container_ready_cold_podman",
                category: "Container-Ready",
                status: &self.container_ready_cold_podman,
            },
            MetricEntry {
                name: "container_ready_warm_vm",
                category: "Container-Ready",
                status: &self.container_ready_warm_vm,
            },
        ]
    }
}

fn write_table_row(out: &mut String, entry: &MetricEntry<'_>) {
    match entry.status {
        BenchmarkMetricStatus::Measured(summary) => {
            let _ = writeln!(
                out,
                "| `{}` | {} | Measured | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} |",
                entry.name,
                entry.category,
                summary.samples_ms.len(),
                summary.min_ms,
                summary.p50_ms,
                summary.p95_ms,
                summary.max_ms,
                summary.mean_ms
            );
        }
        BenchmarkMetricStatus::DeferredPostMvp { .. } => {
            let _ = writeln!(
                out,
                "| `{}` | {} | DeferredPostMvp | - | - | - | - | - | - |",
                entry.name, entry.category
            );
        }
    }
}

fn write_warm_target_note(out: &mut String, report: &PlatformBenchmarkReport) {
    match &report.warm_checkout_spawn {
        BenchmarkMetricStatus::Measured(summary) => {
            let verdict = if summary.p50_ms <= report.warm_pool_target_ms {
                "PASS"
            } else {
                "FAIL"
            };
            let _ = writeln!(
                out,
                "- Target check (`Warm Checkout <= {:.1} ms`): p50 = {:.2} ms -> {verdict}",
                report.warm_pool_target_ms, summary.p50_ms
            );
        }
        BenchmarkMetricStatus::DeferredPostMvp { reason } => {
            let _ = writeln!(
                out,
                "- Target check (`Warm Checkout <= {:.1} ms`): DEFERRED ({})",
                report.warm_pool_target_ms,
                flatten_line(reason)
            );
        }
    }
}

fn write_detail_line(out: &mut String, entry: &MetricEntry<'_>) {
    match entry.status {
        BenchmarkMetricStatus::Measured(summary) => {
            let _ = writeln!(
                out,
                "- `{}`: samples (ms) = {}",
                entry.name,
                format_samples(&summary.samples_ms)
            );
        }
        BenchmarkMetricStatus::DeferredPostMvp { reason } => {
            let _ = writeln!(
                out,
                "- `{}`: **DeferredPostMvp** — {}",
                entry.name,
                flatten_line(reason)
            );
        }
    }
}

fn format_samples(samples_ms: &[f64]) -> String {
    let mut out = String::from("[");
    for (idx, sample) in samples_ms.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{sample:.2}");
    }
    out.push(']');
    out
}

fn flatten_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(warm_p50_ms: f64, warm_deferred: bool) -> PlatformBenchmarkReport {
        let warm_checkout_spawn = if warm_deferred {
            BenchmarkMetricStatus::deferred_post_mvp("temporarily skipped in test")
        } else {
            BenchmarkMetricStatus::measured_samples_ms(&[
                warm_p50_ms - 5.0,
                warm_p50_ms,
                warm_p50_ms + 5.0,
            ])
            .expect("valid warm samples")
        };

        PlatformBenchmarkReport {
            platform: "windows-x86_64".to_owned(),
            arch: "x86_64".to_owned(),
            accelerator: "whpx".to_owned(),
            warm_pool_target_ms: DEFAULT_WARM_POOL_TARGET_MS,
            cold_boot_spawn: BenchmarkMetricStatus::measured_durations(&[
                Duration::from_millis(900),
                Duration::from_millis(1_100),
                Duration::from_millis(1_000),
            ])
            .expect("valid cold boot spawn"),
            cold_boot_first_exec: BenchmarkMetricStatus::measured_durations(&[
                Duration::from_millis(1_050),
                Duration::from_millis(1_250),
                Duration::from_millis(1_150),
            ])
            .expect("valid cold boot first exec"),
            warm_checkout_spawn,
            warm_checkout_first_exec: BenchmarkMetricStatus::measured_durations(&[
                Duration::from_millis(35),
                Duration::from_millis(45),
                Duration::from_millis(55),
            ])
            .expect("valid warm first exec"),
            snapshot_restore: BenchmarkMetricStatus::deferred_post_mvp(
                DEFAULT_SNAPSHOT_DEFERRED_REASON,
            ),
            container_ready_cold_podman: BenchmarkMetricStatus::measured_durations(&[
                Duration::from_millis(2_400),
                Duration::from_millis(2_600),
            ])
            .expect("valid cold container ready"),
            container_ready_warm_vm: BenchmarkMetricStatus::measured_durations(&[
                Duration::from_millis(410),
                Duration::from_millis(490),
            ])
            .expect("valid warm container ready"),
        }
    }

    #[test]
    fn latency_summary_single_sample_and_zero_handling() {
        let single = LatencySummary::from_samples_ms(&[42.5]).expect("single sample valid");
        assert_eq!(single.samples_ms, vec![42.5]);
        assert_eq!(single.min_ms, 42.5);
        assert_eq!(single.p50_ms, 42.5);
        assert_eq!(single.p95_ms, 42.5);
        assert_eq!(single.max_ms, 42.5);
        assert_eq!(single.mean_ms, 42.5);

        let zero = LatencySummary::from_samples_ms(&[-0.0]).expect("-0.0 is valid non-negative");
        assert_eq!(zero.min_ms, 0.0);
        assert!(!zero.min_ms.is_sign_negative());
    }

    #[test]
    fn latency_summary_small_odd_and_even_sets_and_preserves_input_order() {
        // N = 2 (even): p50 index = ceil(1.0) - 1 = 0 (10.0), p95 index = ceil(1.9) - 1 = 1 (20.0)
        let even2 = LatencySummary::from_samples_ms(&[20.0, 10.0]).expect("2 samples");
        assert_eq!(even2.samples_ms, vec![20.0, 10.0]);
        assert_eq!(even2.min_ms, 10.0);
        assert_eq!(even2.p50_ms, 10.0);
        assert_eq!(even2.p95_ms, 20.0);
        assert_eq!(even2.max_ms, 20.0);
        assert_eq!(even2.mean_ms, 15.0);

        // N = 3 (odd): p50 index = ceil(1.5) - 1 = 1 (20.0), p95 index = ceil(2.85) - 1 = 2 (30.0)
        let odd3 = LatencySummary::from_samples_ms(&[30.0, 10.0, 20.0]).expect("3 samples");
        assert_eq!(odd3.min_ms, 10.0);
        assert_eq!(odd3.p50_ms, 20.0);
        assert_eq!(odd3.p95_ms, 30.0);
        assert_eq!(odd3.max_ms, 30.0);
        assert_eq!(odd3.mean_ms, 20.0);

        // N = 4 (even): p50 index = ceil(2.0) - 1 = 1 (20.0), p95 index = ceil(3.8) - 1 = 3 (40.0)
        let even4 = LatencySummary::from_samples_ms(&[40.0, 10.0, 30.0, 20.0]).expect("4 samples");
        assert_eq!(even4.min_ms, 10.0);
        assert_eq!(even4.p50_ms, 20.0);
        assert_eq!(even4.p95_ms, 40.0);
        assert_eq!(even4.max_ms, 40.0);
        assert_eq!(even4.mean_ms, 25.0);
    }

    #[test]
    fn latency_summary_twenty_samples_nearest_rank_math() {
        // Reversed 20..=1 verifies sorting before nearest-rank indexing:
        // N = 20 -> p50 = ceil(0.50 * 20) - 1 = 9 (10.0), p95 = ceil(0.95 * 20) - 1 = 18 (19.0)
        let input: Vec<f64> = (1..=20).rev().map(f64::from).collect();
        let summary = LatencySummary::from_samples_ms(&input).expect("20 samples");
        assert_eq!(summary.samples_ms, input);
        assert_eq!(summary.min_ms, 1.0);
        assert_eq!(summary.p50_ms, 10.0);
        assert_eq!(summary.p95_ms, 19.0);
        assert_eq!(summary.max_ms, 20.0);
        assert_eq!(summary.mean_ms, 10.5);

        let durations: Vec<Duration> = (1..=20).map(Duration::from_millis).collect();
        let from_dur = LatencySummary::from_durations(&durations).expect("20 durations");
        assert_eq!(from_dur.min_ms, 1.0);
        assert_eq!(from_dur.p50_ms, 10.0);
        assert_eq!(from_dur.p95_ms, 19.0);
        assert_eq!(from_dur.max_ms, 20.0);
        assert_eq!(from_dur.mean_ms, 10.5);
    }

    #[test]
    fn latency_summary_rejects_invalid_inputs() {
        assert!(matches!(
            LatencySummary::from_samples_ms(&[]),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            LatencySummary::from_durations(&[]),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            LatencySummary::from_samples_ms(&[1.0, f64::NAN]),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            LatencySummary::from_samples_ms(&[f64::INFINITY]),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            LatencySummary::from_samples_ms(&[f64::NEG_INFINITY]),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            LatencySummary::from_samples_ms(&[-1.0]),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn warm_checkout_within_target_handles_boundary_and_deferred() {
        assert_eq!(
            sample_report(120.0, false).warm_checkout_within_target(),
            Some(true)
        );
        assert_eq!(
            sample_report(500.0, false).warm_checkout_within_target(),
            Some(true)
        );
        assert_eq!(
            sample_report(500.1, false).warm_checkout_within_target(),
            Some(false)
        );
        assert_eq!(
            sample_report(100.0, true).warm_checkout_within_target(),
            None
        );
    }

    #[test]
    fn to_markdown_renders_all_four_metrics_table_and_deferred_note() {
        let pass_report = sample_report(45.0, false);
        let md = pass_report.to_markdown();

        assert!(md.contains("# mini-pod Benchmark Report"));
        assert!(md.contains("windows-x86_64"));
        assert!(md.contains("x86_64"));
        assert!(md.contains("whpx"));
        assert!(md.contains(
            "| Metric | Category | Status | n | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |"
        ));
        assert!(md.contains("Cold Boot"));
        assert!(md.contains("Warm Checkout"));
        assert!(md.contains("Snapshot Restore"));
        assert!(md.contains("Container-Ready"));
        assert!(md.contains("`cold_boot_spawn`"));
        assert!(md.contains("`cold_boot_first_exec`"));
        assert!(md.contains("`warm_checkout_spawn`"));
        assert!(md.contains("`warm_checkout_first_exec`"));
        assert!(md.contains(
            "`snapshot_restore` | Snapshot Restore | DeferredPostMvp | - | - | - | - | - | - |"
        ));
        assert!(md.contains("`container_ready_cold_podman`"));
        assert!(md.contains("`container_ready_warm_vm`"));
        assert!(md.contains("DeferredPostMvp"));
        assert!(md.contains(DEFAULT_SNAPSHOT_DEFERRED_REASON));
        assert!(md.contains("<= 500.0 ms (PASS)"));
        assert!(md.contains("samples (ms) = [900.00, 1100.00, 1000.00]"));

        let fail_md = sample_report(650.0, false).to_markdown();
        assert!(fail_md.contains("<= 500.0 ms (FAIL)"));

        let deferred_warm_md = sample_report(45.0, true).to_markdown();
        assert!(deferred_warm_md.contains("<= 500.0 ms (DEFERRED)"));
    }
}
