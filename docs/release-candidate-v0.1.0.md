# mini-pod v0.1.0 — Verification & Security Guide

- **Source snapshot:** tag `v0.1.0`, commit `95b1cb3`
- **Architecture Contract:** [BRD.md](../BRD.md) (`v2.1`, QEMU-First MVP)
- **Primary Reference Benchmark:** [docs/benchmarks/phase6-windows-x86_64.md](benchmarks/phase6-windows-x86_64.md)

The platform and gate results below record the earlier `v0.1.0-rc2` verification, last updated on November 17, 2026. They are historical observations, with platform and fixture scope as listed, and do not establish live-QEMU verification of subsequent changes. As of November 25, 2026, the `v0.1.0` tag [CI run](https://github.com/OrgGem/mini-pod/actions/runs/45361553067) passed its Ubuntu, macOS, Windows, and guest Alpine jobs. The [release workflow](https://github.com/OrgGem/mini-pod/actions/runs/45394844943) built host artifacts and npm packages, while both guest static-musl jobs failed. GitHub Release and npm publish jobs were skipped.

---

## 1. Platform Support Matrix

| Platform / Target | Accelerator / Mode | Verification Status | Verified Scope & Notes |
| --- | --- | --- | --- |
| **Windows `x86_64`** | QEMU + `WHPX` (fallback `TCG`) | **Historically verified (Live QEMU E2E)** | RC live QEMU suite executed on Windows host with `WHPX`: signed bundle verification, exclusive `state.lock`, Win32 Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, CPU/RAM limits, handle whitelist, confined `qemu -accel help` & `qemu-img` helpers), owner-SID Named Pipe DACLs on both `sandboxd` and `DockerCompatServer` (`ERROR_ACCESS_DENIED` to restricted non-owner token), `sandbox-docker-compat` (`bollard` + `testcontainers` + Ryuk), `HostEgressProxy`, Warm Pool + 4-metric benchmark, `sandboxd` + `sandbox-cli` + `mcp` + crash-recovery drill. |
| **Linux `x86_64`** | QEMU + `KVM` (fallback `TCG`) | **Partially verified (Container musl + Unit/IPC)** | Cross-compiled & tested in pinned `rust:alpine` musl container: guest `tiny-init` / `sandbox-agent`, per-exec cgroup v2 `cgroup.kill` + `setsid` containment, `0700`/`0600` Unix socket ownership on control & Docker IPC, root `fork` + `setuid(65534)` kernel `EACCES` check (`CrossUserIpcCheck::KernelRejectedAccess`), cgroup v2 & `/proc/<pid>/stat` parser tests. Live Linux `KVM` boot was **not** executed on this Windows host. |
| **Linux `aarch64`** | QEMU + `KVM` / `TCG` | **Verified (Bundle + Cross-Arch QEMU TCG Boot)** | Reproducible signed `aarch64` Portable Runtime Bundle built via `scripts/build-portable-bundles.ps1` and booted end-to-end under `qemu-system-aarch64` (`-accel tcg`) in Phase 2 (`signed_bundle_atomic_install_cow_overlay_and_boot_x86_64_and_aarch64`). Live ARM64 KVM host tests not run on this Windows host. |
| **macOS (`x86_64` / `aarch64`)** | QEMU + `HVF` (fallback `TCG`) | **Unexecuted on Host (Code Paths Implemented)** | Unix `0700`/`0600` IPC, `proc_pidinfo(PROC_PIDTBSDINFO)` microsecond `start_token` verification (`expected_start_token == 0` rejected), `setpgid(0, 0)` process-group confinement, and `-accel hvf` -> `-accel tcg` selection are implemented; live execution on macOS hardware was **not** performed. |
| **Windows `ARM64`** | — | **Deferred Post-MVP** | Explicitly out of scope for MVP (`BRD.md` Section 4.2 & Section 6). |

---

## 2. Explicit Security Guarantees & Honest Limits

### 2.1 Isolation Boundary (`IsolationMode`)
- **`VmRequired` never degrades to `SharedKernelAllowed`:** If hardware acceleration (`KVM`/`HVF`/`WHPX`) is unavailable and `AccelerationPolicy::Preferred` is set, `QemuVmDriver` falls back strictly to QEMU `TCG` (same guest-kernel VM isolation). It **never** falls back to Rootless Podman (`userns`).
- **`SharedKernelAllowed` is unsupported by the QEMU driver:** `SandboxSpec::validate_for_host_os` rejects it on Windows and macOS, and `QemuVmDriver` rejects it on all hosts with `SandboxError::UnsupportedIsolationMode`.
- **Windows Enterprise Lockdown (AppLocker / WDAC / EDR):** If host security policy blocks launching `qemu-system-*` or `qemu-img`, `classify_launch_error` surfaces `SandboxError::BinaryExecutionBlocked` with a diagnostic message rather than attempting workarounds.

### 2.2 Local Control & Docker Compatibility IPC Authentication
- **Owner-only OS IPC across both `sandboxd` and `DockerCompatServer`:**
  - **Windows:** Both `sandboxd` control listeners and `enable_docker_compat` (`npipe:////./pipe/minipod-docker-...`) bind Named Pipes with `PIPE_REJECT_REMOTE_CLIENTS` and a protected owner-only DACL `D:P(A;;GA;;;{USER_SID})` (`create_owner_only_async_named_pipe`), verified by `verify_non_owner_named_pipe_denied` against a restricted token with the owner SID disabled (`ERROR_ACCESS_DENIED`).
  - **Unix:** Both `sandboxd` control listeners and `enable_docker_compat` (`unix:///...`) bind `AF_UNIX` sockets with `0600` mode inside an owner-only non-symlink `0700` directory (`ensure_owner_only_dir`), verified against non-owner UIDs (`65534:65534`) via `verify_non_owner_unix_socket_denied` (`EACCES`).
- **No Unauthenticated Loopback Docker Listener & Hardened Policy Gate:** `DockerCompatServer` does not expose unauthenticated TCP in non-test builds, blocks Podman-native `/libpod/*` endpoints (`403 Forbidden`), canonicalizes duplicate slashes and percent-encoded segments (`//containers//%63reate`), rejects duplicate or case-colliding JSON keys (`"hostconfig"`, `"binds"`, `"privileged"`), and rejects host bind mounts, `Devices`, `DeviceCgroupRules`, `CapAdd`, and `SecurityOpt=unconfined`/`disable`.
- **Plaintext Network Control Rejected:** `ControlEndpoint::parse`, `sandboxd` (`--tcp`, `--endpoint`), and `sandbox-cli` (`--endpoint`) reject `tcp://`, `http://`, `https://`, `ws://`, `wss://`, `tls://`, and remote UNC pipe paths (`\\server\pipe\...`) with `SandboxError::PolicyViolation`.

### 2.3 Host Egress Proxy & Anti-DNS-Rebinding (`NetworkPolicy`)
- **`Isolated` (default):** Guest VM boots with `-nic none` (only `lo`, no external network interface or routes).
- **`InternetOnly` / `DomainAllowList`:** Guest boots with `-nic none`; all container/guest HTTP/HTTPS traffic is forced over `virtio-serial` through `HostEgressProxy` with bounded concurrency (`64` concurrent guest egress streams), a `15s` request-head timeout, a `10s` upstream TCP dial timeout, and a `120s` idle relay timeout. Direct guest DNS queries and raw UDP/QUIC egress are impossible.
- **Anti-Rebinding & IP Filtering (`crates/sandbox-runtime/src/egress.rs`):**
  - Blocks private/special IPv4 ranges (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, multicast/reserved) and IPv6 ranges (`::/128`, `::1/128`, `::ffff:0:0/96` IPv4-mapped, `64:ff9b::/96` NAT64, `2002::/16` 6to4, `2001::/32` Teredo, `fc00::/7` ULA, `fe80::/10` link-local, `ff00::/8` multicast).
  - Resolves DNS exclusively on the Host, checks every returned IP against `is_forbidden_ip`, dials TCP **directly to the verified IP** (never re-resolving on connect), and re-validates every HTTP `3xx` redirect target.
- **Honest Limit (No TLS MITM Inspection):** `HostEgressProxy` tunnels HTTPS via `HTTP CONNECT` without decrypting TLS payloads. If an operator allowlists a domain that hosts arbitrary uploads, webhooks, or tunneling APIs, `DomainAllowList` enforces destination domain/port and IP safety but cannot inspect encrypted request bodies inside the TLS session.

### 2.4 Safe Tar Workspace Copy I/O & Supply Chain
- **Safe Tar (`sandbox-runtime/src/safe_tar.rs`, `sandbox-client/src/safe_tar.rs`, `guest/sandbox-agent/src/copy_tar.rs`):** Rejects `..` path traversal, absolute paths, Windows drive prefixes and reserved device names (`CON`, `NUL`, `COM1`, etc.), symlinks, hardlinks, FIFOs/devices, and Windows reparse points/junctions (`0x0400`), enforcing byte and entry budgets (`max_copy_bytes`, `max_copy_entries`). Every extracted file is staged into a fresh `create_new(true)` sibling temporary file (`.minipod-tmp-*`) and atomically renamed into place only after full payload validation, preventing NTFS hardlink write-through and truncated-archive data loss.
- **Signed Portable Runtime Bundles (`crates/sandbox-image`):** Verifies Ed25519 signature (`verify_strict` over raw `manifest.v1` bytes **before** UTF-8 decoding or parsing), validates directory hygiene (rejects symlinks, reparse points, hardlinks, and any undeclared extra files such as sideloaded DLLs), verifies SHA-256 + byte lengths, and promotes bundles via crash-safe `.promote-<id>.v1` journals and shared reader locks.
  - *Bundle & Test Fixture Scope:* `scripts/build-portable-bundles.ps1` packages and Ed25519-signs the reproducible Linux guest artifacts (`kernel/vmlinuz-virt`, `boot/initramfs.cpio.gz`, `rootfs/base.qcow2`, `bin/tiny-init`, `bin/sandbox-agent`), while host `qemu-system-*` and `qemu-img` binaries are discovered from operator-installed host paths (or explicit `--qemu-bin`/`--qemu-img-bin`) and executed strictly inside Win32 Job Object confinement (`ConfinedProcess` / `run_confined_command_bounded`). Repository dev fixtures (`.cache/bundles-src/*`) are signed with `.cache/keys/dev-bundle.key` (`--pub-key-file .cache/keys/dev-bundle.pub`), and `scripts/build-test-oci-images.ps1` builds a minimal offline Ryuk protocol-compatible reaper image (`testcontainers/ryuk:0.11.0`) for air-gapped `Isolated` VM E2E testing.

### 2.5 Resource Accounting & `EnforcementLevel` Matrix (`CapabilityReport`)

| Capability | Windows (`x86_64`) | Linux | macOS | Notes |
| --- | --- | --- | --- | --- |
| `cpu_quota` | `HardLimit` when `host_cpu_quota_Millicores` set (Job Object `CpuRateControlInformation`), else `BestEffort` | `HardLimit` when delegated cgroup v2 `cpu.max` writable; `Unsupported` if set without delegation; `BestEffort` if unset | `Unsupported` if set, else `BestEffort` | `LocalRuntimeManager` never claims `HardLimit` when OS enforcement is unavailable. |
| `host_rss` | `HardLimit` when `host_rss_budget_mb` set (`JOB_OBJECT_LIMIT_JOB_MEMORY`), else `BestEffort` | `HardLimit` when delegated cgroup v2 `memory.max` writable; `Unsupported` if set without delegation; `BestEffort` if unset | `Unsupported` if set, else `BestEffort` | Combined with `AdmissionController` host RSS reservations + `WorkingSetSize` / `/proc/<pid>/statm` sampling; never relies on guest ballooning. |
| `host_storage` | `BestEffort` | `BestEffort` | `BestEffort` | Guest virtual disk (`virtual_disk_mb`) is fixed at ext4/qcow2 creation and QEMU `qemu-stderr.log` is capped at `512 KiB`, while physical `sandboxes/<id>` directory accounting runs on `spawn`, `copy_in`, and periodic budget sweeps rather than synchronous OS filesystem quotas. |
| `egress_filter` | `HardLimit` (`Isolated`, `InternetOnly`, `DomainAllowList`); `Unsupported` (`Unrestricted`) | Same | Same | Guest runs with `-nic none`; non-isolated traffic traverses `HostEgressProxy`. |

### 2.6 Post-MVP Deferrals (`BRD.md` Section 4.1, 4.2, 6)
The following capabilities are **intentionally deferred post-MVP** in the `v0.1.0` source:
1. External VM State/Memory Snapshot restore (`snapshot_restore` = `DeferredPostMvp`; QEMU `savevm`/`loadvm` across CoW overlays is explicitly rejected).
2. Native macOS `Virtualization.framework` / `vmnet` backend.
3. Windows `ARM64` host builds.
4. Bidirectional real-time host/guest Live Mount (MVP uses explicit `CopyIn` -> `Exec` -> `CopyOut`).
5. Full BuildKit parity.
6. The `< 500 ms` target applies strictly to **Warm Pool checkout** (`3.50 ms` p50 measured), not to Cold Boot (`2092.41 ms` p50).

---

## 3. Historical BRD 7 Release Gates Verification Matrix

The PASS entries preserve the RC observations described above. Re-run the applicable gates against the intended build and host before relying on them for a new release.

| Gate | Requirement (`BRD.md` Section 6) | Verification Evidence (Files & Test Cases) | Observed Result |
| --- | --- | --- | --- |
| **Gate 1** | Separated 4-metric benchmark (`cold boot`, `warm checkout`, `snapshot restore`, `container-ready`) | [phase6_warm_pool_and_bench_e2e.rs](../crates/sandbox-vmm/tests/phase6_warm_pool_and_bench_e2e.rs) (`e2e_separated_four_metric_benchmark_cold_warm_snapshot_container_ready`); [phase6-windows-x86_64.md](benchmarks/phase6-windows-x86_64.md) | **PASS** — `cold_boot_spawn`: `2092.41 ms` p50 (`first_exec`: `1.45 ms`); `warm_checkout_spawn`: `3.50 ms` p50 (`<= 500.0 ms`, `first_exec`: `1.57 ms`); `container_ready_cold_podman`: `3801.77 ms` p50; `container_ready_warm_vm`: `120.90 ms` p50; `snapshot_restore`: `DeferredPostMvp`. |
| **Gate 2** | Warm Pool exhaustion admission/backpressure keeps Host RSS below ceiling | [phase6_warm_pool_and_bench_e2e.rs](../crates/sandbox-vmm/tests/phase6_warm_pool_and_bench_e2e.rs) (`e2e_warm_pool_overload_backpressure_dirty_disposal_and_rss_cap`); [phase5_egress_and_resources_e2e.rs](../crates/sandbox-vmm/tests/phase5_egress_and_resources_e2e.rs) (`e2e_admission_control_os_resource_caps_and_capability_report`) | **PASS** — Foreground callers prioritized over background replenisher; dirty VM disposal enforced; total Host RSS held strictly below configured cap. |
| **Gate 3** | `SIGKILL` / `TerminateProcess` mid-spawn or mid-destroy leaves zero orphan QEMU processes or disk files after reconciliation | [phase7_rc_drill_and_ipc_e2e.rs](../bins/sandboxd/tests/phase7_rc_drill_and_ipc_e2e.rs) (`e2e_rc_daemon_sdk_cli_mcp_and_incident_recovery_drill`); [phase3_runtime_e2e.rs](../crates/sandbox-vmm/tests/phase3_runtime_e2e.rs) (`e2e_crash_recovery_orphan_kill_and_cleanup`) | **PASS** — Abrupt `daemon1.kill()` leaves `.journal` + `overlay.qcow2`; `sandboxd` #2 startup reconciler clears all leftover sandboxes/overlays/journals and confirms zero live orphan PIDs. |
| **Gate 4** | Second OS account immediately denied by OS kernel when connecting to control Named Pipe or Unix socket | [phase7_rc_drill_and_ipc_e2e.rs](../bins/sandboxd/tests/phase7_rc_drill_and_ipc_e2e.rs) (`e2e_gate4_second_os_user_denied_access_to_control_ipc`); [ipc.rs](../crates/sandbox-vmm/src/ipc.rs) (`verify_non_owner_named_pipe_denied`, `verify_non_owner_unix_socket_denied`); [spike_e2e.rs](../crates/sandbox-vmm/tests/spike_e2e.rs) (`ipc_endpoint_enforces_owner_only_permissions`) | **PASS** — Windows NT kernel returns `ERROR_ACCESS_DENIED (5)` to restricted non-owner token against live `sandboxd` Named Pipe; Unix `0700`/`0600` + `fork`/`setuid(65534)` returns `EACCES` under root container verification. |
| **Gate 5** | Automated security tests block DNS rebinding, private/mapped IPv6, and tar traversal/symlinks/reparse points | [phase5_egress_and_resources_e2e.rs](../crates/sandbox-vmm/tests/phase5_egress_and_resources_e2e.rs) (`e2e_egress_proxy_blocks_private_ips_ipv6_mapped_dns_rebinding_and_redirects`); [phase3_runtime_e2e.rs](../crates/sandbox-vmm/tests/phase3_runtime_e2e.rs) (`e2e_safe_copy_in_exec_copy_out_and_reject_guest_symlink`); `safe_tar.rs` tests | **PASS** — Blocks RFC1918, loopback, metadata IP, `::ffff:127.0.0.1`, DNS rebinding flips, `3xx` redirects to internal targets, `..`, symlinks, and Windows junctions. |
| **Gate 6** | Testcontainers full lifecycle (pull/import, port forward to Host, logs, exec hijack, Ryuk cleanup) | [phase4_docker_compat_e2e.rs](../crates/sandbox-vmm/tests/phase4_docker_compat_e2e.rs) (`e2e_testcontainers_full_lifecycle_and_ryuk_reaper`, `e2e_bollard_sdk_lifecycle_port_forward_hijack_archive_and_policy`) | **PASS** — Offline OCI `echo-http` + `ryuk` containers boot via `sandbox-docker-compat`, map HTTP ports to loopback, serve `200 OK`, reject raw host bind mounts (`400`), and clean up via Ryuk. |
| **Gate 7** | Disk fill and runaway `stdout`/`stderr` floods terminate within budget and release temporary storage | [phase3_runtime_e2e.rs](../crates/sandbox-vmm/tests/phase3_runtime_e2e.rs) (`e2e_stdout_budget_deadline_priority_cancel_and_disk_cap`, `e2e_ttl_lease_renewal_and_automatic_expiry`) | **PASS** — Guest supervisor kills runaway process group/cgroup at `stdout_budget_bytes` / `deadline` and on priority `ExecCancel`; guest disk write stops at `ENOSPC` within `host_storage_budget_mb`; `destroy` reclaims overlay. |

### Changes after the recorded RC checks

The current source includes the following fixes, with regression tests alongside the affected implementation. The historical live-QEMU results above predate these changes.

- **Compose safety:** `up` verifies a container's Compose project and service labels before deleting the inspected container ID. `down` filters by project labels, removes networks by ID, continues independent cleanup after failures, and returns an error for failed cleanup. See [Compose implementation and tests](../bins/sandbox-cli/src/compose.rs).
- **Lifecycle and RSS:** sandbox IDs use random values. Docker endpoint names include the sandbox identity. Admission accounts for transient and stopping VM RSS across warm-pool and active transitions. Failed cleanup is surfaced through `DestroyStatus`. See [runtime manager](../crates/sandbox-runtime/src/manager.rs), [admission controller](../crates/sandbox-runtime/src/admission.rs), and [daemon server](../bins/sandboxd/src/server.rs).
- **Unix orphan recovery:** the reconciler verifies the recorded PID and process start token. After signaling a matching orphan it waits for exit. If the process check errors or the exit wait times out, the journal is retained for later recovery and artifact cleanup is deferred. See [Unix process handling](../crates/sandbox-vmm/src/os/unix.rs) and [startup reconciliation](../crates/sandbox-runtime/src/manager.rs).
- **Exec and transport:** the client can await exit again after a pending `wait_exit()` is cancelled. While waiting, unread output is discarded to keep the bounded queue moving. Cancellation, stream credits, shutdown, and CopyOut timeout handling were hardened. See [client stream](../crates/sandbox-client/src/client.rs), [runtime stream](../crates/sandbox-runtime/src/exec_stream.rs), and [VMM driver](../crates/sandbox-vmm/src/driver.rs).
- **Bundle promotion and files:** warm-up admission handoff and bundle swap reader tests were made deterministic. Bundle installation uses reader locks and promotion journals. Image export creates a new temporary archive and retries name collisions without deleting pre-existing files. See [bundle installer](../crates/sandbox-image/src/installer.rs) and [image build](../bins/sandbox-cli/src/image_build.rs).
- **Docker API and launchers:** the adapter restricts Docker query parameters and tmpfs options. The npm launcher handles Windows signals. See [Docker adapter](../crates/sandbox-docker-compat/src/server.rs) and [npm launcher](../npm/launcher.js).

---

## 4. Quickstart Examples

### 4.1 Run `sandboxd serve` (Local Control Daemon)

Using a signed bundle (for dev fixtures generated via `scripts/build-portable-bundles.ps1`):

```powershell
# Windows (owner-only Named Pipe default: \\.\pipe\minipod-sandboxd-<USERNAME>)
cargo run -p sandboxd -- serve `
  --bundle-dir .cache\bundles-src\x86_64 `
  --pub-key-file .cache\keys\dev-bundle.pub `
  --state-dir $env:LOCALAPPDATA\minipod\state `
  --warm-pool-size 1 `
  --max-rss-mb 2048
```

```bash
# Linux / macOS (owner-only Unix socket default in $XDG_RUNTIME_DIR/minipod/ctl.sock or /tmp/minipod-<uid>/ctl.sock)
cargo run -p sandboxd -- serve \
  --bundle-dir .cache/bundles-src/x86_64 \
  --pub-key-file .cache/keys/dev-bundle.pub \
  --state-dir ~/.local/state/minipod \
  --warm-pool-size 1 \
  --max-rss-mb 2048
```

> Plain `--tcp` or `--endpoint tcp://...` is unconditionally rejected with `PolicyViolation`.

### 4.2 Interact via `sandbox-cli`

```powershell
# Query daemon counters and check configured binaries, bundle, and accelerators
sandbox-cli --json status
sandbox-cli --json doctor
# Optional live guest execution and cleanup check
sandbox-cli --json doctor --smoke

# One-shot execution with automatic cleanup attempt
sandbox-cli --json run -- /bin/uname -a

# Spawn an isolated VM (matching warm pool defaults: 1 vCPU, 256 MiB RAM, 512 MiB RSS cap, 512 MiB disk)
sandbox-cli --json spawn --rss-mb 512 --ttl-secs 300

# Copy workspace in, execute command, copy results out
sandbox-cli copy-in <SANDBOX_ID> .\workspace /tmp/work
sandbox-cli exec <SANDBOX_ID> -- /bin/sh -c "ls -la /tmp/work"
sandbox-cli copy-out <SANDBOX_ID> /tmp/work .\out

# Enable owner-only Docker-compatible IPC endpoint (`npipe://` on Windows, `unix://` on Unix)
sandbox-cli docker-endpoint <SANDBOX_ID>

# Idempotent cleanup
sandbox-cli destroy <SANDBOX_ID>
```

`doctor --smoke` can use a warm VM. Inspect its reported accelerator, workload, and cleanup fields. A `run` report separates workload, copy-out, and cleanup, and can report an unknown cleanup outcome when the ID was never received. Use an explicit `spawn` workflow when several commands must share a sandbox.

### 4.3 Run MCP Server (`sandboxd mcp`)

Connected mode (talking to a running `sandboxd serve` instance) or standalone mode:

```json
{
  "mcpServers": {
    "mini-pod": {
      "command": "sandboxd",
      "args": [
        "mcp",
        "--bundle-dir", "/path/to/signed-bundle",
        "--pub-key-file", "/path/to/bundle.pub",
        "--warm-pool-size", "1"
      ]
    }
  }
}
```

Exposed MCP tools over newline-delimited JSON-RPC 2.0 `stdio` (`stdout` carries strictly JSON-RPC frames):
- `sandbox_status`
- `sandbox_spawn`
- `sandbox_exec`
- `sandbox_renew_lease`
- `sandbox_copy_in`
- `sandbox_copy_out`
- `sandbox_destroy`

### 4.4 Embed via `SandboxClient` Rust SDK

```rust
use std::collections::BTreeMap;
use std::time::Duration;
use sandbox_client::{ControlEndpoint, SandboxClient};
use sandbox_core::{
    AccelerationPolicy, ExecRequest, ExecTarget, IsolationMode, NetworkPolicy, ResourceBudget,
    SandboxSpec,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set MINIPOD_ENDPOINT to the running daemon's local pipe or socket URI.
    let endpoint = ControlEndpoint::parse(&std::env::var("MINIPOD_ENDPOINT")?)?;
    let client = SandboxClient::new(endpoint);

    let lease = client.spawn(SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: ResourceBudget {
            guest_vcpus: 1,
            host_cpu_quota_Millicores: None,
            guest_ram_mb: 256,
            host_rss_budget_mb: Some(512),
            virtual_disk_mb: 512,
            host_storage_budget_mb: 1024,
        },
        lease_ttl: Duration::from_secs(300),
    }).await?;

    let out = client.exec_collect(&lease.id, ExecRequest {
        target: ExecTarget::Guest,
        argv: vec!["/bin/echo".into(), "hello from mini-pod".into()],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline: Duration::from_secs(10),
        stdout_budget_bytes: 256 * 1024,
        stderr_budget_bytes: 64 * 1024,
    }).await?;
    println!("{}", String::from_utf8_lossy(&out.stdout));

    client.destroy(&lease.id).await?;
    Ok(())
}
```
