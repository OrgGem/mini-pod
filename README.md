# mini-pod

Unprivileged, QEMU-first micro-VM sandbox runtime in Rust with signed Portable Runtime Bundles, owner-only local IPC, an anti-rebinding Host Egress Proxy, an embedded Podman/Docker API compatibility adapter, a Warm Pool, CLI, MCP server, and lightweight async SDK.

- **Specification & Architecture Contract:** [BRD.md](BRD.md) (`v2.1`)
- **Engineering & Security Invariants:** [AGENTS.md](AGENTS.md)
- **Release Candidate Notes & Support Matrix:** [docs/release-candidate-v0.1.0.md](docs/release-candidate-v0.1.0.md)
- **Measured Benchmark Report:** [docs/benchmarks/phase6-windows-x86_64.md](docs/benchmarks/phase6-windows-x86_64.md)

---

## Architecture (4-Layer Clean Workspace)

Dependency arrows point strictly inward from outer composition roots toward domain types and framing:

```text
Layer 4 (Composition Roots):   bins/sandboxd  |  bins/sandbox-cli
                                      |                   |
                                      v                   v
Layer 3 (Adapters & SDK):      sandbox-docker-compat | sandbox-vmm | sandbox-image | sandbox-client
                                      \                     |             /
                                       +--------------------+------------+
                                                            v
Layer 2 (Use Cases):                                 sandbox-runtime
                                                            |
                                                            v
Layer 1 (Domain & Framing):                    sandbox-core + sandbox-protocol

Guest Binaries (Linux static musl):            guest/tiny-init (PID 1) | guest/sandbox-agent
```

| Crate / Binary | Layer | Responsibility |
| --- | --- | --- |
| [`crates/sandbox-core`](crates/sandbox-core) | 1 | Domain policies (`IsolationMode`, `AccelerationPolicy`, `NetworkPolicy`, `EnforcementLevel`, `ResourceBudget`), `SandboxSpec` validation, `SandboxError`. |
| [`crates/sandbox-protocol`](crates/sandbox-protocol) | 1 | Length-bounded binary framing, handshake negotiation, prioritized control vs. data lanes, and credit-based backpressure. |
| [`crates/sandbox-runtime`](crates/sandbox-runtime) | 2 | `RuntimeManager` (`LocalRuntimeManager`): lifecycle, admission control, TTL lease sweeper, crash journal & startup reconciler, Warm Pool, safe tar I/O, and `HostEgressProxy`. |
| [`crates/sandbox-vmm`](crates/sandbox-vmm) | 3 | Cross-OS QEMU driver (`KVM`/`HVF`/`WHPX` -> `TCG`, never falling back to `SharedKernelAllowed`), Windows Job Object confinement, Unix `setpgid`/cgroup v2, owner-only IPC (`virtio-serial`). |
| [`crates/sandbox-image`](crates/sandbox-image) | 3 | Ed25519 manifest signature verification, SHA-256 + anti-tamper tree validation, atomic bundle swap, `qemu-img` CoW QCOW2 overlays, and `bundle-pack` signer CLI. |
| [`crates/sandbox-docker-compat`](crates/sandbox-docker-compat) | 3 | Owner-only IPC (`npipe://` Named Pipe on Windows, `unix://` `0600` socket on Unix) HTTP/1.1 Docker Engine compatibility adapter (`bollard` / `testcontainers` + Ryuk), host port forwarding over virtio, HTTP hijack & half-close, URL/JSON canonicalization, `/libpod/*` block, and raw host bind-mount rejection. |
| [`crates/sandbox-client`](crates/sandbox-client) | Adapter | Lightweight async `SandboxClient` SDK + `ControlEndpoint` parser + client-side safe tar packing/extraction (no daemon/QEMU/MCP deps). |
| [`bins/sandboxd`](bins/sandboxd) | 4 | Local daemon (`serve`) over owner-only Named Pipe / Unix socket and JSON-RPC 2.0 `stdio` MCP server (`mcp`). |
| [`bins/sandbox-cli`](bins/sandbox-cli) | 4 | CLI client (`status`, `spawn`, `exec`, `renew`, `copy-in`, `copy-out`, `docker-endpoint`, `destroy`). |
| [`guest/tiny-init`](guest/tiny-init) & [`guest/sandbox-agent`](guest/sandbox-agent) | Guest | PID 1 read-only rootfs + overlay setup, zombie reaping, execution supervisor (per-exec cgroup v2 `cgroup.kill` + container exec process-tree termination on deadline or output budget), and Podman Unix socket relay. |

---

## Prerequisites

- **Rust toolchain:** Rust `1.89+` (`rustfmt`, `cargo`)
- **QEMU:** `qemu-system-x86_64` (plus `qemu-system-aarch64` for cross-arch bundle test) and `qemu-img` on `PATH` (or in standard Windows `Program Files\qemu` / `%LOCALAPPDATA%\Programs\qemu`)
- **Docker (optional, for rebuilding reproducible guest bundles & offline OCI test images):** Linux container runtime supporting `linux/amd64` and `linux/arm64`

---

## Build & Test Commands

### Fast Compile & Unit/Component Tests (No QEMU Required)

```powershell
# Compile all workspace targets
cargo check --all-targets

# Run workspace unit + non-QEMU tests (QEMU-backed E2E tests skip cleanly unless MINIPOD_REQUIRE_QEMU_TESTS=1)
cargo test --workspace
```

### Build Signed Portable Runtime Bundles & Run Full QEMU E2E Suite

```powershell
# 1. Build reproducible signed x86_64 & aarch64 bundles (.cache/bundles-src + .cache/keys/dev-bundle.pub)
powershell -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1

# 2. Build offline OCI test images for Docker compat / Testcontainers E2E (.cache/test-images)
powershell -ExecutionPolicy Bypass -File scripts/build-test-oci-images.ps1

# 3. Run full workspace tests requiring live QEMU + WHPX/KVM/TCG
$env:MINIPOD_REQUIRE_QEMU_TESTS = "1"
cargo test --workspace
```

---

## Benchmark Summary (`windows-x86_64`, `whpx`)

Measured by `crates/sandbox-vmm/tests/phase6_warm_pool_and_bench_e2e.rs` and recorded in [docs/benchmarks/phase6-windows-x86_64.md](docs/benchmarks/phase6-windows-x86_64.md):

| Metric | Category | Status | n | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cold_boot_spawn` | Cold Boot | Measured | 3 | 2011.93 | 2092.41 | 2115.95 | 2115.95 | 2073.43 |
| `cold_boot_first_exec` | Cold Boot | Measured | 3 | 1.27 | 1.45 | 1.47 | 1.47 | 1.40 |
| `warm_checkout_spawn` | Warm Checkout | Measured | 3 | 3.05 | **3.50** | 4.08 | 4.08 | 3.54 |
| `warm_checkout_first_exec` | Warm Checkout | Measured | 3 | 1.40 | 1.57 | 1.65 | 1.65 | 1.54 |
| `snapshot_restore` | Snapshot Restore | `DeferredPostMvp` | - | - | - | - | - | - |
| `container_ready_cold_podman` | Container-Ready | Measured | 3 | 3800.39 | 3801.77 | 4063.79 | 4063.79 | 3888.65 |
| `container_ready_warm_vm` | Container-Ready | Measured | 3 | 120.33 | 120.90 | 124.18 | 124.18 | 121.81 |

Warm Pool Checkout (`3.50 ms` p50) meets the `<= 500.0 ms` Warm Pool target. Cold Boot (`2092.41 ms` p50) and State/Memory Snapshot (`DeferredPostMvp`) are tracked independently per [BRD.md](BRD.md).

---

## License

MIT (`Cargo.toml`: `license = "MIT"`).
