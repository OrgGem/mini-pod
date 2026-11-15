# mini-pod

Unprivileged, QEMU-First sandbox runtime for executing untrusted workloads and containerized dependencies (`Podman`-inside-VM with Docker API compatibility) across Windows, Linux, and macOS.

- **Specification & Contracts:** [BRD.md](BRD.md) (`v2.1`)
- **Engineering Rules & Phase Workflow:** [AGENTS.md](AGENTS.md)

## Cargo Workspace Structure

```text
mini-pod/
├── Cargo.toml                         # Workspace root (11 members, guest-release profile)
├── crates/
│   ├── sandbox-core/                  # Layer 1: Domain types, policy invariants, SandboxError
│   ├── sandbox-protocol/              # Layer 1: Versioned binary framing, Control/Data lanes
│   ├── sandbox-runtime/               # Layer 2: RuntimeManager trait & lifecycle use cases
│   ├── sandbox-vmm/                   # Layer 3: Shared QEMU driver + OS modules (windows/unix)
│   ├── sandbox-image/                 # Layer 3: Ed25519 bundle verification & qcow2 CoW overlays
│   ├── sandbox-docker-compat/         # Layer 3: Docker API adapter, port mapping & HTTP hijack
│   └── sandbox-client/                # Adapter: Lightweight Rust SDK (no daemon/VMM/MCP)
├── bins/
│   ├── sandboxd/                      # Layer 4: Daemon composition root (auth, MCP, runtime wiring)
│   └── sandbox-cli/                   # Layer 4: CLI composition root
└── guest/
    ├── tiny-init/                     # Guest PID 1 (ro rootfs + Podman overlay, zombie reaper)
    └── sandbox-agent/                 # Guest RPC daemon, Execution Supervisor & Podman relay
```

## Clean Architecture Dependency Matrix

Source-code dependencies point strictly inward toward `sandbox-core` and `sandbox-protocol`:

| Component | Layer | Allowed Internal Dependencies | Forbidden Dependencies |
| --- | --- | --- | --- |
| `sandbox-core` | Layer 1 (Domain) | None (pure `std`) | `tokio` I/O, HTTP, QEMU, OS process APIs |
| `sandbox-protocol` | Layer 1 (Protocol) | None (pure `std`) | Host filesystem, QEMU, Podman logic |
| `sandbox-runtime` | Layer 2 (Use Cases) | `sandbox-core`, `sandbox-protocol` | Layer 3 adapters, CLI, MCP, Docker HTTP routing |
| `sandbox-vmm` | Layer 3 (Adapter) | `sandbox-core`, `sandbox-protocol`, `sandbox-runtime` | Lease/Warm Pool policies, `bins/*` |
| `sandbox-image` | Layer 3 (Adapter) | `sandbox-core` | VM process lifecycle, HTTP servers |
| `sandbox-docker-compat` | Layer 3 (Adapter) | `sandbox-core`, `sandbox-protocol`, `sandbox-runtime` | Direct `bins/*`; `bollard` allowed only in client/tests |
| `sandbox-client` | Adapter (SDK) | `sandbox-core`, `sandbox-protocol` | `sandbox-runtime`, `sandbox-vmm`, `sandboxd`, MCP |
| `bins/sandboxd` | Layer 4 (Composition) | Layer 1–3 host crates | Library crates depending back on `bins/*` |
| `bins/sandbox-cli` | Layer 4 (Composition) | `sandbox-core`, `sandbox-client` | `sandbox-vmm`, daemon internals |
| `guest/tiny-init`, `guest/sandbox-agent` | Guest | `sandbox-protocol` | Host crates, TCP `2375` listener |

## Toolchain Setup (Prerequisites for Phase 1)

1. Install Rust (`>= 1.75`) via `rustup`:
   ```powershell
   winget install Rustlang.Rustup
   rustup default stable
   rustup target add x86_64-unknown-linux-musl
   ```
2. Install QEMU for host spike testing:
   ```powershell
   winget install SoftwareFreedomConservancy.QEMU
   ```
3. Verify workspace compilation and end-of-phase tests:
   ```powershell
   cargo check --all-targets
   cargo test --workspace
   cargo build -p sandbox-agent --profile guest-release
   ```

## Phase Roadmap Mapping (`BRD.md` Section 6)

| Phase | Timeline | Target Crates / Components | Completion Gate |
| --- | --- | --- | --- |
| Phase 1 | Week 1 | Spike QEMU + `sandbox-protocol` + `sandbox-vmm` | Unprivileged boot, `virtio-serial` handshake (`-chardev pipe` / `socket`), exec, clean teardown |
| Phase 2 | Week 2 | `sandbox-image`, CI bundle pipeline | Reproducible guest rootfs/kernel, Ed25519 + SHA-256 verification, atomic swap (`x86_64` & `aarch64`) |
| Phase 3 | Weeks 3–4 | `sandbox-core`, `sandbox-runtime`, `sandbox-vmm`, `guest/*` | Isolated execution on 3 OSes, Windows Job Object, TTL lease, crash journal/reconciler, safe Copy I/O |
| Phase 4 | Weeks 5–6 | `guest/sandbox-agent`, `sandbox-docker-compat` | Podman Unix socket relay, Host port forwarding, Docker SDK & Testcontainers suite passing |
| Phase 5 | Week 7 | `sandbox-runtime` (egress & accounting) | Host Egress Proxy (anti-DNS-rebinding & IPv6 filter), admission control, honest `EnforcementLevel` |
| Phase 6 | Week 8 | `sandbox-runtime` (Warm Pool) | Separated benchmarks (`Cold Boot`, `Warm Checkout`, `Container-Ready`), pool exhaustion backpressure |
| Phase 7 | Week 9 | `sandbox-client`, `bins/sandbox-cli`, `bins/sandboxd` | Packaged CLI/SDK/MCP server, crash recovery drills, all 7 Release Gates signed off |
