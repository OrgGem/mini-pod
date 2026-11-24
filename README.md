# mini-pod

Unprivileged, QEMU-first micro-VM sandbox runtime in Rust with Ed25519-signed Portable Runtime Bundles, owner-only local IPC, an anti-rebinding Host Egress Proxy, an embedded Podman/Docker Engine API compatibility adapter, a pre-booted Warm Pool, CLI (`sandbox-cli`), MCP server (`sandboxd mcp`), and lightweight async Rust SDK (`sandbox-client`).

- **Specification & Architecture Contract:** [BRD.md](BRD.md) (`v2.1`)
- **Engineering & Security Invariants:** [AGENTS.md](AGENTS.md)
- **Verification, Security & Support Guide:** [docs/release-candidate-v0.1.0.md](docs/release-candidate-v0.1.0.md)
- **Measured Benchmark Report:** [docs/benchmarks/phase6-windows-x86_64.md](docs/benchmarks/phase6-windows-x86_64.md)

---

## Current status and recent fixes

As of November 25, 2026, the `v0.1.0` tag points to commit `95b1cb3`. The tag's [CI run](https://github.com/OrgGem/mini-pod/actions/runs/45361553067) passed on Ubuntu, macOS, Windows, and the guest Alpine job. The [release workflow](https://github.com/OrgGem/mini-pod/actions/runs/45394844943) built host artifacts and npm packages, but both static guest musl jobs failed, so GitHub Release and npm publication were skipped. The live-QEMU results and benchmark linked below were recorded earlier and do not establish a new live-QEMU run at this tag.

Recent fixes included in this snapshot address:

- **Compose ownership and cleanup:** `up` checks project and service labels before replacing a container. `down` continues independent cleanup after errors and reports failures. Network removal targets the discovered network ID. [Commits `e147871`](https://github.com/OrgGem/mini-pod/commit/e1478710bcb4c2c5615b5fa03e4443e24337ad4a) and [`03d7769`](https://github.com/OrgGem/mini-pod/commit/03d7769705af57f93c9e89426c16f6b5d4f77e01).
- **Lifecycle and admission:** randomized sandbox IDs, Docker endpoint names tied to sandbox identity, and RSS accounting for VMs being stopped and during Warm Pool handoff. These changes protect admission decisions across concurrent lifecycle transitions. [Commits `e147871`](https://github.com/OrgGem/mini-pod/commit/e1478710bcb4c2c5615b5fa03e4443e24337ad4a), [`03d7769`](https://github.com/OrgGem/mini-pod/commit/03d7769705af57f93c9e89426c16f6b5d4f77e01), and [`cc751cf`](https://github.com/OrgGem/mini-pod/commit/cc751cfe0cfb99f418ee45b2d69d7e2f8b7a613f).
- **Streams and cleanup:** cancellation-safe exit waiting, bounded stream handling, safer orphan recovery and temporary-file creation. Guest and host cancellation paths were hardened for busy streams. [Commits `e147871`](https://github.com/OrgGem/mini-pod/commit/e1478710bcb4c2c5615b5fa03e4443e24337ad4a), [`99a2ad9`](https://github.com/OrgGem/mini-pod/commit/99a2ad9), and [`2803ad5`](https://github.com/OrgGem/mini-pod/commit/2803ad5).
- **Docker API and packaging:** stricter Docker query and tmpfs policy checks, plus Windows launcher signal handling. [Commits `4f9f4f6`](https://github.com/OrgGem/mini-pod/commit/4f9f4f6) and [`abdeda2`](https://github.com/OrgGem/mini-pod/commit/abdeda2).

## Table of Contents

1. [Architecture (4-Layer Clean Workspace)](#1-architecture-4-layer-clean-workspace)
   - [1.1 Target Use Cases & When Not to Use](#11-target-use-cases--when-not-to-use)
2. [System Requirements & Installation](#2-system-requirements--installation)
   - [2.1 Prerequisites](#21-prerequisites)
   - [2.2 Prebuilt Release Binaries](#22-prebuilt-release-binaries)
   - [2.3 Build & Install Binaries from Source](#23-build--install-binaries-from-source)
   - [2.4 Quickstart Checklist (After Cloning)](#24-quickstart-checklist-after-cloning)
3. [Building Signed Portable Runtime Bundles](#3-building-signed-portable-runtime-bundles)
4. [Running the Daemon (`sandboxd serve`)](#4-running-the-daemon-sandboxd-serve)
5. [CLI Usage Guide (`sandbox-cli`)](#5-cli-usage-guide-sandbox-cli)
6. [Docker API & Testcontainers Integration](#6-docker-api--testcontainers-integration)
7. [MCP Server Usage (`sandboxd mcp`)](#7-mcp-server-usage-sandboxd-mcp)
8. [Rust SDK Usage (`sandbox-client`)](#8-rust-sdk-usage-sandbox-client)
9. [Testing & Verification](#9-testing--verification)
10. [Benchmark Summary](#10-benchmark-summary-windows-x86_64-whpx)
11. [License](#11-license)

---

## 1. Architecture (4-Layer Clean Workspace)

Dependency arrows point strictly inward from outer composition roots toward domain types and wire framing:

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
| [`crates/sandbox-protocol`](crates/sandbox-protocol) | 1 | Length-bounded binary framing, handshake negotiation, prioritized control vs. data lanes, and per-stream `StreamCredit` backpressure. |
| [`crates/sandbox-runtime`](crates/sandbox-runtime) | 2 | `RuntimeManager` (`LocalRuntimeManager`): lifecycle, admission control, TTL lease sweeper, exclusive `state.lock`, crash journal & startup reconciler, Warm Pool, safe tar I/O, and `HostEgressProxy`. |
| [`crates/sandbox-vmm`](crates/sandbox-vmm) | 3 | Cross-OS QEMU driver (`KVM`/`HVF`/`WHPX` -> `TCG`, never falling back to `SharedKernelAllowed`), Windows Job Object confinement + handle whitelist, Unix `setpgid`/cgroup v2, owner-only IPC (`virtio-serial`). |
| [`crates/sandbox-image`](crates/sandbox-image) | 3 | Ed25519 manifest signature verification, SHA-256 + anti-tamper tree validation, crash-safe versioned bundle promotion, `qemu-img` CoW QCOW2 overlays, and `bundle-pack` signer CLI. |
| [`crates/sandbox-docker-compat`](crates/sandbox-docker-compat) | 3 | Owner-only IPC (`npipe://` Named Pipe on Windows, `unix://` `0600` socket on Unix) HTTP/1.1 Docker Engine compatibility adapter (`bollard` / `testcontainers` + Ryuk), host port forwarding over virtio, HTTP hijack & half-close, URL/JSON canonicalization, `/libpod/*` block, and raw host bind-mount rejection. |
| [`crates/sandbox-client`](crates/sandbox-client) | Adapter | Lightweight async `SandboxClient` SDK + `ControlEndpoint` parser + client-side safe tar packing/extraction (no daemon/QEMU/MCP deps). |
| [`bins/sandboxd`](bins/sandboxd) | 4 | Local daemon (`serve`) over owner-only Named Pipe / Unix socket and JSON-RPC 2.0 `stdio` MCP server (`mcp`). |
| [`bins/sandbox-cli`](bins/sandbox-cli) | 4 | CLI client for diagnostics, one-shot and managed VM lifecycles, image builds, Compose, Docker endpoints, and an interactive TUI. |
| [`guest/tiny-init`](guest/tiny-init) & [`guest/sandbox-agent`](guest/sandbox-agent) | Guest | PID 1 read-only rootfs + overlay setup, zombie reaping, execution supervisor (per-exec cgroup v2 `cgroup.kill` + container exec process-tree termination on deadline or output budget), and Podman Unix socket relay. |

### 1.1 Target Use Cases & When Not to Use

| Target Use Case | Why `mini-pod` Fits |
| --- | --- |
| **1. AI Coding Agents & LLM Code Interpreters (`MCP` / Tool-Use)** | Isolates untrusted shell/Python/Node/build commands inside a dedicated guest kernel (`IsolationMode::VmRequired`), checks out pre-booted VMs from the Warm Pool in **`~3.5 ms` p50**, kills the entire guest process group/cgroup tree on `deadline` or `stdout`/`stderr` budget overflow, and defaults to zero-NIC `Isolated` networking or DNS-rebinding-safe `DomainAllowList` filtering via `HostEgressProxy`. |
| **2. Unprivileged Testcontainers & CI Integration Testing** | Runs an isolated Podman daemon inside each micro-VM exposed via an owner-only `npipe://` (Windows) or `unix://` (Linux/macOS) Docker Engine API (`sandbox-docker-compat`), forwards published ports to Host `127.0.0.1`, supports the Testcontainers Ryuk reaper (`--allow-reaper-socket`), and rejects raw host bind mounts (`HostConfig.Binds`) and `--privileged` escalation. |
| **3. Online Judges, Untrusted Plugin Runners & Ephemeral Build Jobs** | Enforces an explicit `copy-in` -> `exec` -> `copy-out` pipeline with strict tar validation (rejecting `..`, symlinks, hardlinks, and Windows NTFS junctions/reparse points), uses one-way disposable `qcow2` Copy-on-Write overlays (never recycling dirty VMs), and reaps orphaned VMs/files after crashes via durable journals. |
| **4. Standard-User Enterprise Workstations (Windows / macOS / Linux)** | Runs without Administrator/root privileges or custom kernel drivers; confines host QEMU processes via Win32 Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + handle whitelist) or Unix process groups/cgroup v2, and restricts control/Docker IPC to the owner SID/UID. |

**When NOT to Use `mini-pod` (Current MVP Scope & Post-MVP Deferrals):**
- **High-volume, real-time bidirectional host/guest Live Mounts:** MVP uses explicit bounded `copy-in` / `copy-out` tar transfers instead of `virtiofs`/`9p` shared mounts. The CLI client uses a `16 MiB` tar budget by default. SDK clients can configure their own limits, subject to daemon and transport limits.
- **GPU passthrough or native Windows containers:** Guest micro-VMs run a minimal Linux kernel (`linux-virt`) with static musl userland and Podman/crun.
- **External VM state/memory snapshots, Windows ARM64 hosts, and native macOS `Virtualization.framework`:** Explicitly deferred post-MVP per [BRD.md](BRD.md).

---

## 2. System Requirements & Installation

### 2.1 Prerequisites

1. **Rust Toolchain (`1.89+`):**
   ```bash
   rustup update stable
   rustc --version   # must be >= 1.89.0
   ```
2. **QEMU (`qemu-system-x86_64` / `qemu-system-aarch64` & `qemu-img`):**
   - **Windows (`x86_64`):**
     ```powershell
     winget install SoftwareFreedomConservancy.QEMU
     ```
     Ensure `C:\Program Files\qemu` is in `PATH` (or `mini-pod` will auto-discover it in `C:\Program Files\qemu` and `%LOCALAPPDATA%\Programs\qemu`). Enable **Windows Hypervisor Platform (`WHPX`)** in Windows Features for hardware acceleration (falls back to `TCG` automatically when `AccelerationPolicy::Preferred` is used).
   - **Linux (`x86_64` / `aarch64`):**
     ```bash
     # Ubuntu / Debian
     sudo apt-get update && sudo apt-get install -y qemu-system-x86 qemu-system-arm qemu-utils
     ```
     Grant your user read/write access to `/dev/kvm` (`sudo usermod -aG kvm $USER`) for `KVM` hardware acceleration.
   - **macOS (`x86_64` / `aarch64`):**
     ```bash
     brew install qemu
     ```
     Uses Apple Hypervisor.framework (`-accel hvf`) with automatic fallback to `TCG`.
3. **Docker (Optional — only required when building guest bundles from source):**
   - Needed to run `scripts/build-portable-bundles.ps1` and `scripts/build-test-oci-images.ps1`.

### 2.2 Prebuilt Release Binaries

The [release workflow](.github/workflows/release.yml) is configured to publish archives containing `sandboxd`, `sandbox-cli`, `bundle-pack`, checksums, and static `linux-musl` guest binaries to [GitHub Releases](https://github.com/OrgGem/mini-pod/releases). The `v0.1.0` workflow did not publish a release. Build from source until a release is available. The configured host targets are:
- **Windows (`x86_64`):** `mini-pod-<version>-x86_64-pc-windows-msvc.zip`
- **Linux (`x86_64` / `aarch64`):** `mini-pod-<version>-x86_64-unknown-linux-gnu.tar.gz`, `mini-pod-<version>-aarch64-unknown-linux-gnu.tar.gz`
- **macOS (`x86_64` / `aarch64`):** `mini-pod-<version>-x86_64-apple-darwin.tar.gz`, `mini-pod-<version>-aarch64-apple-darwin.tar.gz`

Once an npm release has been published, Node.js 18+ users can install the CLI and daemon with `npm install -g @orggem/mini-pod`. Optional platform packages must be enabled; Linux packages use glibc and do not support Alpine/musl. QEMU and a signed guest runtime bundle are installed separately. The [npm release procedure](docs/npm-release.md) describes how to build and publish the packages.

### 2.3 Build & Install Binaries from Source

Clone the repository and build the workspace in release mode:

```bash
git clone https://github.com/OrgGem/mini-pod.git
cd mini-pod

# Build daemon (sandboxd), CLI (sandbox-cli), and bundle signer (bundle-pack)
cargo build --release --bins
```

Compiled binaries are placed in `target/release/`:
- `target/release/sandboxd` (`sandboxd.exe` on Windows) — Local control daemon & MCP server
- `target/release/sandbox-cli` (`sandbox-cli.exe` on Windows) — Command-line client
- `target/release/bundle-pack` (`bundle-pack.exe` on Windows) — Ed25519 bundle manifest generator & signer

Or install directly into `~/.cargo/bin`:

```bash
cargo install --path bins/sandboxd
cargo install --path bins/sandbox-cli
```

### 2.4 Quickstart Checklist (After Cloning)

1. **Install QEMU (`qemu-system-*` & `qemu-img`)** and enable hardware acceleration (`WHPX` on Windows, `/dev/kvm` on Linux, `HVF` on macOS).
2. **Build host binaries:** `cargo build --release --bins`
3. **Generate signed Portable Runtime Bundle:** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1` (creates `.cache/keys/dev-bundle.pub` and `.cache/bundles-src/x86_64`).
4. **Start daemon (Terminal 1):**
   ```powershell
   .\target\release\sandboxd.exe serve --bundle-dir .cache\bundles-src\x86_64 --pub-key-file .cache\keys\dev-bundle.pub --state-dir "$env:LOCALAPPDATA\minipod\state" --warm-pool-size 1
   ```
5. **Run a sandbox command or open the interactive TUI (Terminal 2):**
   ```powershell
   .\target\release\sandbox-cli.exe tui
   # Or scriptable CLI commands:
   .\target\release\sandbox-cli.exe --json status
   .\target\release\sandbox-cli.exe --json spawn --rss-mb 512 --ttl-secs 300
   .\target\release\sandbox-cli.exe list
   .\target\release\sandbox-cli.exe exec <SANDBOX_ID> -- /bin/uname -a
   .\target\release\sandbox-cli.exe destroy <SANDBOX_ID>
   ```

---

## 3. Building Signed Portable Runtime Bundles

`mini-pod` boots micro-VMs from an Ed25519-signed **Portable Runtime Bundle** containing:
- `kernel/vmlinuz-virt` — Pinned Alpine `linux-virt` kernel
- `boot/initramfs.cpio.gz` — Reproducible initramfs with `tiny-init` as `/init`
- `rootfs/base.qcow2` — Read-only ext4/QCOW2 rootfs with `sandbox-agent` and `podman`/`crun`
- `bin/tiny-init` & `bin/sandbox-agent` — Static musl guest binaries
- `manifest.v1` & `manifest.sig` — Canonical manifest and 64-byte Ed25519 signature

### 3.1 Build Reproducible Multi-Arch Bundles (`x86_64` & `aarch64`)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1
```

By default, this script:
1. Generates a development Ed25519 keypair in `.cache/keys/dev-bundle.key` and `.cache/keys/dev-bundle.pub` (if not already present).
2. Builds byte-for-byte reproducible `x86_64` and `aarch64` bundles in `.cache/bundles-src/x86_64` and `.cache/bundles-src/aarch64`.

### 3.2 Custom Keypair & Manual Signing (`bundle-pack`)

To generate your own production Ed25519 keypair and sign a bundle directory:

```bash
# 1. Generate a 32-byte Ed25519 secret key and 32-byte public key (64 hex chars each)
cargo run --release -p sandbox-image --bin bundle-pack -- \
  --generate-keypair ./keys/prod-bundle.key ./keys/prod-bundle.pub

# 2. Pack and sign a bundle directory
cargo run --release -p sandbox-image --bin bundle-pack -- \
  --bundle-dir .cache/bundles-src/x86_64 \
  --bundle-id minipod-linux-x86_64-v1 \
  --host-os any \
  --guest-arch x86_64 \
  --pin "rust_alpine_digest=sha256:2cccd8b212b37dad15a555589c1b6787da4ab913fe24d8a9b2d99d3498869409" \
  --pin "alpine_digest=sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc" \
  --pin "source_date_epoch=1704067200" \
  --entry "kernel=kernel/vmlinuz-virt" \
  --entry "initrd=boot/initramfs.cpio.gz" \
  --entry "base_rootfs_qcow2=rootfs/base.qcow2" \
  --entry "tiny_init=bin/tiny-init" \
  --entry "guest_agent=bin/sandbox-agent" \
  --secret-key-file ./keys/prod-bundle.key
```

---

## 4. Running the Daemon (`sandboxd serve`)

`sandboxd serve` runs the local control daemon over an **owner-only** OS IPC endpoint:
- **Windows default endpoint:** `\\.\pipe\minipod-sandboxd-<USERNAME>` (Win32 DACL `D:P(A;;GA;;;{USER_SID})` + `PIPE_REJECT_REMOTE_CLIENTS`)
- **Linux / macOS default endpoint:** `unix://$XDG_RUNTIME_DIR/minipod/ctl.sock` or `unix:///tmp/minipod-<UID>/ctl.sock` (`0600` socket inside a `0700` owner-only directory)

### 4.1 Start `sandboxd serve` on Windows (PowerShell)

```powershell
.\target\release\sandboxd.exe serve `
  --bundle-dir .cache\bundles-src\x86_64 `
  --pub-key-file .cache\keys\dev-bundle.pub `
  --state-dir "$env:LOCALAPPDATA\minipod\state" `
  --warm-pool-size 1 `
  --max-sandboxes 8 `
  --max-rss-mb 4096 `
  --max-storage-mb 8192 `
  --admission-timeout-ms 5000
```

### 4.2 Start `sandboxd serve` on Linux / macOS (Bash)

```bash
./target/release/sandboxd serve \
  --bundle-dir .cache/bundles-src/x86_64 \
  --pub-key-file .cache/keys/dev-bundle.pub \
  --state-dir "$HOME/.local/state/minipod" \
  --warm-pool-size 1 \
  --max-sandboxes 8 \
  --max-rss-mb 4096 \
  --max-storage-mb 8192 \
  --admission-timeout-ms 5000
```

### 4.3 `sandboxd` Options & Environment Variables

| Option | Environment Variable | Description |
| --- | --- | --- |
| `--bundle-dir <PATH>` | `MINIPOD_BUNDLE_DIR` | Path to the signed Portable Runtime Bundle directory (required). |
| `--pub-key-file <PATH>` | `MINIPOD_PUB_KEY_FILE` | File containing the 64-character hex Ed25519 public key. |
| `--pub-key-hex <HEX>` | `MINIPOD_PUB_KEY_HEX` | Inline 64-character hex Ed25519 public key. |
| `--state-dir <PATH>` | `MINIPOD_STATE_DIR` | Durable state directory for `state.lock`, crash journals (`journals/`), and per-VM overlays (`sandboxes/`). |
| `--endpoint <URI>` | `MINIPOD_ENDPOINT` | Custom local control endpoint (`\\.\pipe\...` / `npipe://...` on Windows, `unix:///...` on Unix). Plain TCP (`tcp://`, `http://`) is rejected. |
| `--ready-file <PATH>` | — | Writes an atomic JSON readiness file (`{"endpoint":"...","pid":...}`) once the listener is bound. |
| `--qemu-bin <PATH>` | `MINIPOD_QEMU_BIN` | Explicit path to `qemu-system-x86_64` or `qemu-system-aarch64`. |
| `--qemu-img-bin <PATH>` | `MINIPOD_QEMU_IMG_BIN` | Explicit path to `qemu-img`. |
| `--arch <x86_64\|aarch64>` | `MINIPOD_ARCH` | Guest architecture (defaults to host native architecture). |
| `--warm-pool-size <N>` | — | Number of pre-booted `Isolated` VMs (`1 vCPU`, `256 MiB` RAM, `512 MiB` RSS cap, `512 MiB` disk) kept ready for `< 500 ms` checkout (default: `0`). |
| `--max-sandboxes <N>` | — | Maximum concurrent active + warm sandboxes. |
| `--max-rss-mb <N>` | — | Maximum total Host RSS budget across all sandboxes in MiB. |
| `--max-storage-mb <N>` | — | Maximum total Host physical storage budget in MiB. |
| `--admission-timeout-ms <MS>` | — | Time in milliseconds a foreground `spawn` waits in the FIFO admission queue before returning `AdmissionRejected` (default: `0`). |

---

## 5. CLI Usage Guide (`sandbox-cli`)

`sandbox-cli` connects to `sandboxd` over the default owner-only endpoint (or `--endpoint <URI>` / `MINIPOD_ENDPOINT`). Add `--json` to any command for structured JSON output.

### Run a one-shot workload

```bash
sandbox-cli run --input ./job /tmp/work --cwd /tmp/work --output /tmp/work/out ./result --deadline-secs 60 -- sh ./process.sh
```

`run` creates a VM with isolated networking by default, copies the explicitly selected input into it, executes the command, copies the selected output after a successful execution, and attempts to destroy the sandbox. The command and its tools must be available in the guest bundle, and the copy-in destination must be writable in the guest. Omit either transfer flag when it is not needed. The output destination must not exist and its parent directory must already exist. Output is extracted into a private staging directory on the same filesystem and published with an atomic no-overwrite rename.

`run` accepts the resource, isolation, accelerator, network, and TTL options of `spawn`, as well as the working directory, user, environment, deadline, and output budget options of `exec`. `--operation-id` is available on `spawn` and is not accepted by `run`. `run` renews the lease during the operation. An interrupt requests cancellation and cleanup. With `--json`, the result contains separate `workload`, `copy_out`, and `cleanup` objects and the sandbox ID when known. Cleanup that reports `ProcessExited` or an unknown outcome makes the command fail and includes the sandbox ID when available for investigation.

The Linux guest agent gives each guest exec its own cgroup v2 leaf with a limit of 128 tasks, including threads. The kernel rejects new tasks at capacity. The agent stays outside the leaf and can accept the next exec on the same VM. A failure to install the limit rejects the guest exec before launch. Commands targeting an existing Podman container use that container's resource policy.

### 5.1 Check Daemon Status & List Active Sandboxes

```bash
sandbox-cli status
sandbox-cli --json status

# Check the daemon's configured QEMU, qemu-img, bundle, and accelerator candidates
sandbox-cli doctor
sandbox-cli --json doctor
# Start an isolated VM, verify guest execution, report its actual accelerator, and clean up
sandbox-cli doctor --smoke
sandbox-cli --json doctor --smoke --accel required

sandbox-cli list
sandbox-cli --json list
```

`doctor` checks the daemon connection and reports whether its configured QEMU and `qemu-img` run, whether the configured bundle verifies against the key loaded by the daemon, and which accelerator candidates its host and guest architecture support. Accelerator candidates come from a QEMU probe and do not establish that a VM can boot. Checks that cannot be made are reported as `unknown`, and the command exits nonzero when any check fails or is unknown.

`doctor --smoke` additionally requests an isolated sandbox, runs `/bin/sh -c 'exit 0'` in the guest, and reports the accelerator selected by the active VM driver and the cleanup result. It may check out a VM from the warm pool, so a passing smoke check does not measure cold boot. `--accel required` requires hardware acceleration; the default is `preferred`, which permits QEMU TCG when hardware acceleration is unavailable.

### 5.1b Interactive Container Sandbox Console (`sandbox-cli tui`)

Launch the full-screen keyboard-driven terminal dashboard for live sandbox VM and guest Podman container administration:

```bash
sandbox-cli tui
sandbox-cli tui --refresh-ms 500
```

| Key | Scope | Action |
| --- | --- | --- |
| `Tab` / `Shift+Tab` / `1-3` | Global | Switch focus between **Sandboxes**, **Guest Containers**, and **Output & Activity Log** |
| `s` | Sandboxes | Spawn a sandbox (`[1]` Warm-Pool Isolated, `[2]` Container Isolated, `[3]` Container + Internet) |
| `r` | Sandboxes | Renew selected sandbox lease (`+300s`) |
| `d` | Sandboxes | Bind & display owner-only `DOCKER_HOST` endpoint (`Standard` or `Testcontainers` mode) |
| `e` | Sandboxes | Execute a shell command inside the selected Guest VM |
| `D` / `Del` | Sandboxes | Destroy selected sandbox (with `y/n` confirmation) |
| `c` / `Enter` | Containers | Inspect/refresh `podman ps -a` inside the selected sandbox |
| `b` | Containers | Build an OCI image from a host directory + `Dockerfile` (`<context_dir> <image:tag>`) |
| `C` (`Shift+c`) | Containers | Deploy a multi-container `compose.yaml` / `docker-compose.yml` stack into the sandbox |
| `i` | Containers | Stream a host OCI `.tar` archive (`docker save` / `podman save`) into air-gapped guest `podman load` |
| `n` | Containers | Run a new detached container (`podman run -d ...`) |
| `x` | Containers | Execute a command directly inside the selected container (`ExecTarget::Container`) |
| `l` | Containers | Tail container logs (`podman logs --tail 100`) into Output pane |
| `S` | Containers | Start or Stop the selected container |
| `X` / `Del` | Containers | Force-remove the selected container (with `y/n` confirmation) |
| `R` / `?` / `q` | Global | Force refresh / Toggle keyboard help / Quit cleanly |

### 5.2 Spawn a Micro-VM Sandbox

- **Warm Pool Checkout (matches default warm template: `isolated`, `1` vCPU, `256 MiB` RAM, `512 MiB` RSS, `512 MiB` disk):**
  ```bash
  sandbox-cli --json spawn --rss-mb 512 --ttl-secs 300
  ```
- **Retryable spawn request:** `sandbox-cli --json spawn --operation-id <lowercase-UUID> --rss-mb 512`. Retry the same logical request with the same UUID and identical spec. If the operation has expired or belongs to a previous daemon incarnation, use a new UUID for a fresh spawn after checking the daemon state.
- **Custom Network Policy (`isolated`, `internet`, or repeatable `allow:<domain>:<port>`):**
  ```bash
  # Allow outbound HTTPS/HTTP only to github.com:443 and *.npmjs.org:443 via HostEgressProxy
  sandbox-cli spawn \
    --isolation vm \
    --accel preferred \
    --network allow:github.com:443 \
    --network allow:*.npmjs.org:443 \
    --vcpus 2 \
    --ram-mb 512 \
    --rss-mb 768 \
    --cpu-millicores 1000 \
    --disk-mb 1024 \
    --storage-mb 2048 \
    --ttl-secs 600
  ```

### 5.3 Copy Workspace In, Execute Commands, and Copy Results Out

```bash
# 1. Copy a host directory or file into the guest VM (safe tar: rejects symlinks, '..', reparse points)
sandbox-cli copy-in <SANDBOX_ID> ./my-project /workspace/app

# 2. Run a command inside the Guest VM with environment variables, working directory, and budgets
sandbox-cli exec <SANDBOX_ID> \
  --cwd /workspace/app \
  --user 0:0 \
  --env RUST_BACKTRACE=1 \
  --deadline-secs 60 \
  --stdout-budget-bytes 1048576 \
  --stderr-budget-bytes 262144 \
  -- /bin/sh -c "uname -a && ls -la /workspace/app"

# 3. Run a command directly inside a running Podman container within the Guest VM
sandbox-cli exec <SANDBOX_ID> \
  --container my-container \
  --cwd /work \
  -- /bin/sh -c "env && ps aux"

# 4. Copy build artifacts from the guest VM back to the host (staged atomically via temp files)
sandbox-cli copy-out <SANDBOX_ID> /workspace/app/dist ./host-dist
```

### 5.4 Renew Lease & Destroy Sandbox (Idempotent)

```bash
# Extend lease TTL by 600 seconds from now
sandbox-cli renew <SANDBOX_ID> --ttl-secs 600

# Destroy sandbox and reclaim all host processes, overlays, and journals (idempotent)
sandbox-cli destroy <SANDBOX_ID>
```

### 5.5 Build Local Images (`Dockerfile`) & Run `compose.yaml` Stacks (No Host Docker Required)

`sandbox-cli` includes native `build` and `compose` subcommands that work on clean hosts **without Docker Desktop, `docker.exe`, or `docker-compose` installed**:

```bash
# 1. Build an OCI image inside the sandbox from a local folder + Dockerfile (up to 128 MiB context)
#    Optional `-o` exports the built image back to a host `.tar` archive.
sandbox-cli build <SANDBOX_ID> ./my-app -t my-app:v1 -f Dockerfile --build-arg ENV=prod -o ./my-app.tar

# 2. Bring up a multi-service Compose stack (builds `build:` services, orders `depends_on:`,
#    creates Podman DNS networks & named `volumes:`, and forwards `ports:` to Host 127.0.0.1)
sandbox-cli compose <SANDBOX_ID> up -f ./compose.yaml -p my-app --build

# 3. Check stack status, view service logs, and tear down (including named volumes with `-v`)
sandbox-cli compose <SANDBOX_ID> ps -f ./compose.yaml -p my-app
sandbox-cli compose <SANDBOX_ID> logs -f ./compose.yaml -p my-app --tail 100
sandbox-cli compose <SANDBOX_ID> down -f ./compose.yaml -p my-app -v
```

Use the same project name and file when inspecting or retrying teardown, especially when sharing a sandbox across projects. `up` checks the existing container's Compose project and service labels before replacement. A name collision with another project or service fails with `PolicyViolation`. `down` acts on resources labeled for the selected project, attempts independent cleanup even after errors, and reports listing and deletion failures. A failed `up` or `down` can leave resources behind. Inspect with `compose ps` and retry cleanup as needed. `-v` also removes project-labeled named volumes.

---

## 6. Docker API & Testcontainers Integration

Each sandbox VM runs an isolated Podman daemon inside the guest reachable exclusively over `virtio-serial`. `sandbox-docker-compat` exposes an owner-only Docker Engine HTTP/1.1 endpoint on the Host:

```bash
# Standard mode (blocks all host bind mounts including /var/run/docker.sock)
sandbox-cli docker-endpoint <SANDBOX_ID>

# Testcontainers mode (rewrites /var/run/docker.sock bind mount to /run/podman/podman.sock inside guest for Ryuk)
sandbox-cli docker-endpoint <SANDBOX_ID> --allow-reaper-socket
```

The returned URI identifies the sandbox's endpoint and uses an owner-only Windows Named Pipe or a `0600` Unix socket inside a `0700` directory. Capture the returned value instead of constructing the endpoint name. After destroying or replacing a sandbox, obtain a fresh endpoint for the new sandbox.

### Using with `DOCKER_HOST`, `bollard`, or `testcontainers`

```powershell
# PowerShell (Windows)
$env:DOCKER_HOST = (sandbox-cli docker-endpoint <SANDBOX_ID> --allow-reaper-socket).Trim()
$env:TESTCONTAINERS_HOST_OVERRIDE = "127.0.0.1"
```

```bash
# Bash (Linux / macOS)
export DOCKER_HOST="$(sandbox-cli docker-endpoint <SANDBOX_ID> --allow-reaper-socket)"
export TESTCONTAINERS_HOST_OVERRIDE="127.0.0.1"
```

Security policies enforced automatically by `sandbox-docker-compat`:
- Publishes container ports exclusively onto Host `127.0.0.1:<ephemeral_port>` and rewrites `/containers/{id}/json` (`inspect`) and `/containers/json` (`list`) so Testcontainers and Docker SDKs connect seamlessly.
- Supports `101 UPGRADED` HTTP hijack with independent `stdin`/`stdout` half-close (`/exec/{id}/start`, `/containers/{id}/attach`).
- Blocks `/libpod/*` routes (`403 Forbidden`), canonicalizes URL paths, rejects duplicate or case-smuggled JSON keys, and blocks raw host bind mounts, `Privileged=true`, `CapAdd`, `Devices`, `DeviceCgroupRules`, and host namespace sharing (`400 Bad Request`).

---

## 7. MCP Server Usage (`sandboxd mcp`)

`sandboxd mcp` implements a newline-delimited JSON-RPC 2.0 Model Context Protocol (`2024-11-05`) server over `stdio`. It supports two modes:

### 7.1 Connected Mode (Shares a Running `sandboxd serve` Daemon)

```json
{
  "mcpServers": {
    "mini-pod": {
      "command": "sandboxd",
      "args": [
        "mcp",
        "--connect",
        "\\\\.\\pipe\\minipod-sandboxd-Gem"
      ]
    }
  }
}
```

### 7.2 Standalone Mode (Manages its Own Embedded Runtime)

```json
{
  "mcpServers": {
    "mini-pod": {
      "command": "sandboxd",
      "args": [
        "mcp",
        "--bundle-dir",
        "D:\\Git\\mini-pod\\.cache\\bundles-src\\x86_64",
        "--pub-key-file",
        "D:\\Git\\mini-pod\\.cache\\keys\\dev-bundle.pub",
        "--state-dir",
        "C:\\Users\\Gem\\AppData\\Local\\minipod\\mcp-state",
        "--warm-pool-size",
        "1"
      ]
    }
  }
}
```

### Exposed MCP Tools

| Tool Name | Description |
| --- | --- |
| `sandbox_status` | Query active sandboxes, warm pool readiness, and host resource reservations. |
| `sandbox_spawn` | Spawn an isolated or egress-filtered micro-VM with custom CPU/RAM/disk/TTL budgets. |
| `sandbox_exec` | Execute a command inside the guest VM or a container (`argv`, `cwd`, `env`, `deadline_secs`). |
| `sandbox_renew_lease` | Renew a sandbox's TTL lease (`sandbox_id`, `ttl_secs`). |
| `sandbox_copy_in` | Safely pack and copy a host file/directory into the guest (`src_host`, `dst_guest`). |
| `sandbox_copy_out` | Safely copy and extract a guest file/directory to the host (`src_guest`, `dst_host`). |
| `sandbox_destroy` | Idempotently destroy a sandbox and verify `AllResourcesCleaned`. |

### 7.3 Bundled Agent Skill (`skills/sandbox-cli`)

For CLI-driven coding agents (Antigravity, Claude Code, Cursor, Codex), a minimal progressive-disclosure skill is provided at [`skills/sandbox-cli/SKILL.md`](skills/sandbox-cli/SKILL.md) (with container/daemon details in [`skills/sandbox-cli/references/containers-and-daemon.md`](skills/sandbox-cli/references/containers-and-daemon.md)).

- **Antigravity (`skills.json`):** Add `{ "entries": [{ "path": "skills" }] }` to `.agents/skills.json`.
- **Standalone / `npx skills`:** Copy `skills/sandbox-cli` into `.agents/skills/sandbox-cli` (or run `npx skills add OrgGem/mini-pod`).

---

## 8. Rust SDK Usage (`sandbox-client`)

Add `sandbox-client` and `sandbox-core` to your `Cargo.toml` to control `sandboxd` programmatically without pulling in daemon, VMM, or MCP dependencies:

```rust
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use sandbox_client::{ControlEndpoint, SandboxClient};
use sandbox_core::{
    AccelerationPolicy, DestroyStatus, ExecRequest, ExecTarget, IsolationMode, NetworkPolicy,
    ResourceBudget, SandboxSpec,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set MINIPOD_ENDPOINT to the running daemon's local pipe or socket URI.
    let endpoint = ControlEndpoint::parse(&std::env::var("MINIPOD_ENDPOINT")?)?;
    let client = SandboxClient::new(endpoint);

    // 1. Spawn a micro-VM (matches Warm Pool template when warm-pool-size > 0)
    let lease = client
        .spawn(SandboxSpec {
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
        })
        .await?;

    // 2. Copy host files in, execute a command, and copy results out
    client
        .copy_in_path(&lease.id, Path::new("./src"), "/tmp/work_in")
        .await?;

    let out = client
        .exec_collect(
            &lease.id,
            ExecRequest {
                target: ExecTarget::Guest,
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "mkdir -p /tmp/work_out && ls -la /tmp/work_in > /tmp/work_out/listing.txt && cat /tmp/work_out/listing.txt".into(),
                ],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 256 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await?;
    assert_eq!(out.exit.code, Some(0));
    print!("{}", String::from_utf8_lossy(&out.stdout));

    client
        .copy_out_to_path(&lease.id, "/tmp/work_out", Path::new("./out"))
        .await?;

    // 3. Optionally enable the owner-only Docker API endpoint for bollard / testcontainers
    let docker_uri = client.enable_docker_compat(&lease.id, false).await?;
    println!("Docker endpoint: {docker_uri}");

    // 4. Idempotent teardown
    let status = client.destroy(&lease.id).await?;
    assert_eq!(status, DestroyStatus::AllResourcesCleaned);
    Ok(())
}
```

For streaming execution, consume output with `next_output()` or use `collect()` / `exec_collect()` when output is needed. `ClientExecStream::wait_exit()` discards unread output while waiting to avoid blocking on a full output queue. Its result can be awaited again after a caller cancels a pending wait.

---

## 9. Testing & Verification

### 9.1 Fast Compile, Clippy & Unit/Component Tests (No QEMU Required)

```powershell
# Compile all workspace targets
cargo check --all-targets

# Lint all workspace targets with warnings denied
cargo clippy --workspace --all-targets -- -D warnings

# Run all unit and component tests (QEMU-backed E2E tests skip cleanly unless MINIPOD_REQUIRE_QEMU_TESTS=1)
cargo test --workspace
```

### 9.2 Full Live-QEMU E2E Suite

```powershell
# 1. Build reproducible signed x86_64 & aarch64 bundles (.cache/bundles-src + .cache/keys/dev-bundle.pub)
powershell -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1

# 2. Build offline OCI test images for Docker compat / Testcontainers E2E (.cache/test-images)
powershell -ExecutionPolicy Bypass -File scripts/build-test-oci-images.ps1

# 3. Run full workspace tests requiring live QEMU + WHPX/KVM/HVF/TCG
$env:MINIPOD_REQUIRE_QEMU_TESTS = "1"
cargo test --workspace -- --test-threads=1
```

---

## 10. Benchmark Summary (`windows-x86_64`, `whpx`)

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

## 11. License

MIT (`Cargo.toml`: `license = "MIT"`).
