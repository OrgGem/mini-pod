---
name: sandbox-cli
description: >-
  Run untrusted code, builds, tests, and isolated Podman containers inside hardware/QEMU
  micro-VM sandboxes using mini-pod's `sandbox-cli`. Use for one-shot sandbox workloads,
  readiness diagnostics, sandbox lifecycles, or an isolated `DOCKER_HOST` endpoint.
---

# `sandbox-cli` — Agent Operational Guide

Use `sandbox-cli` to run untrusted code, scripts, builds, or containers inside disposable Linux micro-VMs managed by `sandboxd` over an owner-only local IPC socket/pipe.

## 1. Golden Rules for Agents

1. **Use `--json`** (`sandbox-cli --json <subcommand>`) for machine-readable results. Check the process exit code and the reported operation and cleanup status.
2. **Use `status` and `list` for unattended work.** `tui` requires an interactive TTY.
3. **Destroy sandboxes created for the task** when finished, including after failures. `destroy` is idempotent. Check for `AllResourcesCleaned`; `ProcessExited` means artifacts remain and exits nonzero.
4. **Never pass `tcp://` or `http://` to `--endpoint`** — `mini-pod` enforces owner-only Unix sockets (`unix:///...`) or Windows Named Pipes (`\\.\pipe\...` / `npipe://...`).
5. **Binary discovery:** Use `sandbox-cli` if on `PATH`, otherwise `./target/release/sandbox-cli` (Linux/macOS) or `.\target\release\sandbox-cli.exe` (Windows).

## 2. One-shot workload and diagnostics

Use `run` for a single guest command and optional transfers. The input destination must be writable, and the command must exist in the guest.

```bash
sandbox-cli --json doctor
sandbox-cli --json run --input ./job /tmp/work --cwd /tmp/work \
  --output /tmp/work/out ./result --deadline-secs 60 -- sh ./process.sh
```

`doctor` reports daemon, QEMU, `qemu-img`, bundle, and accelerator-candidate checks. `doctor --smoke` also runs an isolated guest command, reports the actual accelerator and attempts cleanup. Smoke may use a warm VM. A failed or unknown check exits nonzero.

`run` defaults to isolated networking, renews the lease, copies output only after successful execution, and attempts cleanup after obtaining an ID. Omit `--input` or `--output` when unnecessary. The host output destination must not exist, and its parent must exist. Inspect `workload`, `copy_out`, and `cleanup` in the result. If cleanup is `ProcessExited`, `error`, or `unknown`, retain the reported ID and details for investigation. An interrupted spawn can have unknown cleanup without an ID. `run` does not accept `--operation-id`.

For several operations in the same VM, use the managed workflow below.

## 3. Managed workflow (`Copy-In -> Exec -> Copy-Out -> Destroy`)

### Step 1: Verify Daemon Health
```bash
sandbox-cli --json status
# -> {"active_sandboxes":0,"warm_ready_vms":1,"effective_host_rss_mb":256,"reserved_host_storage_mb":1024,"version":"0.1.0"}
```
If connection fails, check the endpoint and daemon status. See [containers-and-daemon.md](./references/containers-and-daemon.md).

### Step 2: Spawn a Sandbox
- **Warm-Pool Checkout:**
  A ready VM must match the daemon's warm template. The default template uses `isolated`, `1` vCPU, `256` MiB RAM, `--rss-mb 512`, `512` MiB disk, and `1024` MiB storage:
  ```bash
  sandbox-cli --json spawn --rss-mb 512 --ttl-secs 300
  # -> {"id":"<sandbox-id>","ttl_secs":300,"capabilities":{...}}
  ```
- **Custom Resources or Controlled Outbound Network:**
  ```bash
  # Allow HTTPS only to specific domains via HostEgressProxy (blocks RFC1918/loopback/IPv6 internal & DNS rebinding)
  sandbox-cli --json spawn \
    --network allow:pypi.org:443 \
    --network allow:*.pythonhosted.org:443 \
    --vcpus 2 --ram-mb 512 --rss-mb 768 \
    --disk-mb 1024 --storage-mb 2048 --ttl-secs 600
  ```
  *(Use `--network internet` for general outbound HTTP/HTTPS via `HostEgressProxy`, or keep default `--network isolated` for zero network).*

Pass the returned sandbox `id` verbatim to subsequent commands. For retryable explicit spawn requests, `spawn --operation-id <lowercase-UUID>` associates the operation ID with the exact sandbox spec. Retry the same logical request with the same UUID and identical spec. Retrying with a different spec is rejected. If the operation has expired or belongs to a previous daemon incarnation, check the daemon state and use a new UUID for a fresh spawn.

### Step 3: Copy Workspace In (`copy-in`)
```bash
sandbox-cli --json copy-in <SANDBOX_ID> ./src-dir /workspace/app
```
- **Safe-tar limits:** The CLI client defaults to a `16 MiB` tar archive budget, including tar overhead. Extraction uses a `4096` entry default; daemon limits also apply. Transfers reject symlinks, hardlinks, Windows junctions/reparse points, and `..`.
- **Select inputs:** Copy only files needed for the task and check for private data before including directories such as `.git/`, `node_modules/`, `target/`, or `.venv/`.
- **Guest filesystem layout:** `/` is read-only Alpine Linux; writable mounts are `/workspace`, `/tmp`, `/var/tmp`, `/root`, `/etc`, and `/var/lib/containers`.

### Step 4: Execute Commands (`exec`) & Renew Lease (`renew`)
Always separate `exec` flags from the guest command with `--`. Note that `sandbox-cli exec` closes `stdin` immediately, so commands never hang waiting for input:
```bash
sandbox-cli --json exec <SANDBOX_ID> \
  --cwd /workspace/app \
  --env CI=1 \
  --deadline-secs 60 \
  --stdout-budget-bytes 1048576 \
  --stderr-budget-bytes 1048576 \
  -- /bin/sh -c "uname -a && ls -la"
# -> {"exit_code":0,"timed_out":false,"stdout_truncated":false,"stderr_truncated":false,"stdout":"...","stderr":"..."}
```
- Timeout returns process exit code `124` and `"timed_out": true` (guest supervisor kills the entire process group / cgroup).
- Before long multi-step tasks expire, extend TTL from *now*:
  ```bash
  sandbox-cli --json renew <SANDBOX_ID> --ttl-secs 300
  ```

### Step 5: Copy Artifacts Out (`copy-out`) & Destroy (`destroy`)
```bash
sandbox-cli --json copy-out <SANDBOX_ID> /workspace/app/dist ./host-dist
sandbox-cli --json destroy <SANDBOX_ID>
```

Inspect the destroy result. For `ProcessExited`, investigate the reported remaining artifacts and retry cleanup where appropriate.

## 4. Quick Subcommand Reference

| Subcommand | Purpose |
| --- | --- |
| `status` | Daemon version, active VM count, Warm Pool ready count, Host RSS & storage usage |
| `doctor [--smoke] [--accel required\|preferred\|software]` | Check readiness; optionally execute a guest smoke check (`--accel` requires `--smoke`) |
| `list` | Per-sandbox `id`, `pid`, `alive`, `network`, `remaining_ttl_ms`, `live_rss_bytes`, `docker_endpoint` |
| `spawn [FLAGS]` | Create VM (`--operation-id`, `--network`, `--vcpus`, `--ram-mb`, `--rss-mb`, `--cpu-millicores`, `--disk-mb`, `--storage-mb`, `--ttl-secs`) |
| `run [FLAGS] -- <ARGV...>` | Create, execute, optionally copy input/output, and attempt to destroy a sandbox |
| `copy-in <ID> <HOST> <GUEST>` | Upload file/dir safely into guest (`<= 16 MiB`, no symlinks) |
| `exec <ID> [FLAGS] -- <ARGV...>` | Run command in Guest VM (or `--container <NAME>` inside a Podman container) |
| `renew <ID> --ttl-secs <N>` | Reset sandbox lease TTL to `<N>` seconds from now |
| `copy-out <ID> <GUEST> <HOST>` | Download file/dir safely from guest to host |
| `build <ID> <CONTEXT_DIR> -t <TAG> [FLAGS]` | Build image from host folder + `Dockerfile` inside VM (`-f`, `--build-arg`, `--target`, `-o <OUT.tar>`) |
| `compose <ID> <up\|ps\|logs\|down> [FLAGS]` | Run/inspect/tear down multi-container `compose.yaml` stacks natively (0 Host Docker needed) |
| `docker-endpoint <ID> [--allow-reaper-socket]` | Bind owner-only `DOCKER_HOST` socket/pipe for Docker CLI, `bollard`, or Testcontainers |
| `destroy <ID>` | Idempotently attempt cleanup and report whether artifacts remain |

For **Podman containers inside sandboxes**, **`DOCKER_HOST` / Testcontainers**, **starting `sandboxd`**, or **error codes**, read [references/containers-and-daemon.md](./references/containers-and-daemon.md).
