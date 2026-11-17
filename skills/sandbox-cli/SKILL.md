---
name: sandbox-cli
description: >-
  Run untrusted code, builds, tests, and isolated Podman containers inside hardware/QEMU
  micro-VM sandboxes using mini-pod's `sandbox-cli`. Activate when asked to execute commands
  in a sandbox, manage sandbox lifecycles (`spawn`, `copy-in`, `exec`, `renew`, `copy-out`,
  `destroy`), or expose an isolated `DOCKER_HOST` endpoint.
---

# `sandbox-cli` — Agent Operational Guide

Use `sandbox-cli` to run untrusted code, scripts, builds, or containers inside disposable Linux micro-VMs managed by `sandboxd` over an owner-only local IPC socket/pipe.

## 1. Golden Rules for Agents

1. **Always pass `--json`** (`sandbox-cli --json <subcommand>`) so responses are structured and unambiguous.
2. **Never run `sandbox-cli tui`** — `tui` requires a human interactive TTY and immediately fails on non-TTY pipes. Use `status` and `list` instead.
3. **Always `destroy <SANDBOX_ID>` when finished** (even after command failures). `destroy` is idempotent.
4. **Never pass `tcp://` or `http://` to `--endpoint`** — `mini-pod` enforces owner-only Unix sockets (`unix:///...`) or Windows Named Pipes (`\\.\pipe\...` / `npipe://...`).
5. **Binary discovery:** Use `sandbox-cli` if on `PATH`, otherwise `./target/release/sandbox-cli` (Linux/macOS) or `.\target\release\sandbox-cli.exe` (Windows).

## 2. Standard 5-Step Workflow (`Copy-In -> Exec -> Copy-Out -> Destroy`)

### Step 1: Verify Daemon Health
```bash
sandbox-cli --json status
# -> {"active_sandboxes":0,"warm_ready_vms":1,"effective_host_rss_mb":256,"reserved_host_storage_mb":1024,"version":"0.1.0"}
```
If connection fails, `sandboxd serve` is not running — see [containers-and-daemon.md](./references/containers-and-daemon.md).

### Step 2: Spawn a Sandbox
- **Fast Warm-Pool Checkout (`< 500ms` when `warm_ready_vms > 0`, air-gapped):**
  Must match the default warm template (`isolated`, `1` vCPU, `256` MiB RAM, `--rss-mb 512`, `512` MiB disk, `1024` MiB storage):
  ```bash
  sandbox-cli --json spawn --rss-mb 512 --ttl-secs 300
  # -> {"id":"sb-...","ttl_secs":300,"capabilities":{...}}
  ```
- **Custom Resources or Controlled Outbound Network (cold boot ~1–3s):**
  ```bash
  # Allow HTTPS only to specific domains via HostEgressProxy (blocks RFC1918/loopback/IPv6 internal & DNS rebinding)
  sandbox-cli --json spawn \
    --network allow:pypi.org:443 \
    --network allow:*.pythonhosted.org:443 \
    --vcpus 2 --ram-mb 512 --rss-mb 768 \
    --disk-mb 1024 --storage-mb 2048 --ttl-secs 600
  ```
  *(Use `--network internet` for general outbound HTTP/HTTPS via `HostEgressProxy`, or keep default `--network isolated` for zero network).*

### Step 3: Copy Workspace In (`copy-in`)
```bash
sandbox-cli --json copy-in <SANDBOX_ID> ./src-dir /workspace/app
```
- **Safe-tar limits:** Max `16 MiB` and `4096` entries per `copy-in`. Rejects symlinks, hardlinks, Windows junctions/reparse points, and `..`.
- **Stage clean inputs only:** Never `copy-in` `.git/`, `node_modules/`, `target/`, or `.venv/`.
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

## 3. Quick Subcommand Reference

| Subcommand | Purpose |
| --- | --- |
| `status` | Daemon version, active VM count, Warm Pool ready count, Host RSS & storage usage |
| `list` | Per-sandbox `id`, `pid`, `alive`, `network`, `remaining_ttl_ms`, `live_rss_bytes`, `docker_endpoint` |
| `spawn [FLAGS]` | Create VM (`--network`, `--vcpus`, `--ram-mb`, `--rss-mb`, `--cpu-millicores`, `--disk-mb`, `--storage-mb`, `--ttl-secs`) |
| `copy-in <ID> <HOST> <GUEST>` | Upload file/dir safely into guest (`<= 16 MiB`, no symlinks) |
| `exec <ID> [FLAGS] -- <ARGV...>` | Run command in Guest VM (or `--container <NAME>` inside a Podman container) |
| `renew <ID> --ttl-secs <N>` | Reset sandbox lease TTL to `<N>` seconds from now |
| `copy-out <ID> <GUEST> <HOST>` | Download file/dir safely from guest to host |
| `docker-endpoint <ID> [--allow-reaper-socket]` | Bind owner-only `DOCKER_HOST` socket/pipe for Docker CLI, `bollard`, or Testcontainers |
| `destroy <ID>` | Idempotently kill VM and clean overlays, sockets, and journals |

For **Podman containers inside sandboxes**, **`DOCKER_HOST` / Testcontainers**, **starting `sandboxd`**, or **error codes**, read [references/containers-and-daemon.md](./references/containers-and-daemon.md).
