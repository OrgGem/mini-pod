# Containers, Docker API & Daemon Reference

Load this reference when running OCI/Podman containers inside a sandbox, wiring `DOCKER_HOST` / Testcontainers, or troubleshooting `sandboxd`.

## 1. Running Containers Inside a Sandbox

Size container sandboxes with enough RAM and disk (`--storage-mb` must always be `>= --disk-mb`):

```bash
sandbox-cli --json spawn \
  --network isolated \
  --vcpus 2 --ram-mb 768 --rss-mb 1024 \
  --disk-mb 1024 --storage-mb 2048 --ttl-secs 600
```

### Option A: Native `build` & `compose` Subcommands (Zero Host Docker Needed)

- **Build an image from a local folder + `Dockerfile`:**
  ```bash
  sandbox-cli --json build <ID> ./my-service \
    -t my-service:v1 \
    -f Dockerfile \
    --build-arg ENV=prod \
    -o ./dist/my-service.tar
  ```
- **Deploy, inspect, and tear down a `compose.yaml` / `docker-compose.yml` stack:**
  *(Supports `build:`, `image:`, `depends_on:`, `ports:` forwarded onto Host `127.0.0.1`, named `volumes:`, `tmpfs:`, `networks:` with automatic service DNS aliases, `environment:` / `env_file:`; rejects unsafe host bind mounts and `privileged: true`)*:
  ```bash
  sandbox-cli --json compose <ID> up -f ./compose.yaml -p my-app --build
  sandbox-cli --json compose <ID> ps -f ./compose.yaml -p my-app
  sandbox-cli --json compose <ID> logs -f ./compose.yaml -p my-app --tail 50
  sandbox-cli --json compose <ID> down -f ./compose.yaml -p my-app -v
  ```

  When a sandbox hosts several projects, pass the same explicit `-p` used by `up` and the same Compose file when inspecting or tearing down that project. `up` refuses to replace an existing container unless its project and service labels match. `down` selects project-labeled resources, continues independent cleanup after an error, and reports listing and deletion failures. After a partial failure, inspect what remains and rerun that project's `down` command. Include `-v` when its project-labeled named volumes should also be removed.

### Option B: Direct Guest Podman (`exec`)
- **Air-gapped (`--network isolated`):** Load an OCI archive without internet:
  - A `.tar` small enough for the CLI's `16 MiB` copy budget, including tar wrapping overhead:
    ```bash
    sandbox-cli --json copy-in <ID> ./image.tar /tmp
    sandbox-cli --json exec <ID> -- /usr/bin/podman load -i /tmp/image.tar
    sandbox-cli --json exec <ID> -- /bin/rm -f /tmp/image.tar
    ```
  - For a larger `.tar`, bind `docker-endpoint` (Option C below) and run `docker -H <URI> load -i ./image.tar`.
- **Start & execute inside a container:**
  ```bash
  sandbox-cli --json exec <ID> --deadline-secs 120 -- /usr/bin/podman run -d --name app -p 8080:8080 my-image:latest
  sandbox-cli --json exec <ID> --container app --cwd / -- /bin/sh -c "id && ps aux"
  sandbox-cli --json exec <ID> -- /usr/bin/podman logs --tail 100 app
  ```

### Option C: Host `DOCKER_HOST` Compatibility & Testcontainers
Expose the guest's Podman Engine API on an owner-only Host Unix socket or Windows Named Pipe (published container ports automatically tunnel to `127.0.0.1:<ephemeral_port>` on the Host):

```bash
# Standard mode (blocks all host bind mounts, including /var/run/docker.sock)
sandbox-cli --json docker-endpoint <ID>

# Testcontainers mode (maps /var/run/docker.sock inside guest for Ryuk reaper)
sandbox-cli --json docker-endpoint <ID> --allow-reaper-socket
```

Capture the returned URI instead of constructing its name. It is associated with the sandbox identity. Request a fresh endpoint after replacing the sandbox. Enable the reaper socket only when the workload needs it.

- **PowerShell (Windows):**
  ```powershell
  $ep = (sandbox-cli --json docker-endpoint <ID> --allow-reaper-socket | ConvertFrom-Json).uri
  $env:DOCKER_HOST = $ep
  $env:TESTCONTAINERS_HOST_OVERRIDE = "127.0.0.1"
  ```
- **Bash (Linux / macOS):**
  ```bash
  export DOCKER_HOST="$(sandbox-cli docker-endpoint <ID> --allow-reaper-socket)"
  export TESTCONTAINERS_HOST_OVERRIDE="127.0.0.1"
  ```

## 2. Starting `sandboxd serve` (When `status` Cannot Connect)

`sandboxd` must run in a background process/service owned by the same OS user:

- **Windows (PowerShell):**
  ```powershell
  .\target\release\sandboxd.exe serve `
    --bundle-dir .cache\bundles-src\x86_64 `
    --pub-key-file .cache\keys\dev-bundle.pub `
    --state-dir "$env:LOCALAPPDATA\minipod\state" `
    --warm-pool-size 1 `
    --admission-timeout-ms 5000
  ```
- **Linux / macOS (Bash):**
  ```bash
  ./target/release/sandboxd serve \
    --bundle-dir .cache/bundles-src/x86_64 \
    --pub-key-file .cache/keys/dev-bundle.pub \
    --state-dir "$HOME/.local/state/minipod" \
    --warm-pool-size 1 \
    --admission-timeout-ms 5000
  ```

If `.cache/bundles-src/<arch>` does not exist, follow the repository README's signed-bundle build instructions and use the matching public key. QEMU must also be available to the daemon.

## 3. Common Errors & Remedies

| Error Kind / Symptom | Cause & Fix |
| --- | --- |
| `InvalidSpec` (`virtual_disk_mb exceeds host_storage_budget_mb`) | Set `--storage-mb` to at least `--disk-mb`, allowing space for host-side artifacts (e.g. `--disk-mb 1024 --storage-mb 2048`). |
| `AdmissionRejected` | Host concurrency, RSS, CPU, or storage capacity is unavailable, or the request exceeds a configured limit. Inspect `status` and `list`, then wait or adjust the request. Clean up sandboxes created for the task when appropriate. |
| Copy `BudgetExceeded` | The transfer exceeded a configured archive, entry, or transport limit. Select fewer inputs or smaller outputs. The CLI's default copy archive budget is `16 MiB`, including tar overhead. |
| Truncated output or timeout | Check `stdout_truncated`, `stderr_truncated`, `timed_out`, and the process exit code. Adjust the workload or `exec`/`run` budget and deadline flags as appropriate. |
| `PolicyViolation` on `copy-in` | Source directory contains symlinks, junctions, or hardlinks. Copy plain files only. |
| `LeaseExpired` / `NotFound` | The sandbox or keyed operation may have expired, or the sandbox ID may no longer exist. Inspect the daemon state, then spawn a fresh sandbox if appropriate. Renew leases during long runs. |
| Compose `PolicyViolation` on `up` | An existing container name is owned by a different Compose project or service. Inspect the project and choose names deliberately. |
| `ProcessExited` on destroy | The VM exited but some artifacts remain. Inspect the reported paths and retry cleanup as appropriate. |
