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

### Option A: Direct Guest Podman (`exec`)
- **Air-gapped (`--network isolated`):** Load an OCI archive without internet:
  - Small `.tar` (`<= 16 MiB`):
    ```bash
    sandbox-cli --json copy-in <ID> ./image.tar /tmp/image.tar
    sandbox-cli --json exec <ID> -- /usr/bin/podman load -i /tmp/image.tar
    sandbox-cli --json exec <ID> -- /bin/rm -f /tmp/image.tar
    ```
  - Large `.tar` (`> 16 MiB`): Bind `docker-endpoint` (Option B below) and run `docker -H <URI> load -i ./image.tar`.
- **Start & execute inside a container:**
  ```bash
  sandbox-cli --json exec <ID> --deadline-secs 120 -- /usr/bin/podman run -d --name app -p 8080:8080 my-image:latest
  sandbox-cli --json exec <ID> --container app --cwd / -- /bin/sh -c "id && ps aux"
  sandbox-cli --json exec <ID> -- /usr/bin/podman logs --tail 100 app
  ```

### Option B: Host `DOCKER_HOST` Compatibility & Testcontainers
Expose the guest's Podman Engine API on an owner-only Host Unix socket or Windows Named Pipe (published container ports automatically tunnel to `127.0.0.1:<ephemeral_port>` on the Host):

```bash
# Standard mode (blocks all host bind mounts, including /var/run/docker.sock)
sandbox-cli --json docker-endpoint <ID>

# Testcontainers mode (maps /var/run/docker.sock inside guest for Ryuk reaper)
sandbox-cli --json docker-endpoint <ID> --allow-reaper-socket
```

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

*(If `.cache/bundles-src/<arch>` does not exist yet in a fresh repo clone, ask the user or run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1` once).*

## 3. Common Errors & Remedies

| Error Kind / Symptom | Cause & Fix |
| --- | --- |
| `InvalidSpec` (`virtual_disk_mb exceeds host_storage_budget_mb`) | Pass `--storage-mb` at least `2x` `--disk-mb` (e.g. `--disk-mb 1024 --storage-mb 2048`). |
| `AdmissionRejected` | Host concurrency, RSS, or storage cap is full. `destroy` unused sandboxes (`sandbox-cli --json list`) or wait/retry. |
| `BudgetExceeded` on `copy-in` or `exec` | `copy-in` archive exceeded `16 MiB` / `4096` files, or command output exceeded `--stdout-budget-bytes` / `--stderr-budget-bytes`. Filter files or raise budget flags. |
| `PolicyViolation` on `copy-in` | Source directory contains symlinks, junctions, or hardlinks. Copy plain files only. |
| `LeaseExpired` / `NotFound` | Sandbox TTL elapsed and the sweeper destroyed it. Spawn a fresh sandbox and use `renew` on long runs. |
