# mini-pod Benchmark Report

- **Platform:** windows-x86_64
- **Arch:** x86_64
- **Accelerator:** whpx
- **Warm Pool Target (p50):** <= 500.0 ms (PASS)

## Metrics Summary

| Metric | Category | Status | n | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cold_boot_spawn` | Cold Boot | Measured | 3 | 2011.93 | 2092.41 | 2115.95 | 2115.95 | 2073.43 |
| `cold_boot_first_exec` | Cold Boot | Measured | 3 | 1.27 | 1.45 | 1.47 | 1.47 | 1.40 |
| `warm_checkout_spawn` | Warm Checkout | Measured | 3 | 3.05 | 3.50 | 4.08 | 4.08 | 3.54 |
| `warm_checkout_first_exec` | Warm Checkout | Measured | 3 | 1.40 | 1.57 | 1.65 | 1.65 | 1.54 |
| `snapshot_restore` | Snapshot Restore | DeferredPostMvp | - | - | - | - | - | - |
| `container_ready_cold_podman` | Container-Ready | Measured | 3 | 3800.39 | 3801.77 | 4063.79 | 4063.79 | 3888.65 |
| `container_ready_warm_vm` | Container-Ready | Measured | 3 | 120.33 | 120.90 | 124.18 | 124.18 | 121.81 |

## Separated Metric Details

### 1. Cold Boot
- `cold_boot_spawn`: samples (ms) = [2011.93, 2092.41, 2115.95]
- `cold_boot_first_exec`: samples (ms) = [1.47, 1.27, 1.45]

### 2. Warm Checkout
- Target check (`Warm Checkout <= 500.0 ms`): p50 = 3.50 ms -> PASS
- `warm_checkout_spawn`: samples (ms) = [3.50, 4.08, 3.05]
- `warm_checkout_first_exec`: samples (ms) = [1.65, 1.57, 1.40]

### 3. Snapshot Restore
- `snapshot_restore`: **DeferredPostMvp** — State/Memory Snapshot deferred post-MVP per BRD.md Section 4.1 & Section 6

### 4. Container-Ready
- `container_ready_cold_podman`: samples (ms) = [3801.77, 4063.79, 3800.39]
- `container_ready_warm_vm`: samples (ms) = [120.33, 124.18, 120.90]

## Measurement Notes & Scope

- **Suite:** `crates/sandbox-vmm/tests/phase6_warm_pool_and_bench_e2e.rs`
- **Cold Boot (`cold_boot_spawn`, `cold_boot_first_exec`):** `WarmPoolConfig` disabled (`target_size = 0`); VM spec = 1 vCPU, 256 MiB guest RAM, 512 MiB host RSS cap, 256 MiB disk / 512 MiB host storage (`NetworkPolicy::Isolated`, `AccelerationPolicy::Preferred`). `cold_boot_spawn` times `RuntimeManager::spawn()`; `cold_boot_first_exec` times from `spawn()` return until the first guest `exec_stream` (`/bin/echo ok`) completes.
- **Warm Checkout (`warm_checkout_spawn`, `warm_checkout_first_exec`):** Pool pre-warmed cleanly to `ready_vms = 1` before each sample (`1 vCPU / 256 MiB RAM`). `warm_checkout_spawn` times `RuntimeManager::spawn()` checkout; `warm_checkout_first_exec` times from `spawn()` return until `/bin/echo ok` completes.
- **Snapshot Restore (`snapshot_restore`):** Explicitly marked `DeferredPostMvp` per `BRD.md` Section 4.1 & Section 6.
- **Container-Ready (`container_ready_cold_podman`, `container_ready_warm_vm`):** VM spec = 2 vCPU, 768 MiB guest RAM, 1024 MiB host RSS cap, 512 MiB disk / 1024 MiB host storage, attached to `DockerCompatServer` on loopback HTTP (`bollard`). `container_ready_cold_podman` measures the first container start on a fresh VM (`podman system service` lazy cold boot + `import_image(echo-http.tar)` + `create_container` + `start_container` + `inspect_container` + Host HTTP `GET 127.0.0.1:<port>/hello` returning `200 OK`); `container_ready_warm_vm` measures subsequent `create_container` + `start_container` + `inspect_container` + Host HTTP `GET 127.0.0.1:<port>/hello` `200 OK` iterations on the Podman-warm VM with `echo-http` pre-imported (stopping and removing each prior container cleanly between iterations).
