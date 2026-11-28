"""Reproducible Windows/TCG spike; uses mini-pod CLI, never launches QEMU directly."""
import argparse
import csv
import ctypes
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import threading
import time
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / ".cache/xerj-spike"
PIN = "35ccd192508027cccc1b3e69f3b6721cb17cac64"
CORPUS_PIN = "e359a799946933c10b2c406d9b30c7a810ab15c2"
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def execute(args, *, timeout=120, check=True, cwd=ROOT):
    result = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            creationflags=FLAGS)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-3000:]} {result.stdout[-1000:]}")
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected(name):
    return name in {"BRD.md", "README.md"} or (
        name.startswith(("crates/", "bins/", "guest/", "docs/"))
        and name.endswith((".rs", ".md")))


def prepare():
    CACHE.mkdir(parents=True, exist_ok=True)
    revision = execute(["git", "rev-parse", CORPUS_PIN]).stdout.strip()
    archive = subprocess.run(["git", "archive", revision], cwd=ROOT, check=True, capture_output=True).stdout
    payload = CACHE / "payload"
    corpus = payload / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    files = {}
    # Read regular files individually; never extract an unvalidated archive path.
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for entry in tar:
            if not selected(entry.name):
                continue
            if not entry.isfile() or ".." in Path(entry.name).parts or Path(entry.name).is_absolute():
                raise RuntimeError(f"Unsafe corpus entry: {entry.name}")
            data = tar.extractfile(entry).read()
            target = corpus / entry.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files[entry.name] = {"bytes": len(data), "sha256": sha(data)}
    fixture = HERE / "diagnostics.jsonl"
    (corpus / "diagnostics").mkdir(exist_ok=True)
    shutil.copyfile(fixture, corpus / "diagnostics/events.jsonl")
    files["diagnostics/events.jsonl"] = {"bytes": fixture.stat().st_size, "sha256": sha(fixture.read_bytes())}
    queries = json.loads((HERE / "queries.json").read_text(encoding="utf-8"))
    for query in queries:
        for path in query["relevant"]:
            if path not in files:
                raise RuntimeError(f"Missing gold path {path}")
        if query["category"] == "negative_exact":
            assert not any(query["query"] in p.read_text(encoding="utf-8") for p in corpus.rglob("*") if p.is_file())
    requests = payload / "requests"
    requests.mkdir(exist_ok=True)
    for query in queries:
        write_json(requests / f'{query["id"]}.json', {
            "size": 5,
            "query": {"multi_match": {"query": query["query"], "type": "best_fields",
                       "fields": ["name^5", "defs^3", "title^2", "body", "text", "code", "message"], "operator": "or"}},
            "_source": ["ax_path", "ax_paths", "path", "line", "start_line", "end_line", "ax_locator", "name", "kind", "code", "title", "message"],
        })
    (payload / "query-ids.txt").write_text("\n".join(q["id"] for q in queries) + "\n", encoding="utf-8")
    manifest = {"xerj_revision": PIN, "corpus_revision": revision, "files": files,
                "file_count": len(files), "source_bytes": sum(f["bytes"] for f in files.values()),
                "queries_sha256": sha((HERE / "queries.json").read_bytes()), "query_count": len(queries)}
    write_json(CACHE / "corpus-manifest.json", manifest)
    print(json.dumps({k: v for k, v in manifest.items() if k != "files"}, indent=2))


class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong)] + [
        (name, ctypes.c_size_t) for name in ["PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
        "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage"]]


def monitor_host(pid, directory, output, stopped):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(MemoryCounters), ctypes.c_ulong]
    kernel.GetCompressedFileSizeW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.GetCompressedFileSizeW.restype = ctypes.c_ulong
    handle = kernel.OpenProcess(0x1010, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    started = time.perf_counter()
    try:
        with output.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file, delimiter="\t")
            writer.writerow(["elapsed_ms", "qemu_rss_bytes", "qemu_peak_rss_bytes", "qemu_private_bytes", "sandbox_allocated_bytes"])
            while not stopped.is_set():
                counters = MemoryCounters()
                counters.cb = ctypes.sizeof(counters)
                if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    raise ctypes.WinError(ctypes.get_last_error())
                allocated = 0
                for path in directory.rglob("*"):
                    try:
                        metadata = path.lstat()
                    except FileNotFoundError:
                        continue
                    # AF_UNIX socket files on Windows are reparse points, not disk data.
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_file_attributes & 0x400:
                        continue
                    high = ctypes.c_ulong()
                    ctypes.set_last_error(0)
                    low = kernel.GetCompressedFileSizeW(str(path), ctypes.byref(high))
                    if low == 0xFFFFFFFF and ctypes.get_last_error():
                        raise OSError(f"Cannot measure {path}: {ctypes.WinError(ctypes.get_last_error())}")
                    allocated += (high.value << 32) | low
                writer.writerow([round((time.perf_counter() - started) * 1000, 3), counters.WorkingSetSize,
                                 counters.PeakWorkingSetSize, counters.PrivateUsage, allocated])
                file.flush()
                stopped.wait(0.5)
    finally:
        kernel.CloseHandle(handle)


def qemu_child(daemon_pid):
    script = f"Get-CimInstance Win32_Process -Filter 'ParentProcessId = {int(daemon_pid)}' | Where-Object Name -eq 'qemu-system-x86_64.exe' | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
    data = json.loads(execute(["powershell", "-NoProfile", "-Command", script]).stdout)
    if isinstance(data, list):
        raise RuntimeError("Expected exactly one QEMU child")
    if "tcg,tb-size=32" not in data["CommandLine"] or "-nic none" not in data["CommandLine"]:
        raise RuntimeError(f"Unexpected QEMU mode: {data['CommandLine']}")
    return data


def run(runs, ram):
    if os.name != "nt":
        raise RuntimeError("This spike's host sampler requires Windows")
    manifest = json.loads((CACHE / "corpus-manifest.json").read_text(encoding="utf-8"))
    if manifest["queries_sha256"] != sha((HERE / "queries.json").read_bytes()):
        raise RuntimeError("Query set changed after corpus preparation")
    payload = CACHE / "payload"
    xerj_bytes = (CACHE / "bin/xerj").read_bytes()
    build = json.loads((CACHE / "bin/build.json").read_text(encoding="utf-8-sig"))
    if build["source_revision"] != PIN or build["xerj_sha256"] != sha(xerj_bytes):
        raise RuntimeError("Binary does not match the pinned build manifest")
    compressed = gzip.compress(xerj_bytes, compresslevel=6, mtime=0)
    (CACHE / "bin/xerj.gz").write_bytes(compressed)
    # The current CLI copy cap is 16 MiB. Transfer bounded chunks through that API.
    transfer = CACHE / "transfer" / sha(compressed)[:16]
    parts = []
    for number, offset in enumerate(range(0, len(compressed), 8 * 1024 * 1024)):
        part = transfer / f"part-{number:03d}"
        part.mkdir(parents=True, exist_ok=True)
        (part / f"xerj.gz.part{number:03d}").write_bytes(compressed[offset:offset + 8 * 1024 * 1024])
        parts.append(part)
    shutil.copyfile(CACHE / "bin/guest-bench", payload / "guest-bench")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = CACHE / "runs" / f"{stamp}-{ram}m"
    output.mkdir(parents=True)
    endpoint = f"npipe://minipod-xerj-spike-{os.getpid()}"
    # Keep the AF_UNIX transport path below Windows sockaddr_un's 108-byte limit.
    state = CACHE / ("s-" + uuid.uuid4().hex[:8])
    bundle = ROOT / ".cache/bundles-perf/8c7be5d/x86_64"
    daemon_args = [ROOT / "target/release/sandboxd.exe", "serve", "--bundle-dir", bundle,
                   "--pub-key-file", ROOT / ".cache/keys/dev-bundle.pub", "--state-dir", state,
                   "--endpoint", endpoint, "--ready-file", output / "ready.json", "--max-sandboxes", "1",
                   "--max-rss-mb", "2048", "--max-storage-mb", "3072"]
    def cli(*args, timeout=120, check=True):
        return execute([ROOT / "target/release/sandbox-cli.exe", "--endpoint", endpoint, "--json", *args], timeout=timeout, check=check)

    metadata = {"manifest": {k: v for k, v in manifest.items() if k != "files"}, "build": build,
                "rustc": (CACHE / "bin/rustc.txt").read_text(encoding="utf-8"),
                "host_cpu": json.loads(execute(["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress"]).stdout),
                "host_revision": execute(["git", "rev-parse", "HEAD"]).stdout.strip(),
                "ram_mib": ram, "vcpus": 1, "host_rss_budget_mib": 2048, "network": "isolated", "acceleration": "software",
                "state_directory": str(state.relative_to(ROOT)),
                "xerj_sha256": sha(xerj_bytes), "xerj_bytes": len(xerj_bytes), "xerj_gzip_bytes": len(compressed),
                "transfer_parts": len(parts), "guest_bench_sha256": sha((payload / "guest-bench").read_bytes()),
                "bundle_manifest_sha256": sha((bundle / "manifest.v1").read_bytes()), "runs": []}
    write_json(output / "metadata.json", metadata)
    daemon_log = (output / "daemon.log").open("w", encoding="utf-8")
    try:
        daemon = subprocess.Popen([str(a) for a in daemon_args], cwd=ROOT, stdout=daemon_log, stderr=subprocess.STDOUT, creationflags=FLAGS)
    except BaseException:
        daemon_log.close()
        raise
    try:
        deadline = time.monotonic() + 30
        while not (output / "ready.json").exists():
            if daemon.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("daemon did not become ready; inspect daemon.log")
            time.sleep(0.1)
        write_json(output / "doctor.json", json.loads(cli("doctor").stdout))
        for number in range(1, runs + 1):
            run_dir = output / f"run-{number}"
            run_dir.mkdir()
            sid = None
            stopped = threading.Event()
            monitor = None
            monitor_errors = []
            record = {"run": number}
            metadata["runs"].append(record)
            try:
                started = time.perf_counter()
                spawn = json.loads(cli("spawn", "--accel", "software", "--network", "isolated", "--vcpus", "1",
                                       "--ram-mb", str(ram), "--rss-mb", "2048", "--disk-mb", "2048",
                                       "--storage-mb", "3072", "--ttl-secs", "3600").stdout)
                record["spawn_ms"] = (time.perf_counter() - started) * 1000
                sid = spawn.get("id") or spawn.get("sandbox_id")
                if not sid:
                    raise RuntimeError(f"No sandbox ID in {spawn}")
                write_json(run_dir / "spawn.json", spawn)
                child = qemu_child(daemon.pid)
                write_json(run_dir / "qemu.json", child)
                def sample():
                    try:
                        monitor_host(child["ProcessId"], state / "sandboxes" / sid, run_dir / "host-memory.tsv", stopped)
                    except Exception as error:
                        monitor_errors.append(str(error))
                monitor = threading.Thread(target=sample)
                monitor.start()
                print(f"run {number}: TCG VM {sid}, copying payload", flush=True)
                started = time.perf_counter()
                cli("copy-in", sid, payload, "/workspace/spike", timeout=180)
                for part in parts:
                    cli("copy-in", sid, part, "/workspace/spike", timeout=180)
                record["copy_in_ms"] = (time.perf_counter() - started) * 1000
                started = time.perf_counter()
                unpack = cli("exec", sid, "--deadline-secs", "120", "--", "/bin/sh", "-c",
                             "cd /workspace/spike && cat xerj.gz.part* > xerj.gz && rm xerj.gz.part* && gunzip xerj.gz", timeout=150)
                if json.loads(unpack.stdout).get("exit_code") != 0:
                    raise RuntimeError(f"Guest unpack failed: {unpack.stdout}")
                record["unpack_ms"] = (time.perf_counter() - started) * 1000
                cli("exec", sid, "--deadline-secs", "30", "--", "/bin/chmod", "+x", "/workspace/spike/xerj", "/workspace/spike/guest-bench")
                digest = cli("exec", sid, "--deadline-secs", "60", "--", "/bin/busybox", "sha256sum", "/workspace/spike/xerj")
                guest_digest = json.loads(digest.stdout)
                write_json(run_dir / "guest-sha256.json", guest_digest)
                if guest_digest.get("exit_code") != 0 or guest_digest.get("stdout", "").split()[0] != metadata["xerj_sha256"]:
                    raise RuntimeError("Guest binary checksum mismatch")
                print(f"run {number}: measuring offline index and queries", flush=True)
                started = time.perf_counter()
                measured = cli("exec", sid, "--deadline-secs", "2400", "--stdout-budget-bytes", "1048576",
                               "--stderr-budget-bytes", "1048576", "--", "/workspace/spike/guest-bench", "/workspace/spike", timeout=2460, check=False)
                record["guest_exec_wall_ms"] = (time.perf_counter() - started) * 1000
                record["cli_exit_code"] = measured.returncode
                (run_dir / "exec.stdout").write_text(measured.stdout, encoding="utf-8")
                (run_dir / "exec.stderr").write_text(measured.stderr, encoding="utf-8")
                record["exec"] = json.loads(measured.stdout) if measured.stdout.strip() else {}
                cli("copy-out", sid, "/workspace/spike/results", run_dir / "guest", timeout=180)
                if measured.returncode or record["exec"].get("exit_code") != 0:
                    raise RuntimeError(f"guest measurement failed: {record['exec']}")
                record["completed"] = True
            except Exception as error:
                record["error"] = str(error)
                raise
            finally:
                stopped.set()
                if monitor:
                    monitor.join(timeout=5)
                if sid:
                    try:
                        cleanup = cli("destroy", sid, timeout=120, check=False)
                        record["destroy_cli_exit_code"] = cleanup.returncode
                        record["destroy_output"] = cleanup.stdout
                    except Exception as error:
                        record["destroy_cli_exit_code"] = -1
                        record["destroy_output"] = str(error)
                record["host_monitor_errors"] = monitor_errors
                record["remaining_overlay_count"] = len(list((state / "sandboxes").rglob("*.qcow2")))
                write_json(output / "metadata.json", metadata)
                print(f"run {number}: cleanup={record.get('destroy_output', '').strip()}", flush=True)
            if monitor_errors or record["remaining_overlay_count"] or record.get("destroy_cli_exit_code") != 0:
                raise RuntimeError("Measurement/cleanup verification failed")
        write_json(output / "final-status.json", json.loads(cli("status").stdout))
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        daemon_log.close()
        print(f"Results: {output}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ram-mib", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.runs <= 5 or not 256 <= args.ram_mib <= 1024:
        parser.error("runs must be 1..5 and RAM 256..1024 MiB")
    prepare() if args.action == "prepare" else run(args.runs, args.ram_mib)
