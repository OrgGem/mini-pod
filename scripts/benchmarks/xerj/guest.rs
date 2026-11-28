//! Standalone, std-only measurement driver. Build with rustc for Linux musl.
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const RESPONSE_CAP: u64 = 4 * 1024 * 1024;
const PHASES: &[&str] = &[
    "idle",
    "index",
    "first_query",
    "warm_query",
    "reindex",
    "changed_reindex",
];

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

// shortcut: this fixed local Axum endpoint sends Content-Length; reject other
// framing, replace with a library client if the benchmark targets another server.
fn response_body(raw: &[u8]) -> io::Result<&[u8]> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| invalid("missing HTTP headers"))?;
    let header = std::str::from_utf8(&raw[..split]).map_err(|_| invalid("invalid HTTP header"))?;
    let status: u16 = header
        .lines()
        .next()
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid("missing HTTP status"))?;
    if !(200..300).contains(&status) {
        return Err(invalid(format!(
            "HTTP {status}: {}",
            String::from_utf8_lossy(&raw[split + 4..])
        )));
    }
    let mut length = None;
    for line in header.lines().skip(1) {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid header field"))?;
        if key.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("unsupported Transfer-Encoding"));
        }
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(invalid("duplicate Content-Length"));
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| invalid("invalid Content-Length"))?,
            );
        }
    }
    let body = &raw[split + 4..];
    if length != Some(body.len()) {
        return Err(invalid("missing or mismatched Content-Length"));
    }
    Ok(body)
}

fn request(method: &str, path: &str, body: &[u8]) -> io::Result<Vec<u8>> {
    let address: SocketAddr = "127.0.0.1:9200".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:9200\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(body)?;
    let mut raw = Vec::new();
    stream.take(RESPONSE_CAP + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > RESPONSE_CAP {
        return Err(invalid("HTTP response exceeds byte cap"));
    }
    Ok(response_body(&raw)?.to_vec())
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(root: &Path, name: &str) -> io::Result<Command> {
    let mut cmd = Command::new(root.join("xerj"));
    let log = File::create(root.join("results").join(format!("{name}.log")))?;
    cmd.current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .env("RUST_LOG", "warn")
        .env("XERJ_DISABLE_FEEDBACK", "true")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    Ok(cmd)
}

fn status_kib(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == key)
                .then(|| value.split_whitespace().next()?.parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn directory_bytes(path: &Path) -> io::Result<(u64, u64)> {
    let mut total = (0, 0);
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_symlink() {
            return Err(invalid("unexpected symlink in measured directory"));
        }
        let size = if meta.is_dir() {
            directory_bytes(&entry.path())?
        } else {
            (meta.len(), meta.blocks() * 512)
        };
        total.0 += size.0;
        total.1 += size.1;
    }
    Ok(total)
}

fn index(root: &Path, label: &str, worker: &AtomicU32) -> io::Result<f64> {
    let started = Instant::now();
    let mut child = Process(
        command(root, label)?
            .args([
                "autoindex",
                "corpus",
                "--prefix",
                "spike",
                "--no-semantic",
                "--no-graph",
                "--workers",
                "1",
                "--plan",
                "no-vectors",
                "--yes",
                "--url",
                "http://127.0.0.1:9200",
                "--state-dir",
                "autoindex-state",
            ])
            .spawn()?,
    );
    worker.store(child.0.id(), Ordering::Relaxed);
    let result = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(900) {
            return Err(invalid("index deadline exceeded"));
        }
        thread::sleep(Duration::from_millis(100));
    };
    worker.store(0, Ordering::Relaxed);
    if !result.success() {
        return Err(invalid(format!("{label} exited {result}")));
    }
    request("POST", "/spike-*/_refresh", b"{}")?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

fn probe_index(root: &Path, label: &str, worker: &AtomicU32, probes: &mut File) -> io::Result<()> {
    let started = Instant::now();
    let error = match index(root, label, worker) {
        Ok(_) => String::new(),
        Err(error) => error.to_string().replace(['\t', '\n', '\r'], " "),
    };
    writeln!(
        probes,
        "{label}\t{:.3}\t{error}",
        started.elapsed().as_secs_f64() * 1000.0
    )
}

fn run(root: &Path) -> io::Result<()> {
    for name in ["results", "home", "tmp"] {
        fs::create_dir_all(root.join(name))?;
    }
    let result_dir = root.join("results");
    let interfaces = fs::read_dir("/sys/class/net")?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    if interfaces != ["lo"] {
        return Err(invalid(format!(
            "expected only loopback, got {interfaces:?}"
        )));
    }
    for file in ["cpuinfo", "meminfo", "mounts", "net/route"] {
        fs::write(
            result_dir.join(file.replace('/', "-")),
            fs::read(format!("/proc/{file}"))?,
        )?;
    }
    let started = Instant::now();
    let mut server = Process(
        command(root, "server")?
            .args([
                "--insecure",
                "--bind",
                "127.0.0.1",
                "--port",
                "9200",
                "--no-auto-port",
                "--data-dir",
                "xerj-data",
                "--shutdown-timeout",
                "5",
            ])
            .spawn()?,
    );
    let server_pid = server.0.id();
    let worker = Arc::new(AtomicU32::new(0));
    let phase = Arc::new(AtomicUsize::new(0));
    let stopped = Arc::new(AtomicBool::new(false));
    let (w, p, s) = (worker.clone(), phase.clone(), stopped.clone());
    let mut samples = File::create(result_dir.join("memory.tsv"))?;
    writeln!(samples, "elapsed_ms\tphase\tserver_rss_kib\tserver_hwm_kib\tindexer_rss_kib\tindexer_hwm_kib\tguest_available_kib")?;
    let monitor = thread::spawn(move || -> io::Result<()> {
        while !s.load(Ordering::Relaxed) {
            let server_status =
                fs::read_to_string(format!("/proc/{server_pid}/status")).unwrap_or_default();
            let worker_status =
                fs::read_to_string(format!("/proc/{}/status", w.load(Ordering::Relaxed)))
                    .unwrap_or_default();
            let memory = fs::read_to_string("/proc/meminfo")?;
            writeln!(
                samples,
                "{:.3}\t{}\t{}\t{}\t{}\t{}\t{}",
                started.elapsed().as_secs_f64() * 1000.0,
                PHASES[p.load(Ordering::Relaxed)],
                status_kib(&server_status, "VmRSS"),
                status_kib(&server_status, "VmHWM"),
                status_kib(&worker_status, "VmRSS"),
                status_kib(&worker_status, "VmHWM"),
                status_kib(&memory, "MemAvailable")
            )?;
            thread::sleep(Duration::from_millis(200));
        }
        samples.sync_all()
    });
    let result = (|| -> io::Result<()> {
        loop {
            if let Ok(banner) = request("GET", "/", b"") {
                fs::write(result_dir.join("banner.json"), banner)?;
                break;
            }
            if server.0.try_wait()?.is_some() {
                return Err(invalid("server exited before readiness"));
            }
            if started.elapsed() > Duration::from_secs(180) {
                return Err(invalid("server readiness deadline exceeded"));
            }
            thread::sleep(Duration::from_millis(100));
        }
        let mut measurements = File::create(result_dir.join("measurements.tsv"))?;
        writeln!(measurements, "metric\tvalue")?;
        writeln!(
            measurements,
            "startup_ms\t{:.3}",
            started.elapsed().as_secs_f64() * 1000.0
        )?;
        thread::sleep(Duration::from_secs(2));
        phase.store(1, Ordering::Relaxed);
        writeln!(
            measurements,
            "index_ms\t{:.3}",
            index(root, "index", &worker)?
        )?;
        for (label, route) in [
            ("indices", "/_cat/indices?format=json"),
            ("mapping", "/spike-*/_mapping"),
            ("count", "/spike-*/_count"),
            ("stats", "/spike-*/_stats"),
        ] {
            fs::write(
                result_dir.join(format!("{label}.json")),
                request("GET", route, b"")?,
            )?;
        }
        fs::write(
            result_dir.join("initial-flush.json"),
            request("POST", "/_flush", b"{}")?,
        )?;
        let (logical, allocated) = directory_bytes(&root.join("xerj-data"))?;
        writeln!(measurements, "initial_data_logical_bytes\t{logical}")?;
        writeln!(measurements, "initial_data_allocated_bytes\t{allocated}")?;
        let ids = fs::read_to_string(root.join("query-ids.txt"))?;
        let ids: Vec<_> = ids.lines().collect();
        if ids.is_empty()
            || ids.iter().any(|id| {
                id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(invalid("invalid query IDs"));
        }
        let mut timings = File::create(result_dir.join("queries.tsv"))?;
        writeln!(timings, "round\tid\telapsed_ms\tresponse_bytes")?;
        for round in 0..6 {
            phase.store(if round == 0 { 2 } else { 3 }, Ordering::Relaxed);
            for offset in 0..ids.len() {
                let id = ids[(offset + round * 7) % ids.len()];
                let body = fs::read(root.join("requests").join(format!("{id}.json")))?;
                let query_started = Instant::now();
                let response = request("POST", "/spike-*/_search", &body)?;
                let elapsed = query_started.elapsed().as_secs_f64() * 1000.0;
                writeln!(timings, "{round}\t{id}\t{elapsed:.3}\t{}", response.len())?;
                fs::write(
                    result_dir.join(format!("query-{round}-{id}.json")),
                    response,
                )?;
            }
        }
        // Keep incremental-index failures explicit without discarding valid initial-search data.
        let mut probes = File::create(result_dir.join("probes.tsv"))?;
        writeln!(probes, "probe\telapsed_ms\terror")?;
        phase.store(4, Ordering::Relaxed);
        probe_index(root, "unchanged-index", &worker, &mut probes)?;
        // A new file provides an unambiguous freshness probe, outside the quality set.
        fs::write(
            root.join("corpus/freshness.txt"),
            "minipodspikefreshnesssentinelalpha\n",
        )?;
        phase.store(5, Ordering::Relaxed);
        probe_index(root, "changed-index", &worker, &mut probes)?;
        probes.sync_all()?;
        fs::write(result_dir.join("freshness-added.json"), request("POST", "/spike-*/_search",
            br#"{"size":5,"query":{"multi_match":{"query":"minipodspikefreshnesssentinelalpha","fields":["body","text","content"]}}}"#)?)?;
        fs::write(
            result_dir.join("final-flush.json"),
            request("POST", "/_flush", b"{}")?,
        )?;
        for directory in ["xerj-data", "autoindex-state"] {
            let (logical, allocated) = directory_bytes(&root.join(directory))?;
            writeln!(measurements, "{directory}_logical_bytes\t{logical}")?;
            writeln!(measurements, "{directory}_allocated_bytes\t{allocated}")?;
        }
        measurements.sync_all()?;
        phase.store(0, Ordering::Relaxed);
        thread::sleep(Duration::from_secs(2));
        Ok(())
    })();
    stopped.store(true, Ordering::Relaxed);
    let monitor_result = monitor
        .join()
        .map_err(|_| invalid("memory monitor panicked"))?;
    if let Ok(output) = Command::new("/bin/busybox").arg("dmesg").output() {
        fs::write(result_dir.join("kernel.log"), output.stdout)?;
    }
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &server_pid.to_string()])
        .status();
    let shutdown = Instant::now();
    while server.0.try_wait()?.is_none() && shutdown.elapsed() < Duration::from_secs(10) {
        thread::sleep(Duration::from_millis(50));
    }
    result.and(monitor_result)
}

fn main() {
    let root = std::env::args_os().nth(1).expect("usage: guest-bench ROOT");
    if let Err(error) = run(Path::new(&root)) {
        eprintln!("benchmark failed: {error}");
        std::process::exit(1);
    }
    println!("benchmark complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_refuses_truncated_ambiguous_and_error_responses() {
        assert_eq!(
            response_body(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            b"{}"
        );
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 429 Limit\r\nContent-Length: 2\r\n\r\n{}"[..],
        ] {
            assert!(response_body(raw).is_err());
        }
    }
    #[test]
    fn memory_fields_are_exact_and_units_are_kib() {
        assert_eq!(status_kib("VmRSS: 123 kB\nVmHWM: 456 kB\n", "VmRSS"), 123);
        assert_eq!(status_kib("VmRSS: 123 kB\n", "VmHWM"), 0);
    }
}
