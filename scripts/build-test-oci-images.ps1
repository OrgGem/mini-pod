[CmdletBinding()]
param(
    [string]$OutDir = ".cache\test-images",
    [ValidateSet("x86_64", "aarch64")]
    [string]$Arch = "x86_64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RustAlpineImage = "rust:alpine@sha256:2cccd8b212b37dad15a555589c1b6787da4ab913fe24d8a9b2d99d3498869409"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutDirPath = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir
} else {
    Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDirPath | Out-Null

$DockerPlatform = if ($Arch -eq "aarch64") { "linux/arm64" } else { "linux/amd64" }

& docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon is not reachable; cannot build offline OCI test images."
}

$BuildRoot = Join-Path $RepoRoot (".cache\tmp-test-images-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null

try {
    $EchoRs = @'
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}

fn handle_client(mut stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 4096];
    let mut acc = Vec::with_capacity(512);
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") || acc.len() >= 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nhello-minipod";
    let _ = stream.write_all(resp);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

fn main() {
    unsafe {
        signal(15, on_signal);
        signal(2, on_signal);
    }
    let listener = TcpListener::bind("0.0.0.0:8080").expect("bind 0.0.0.0:8080");
    listener.set_nonblocking(true).expect("set_nonblocking");

    println!("READY_ON_8080");
    let _ = io::stdout().flush();

    while !SHUTDOWN.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || handle_client(stream));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}
'@

    $RyukRs = @'
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}

#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool,
    Num,
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn parse_value(&mut self) -> Option<Json> {
        self.skip_ws();
        let ch = *self.b.get(self.i)?;
        match ch {
            b'"' => self.parse_str().map(Json::Str),
            b'{' => self.parse_obj(),
            b'[' => self.parse_arr(),
            b't' => {
                self.i = self.i.checked_add(4)?;
                Some(Json::Bool)
            }
            b'f' => {
                self.i = self.i.checked_add(5)?;
                Some(Json::Bool)
            }
            b'n' => {
                self.i = self.i.checked_add(4)?;
                Some(Json::Null)
            }
            b'-' | b'0'..=b'9' => {
                while self.i < self.b.len()
                    && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    self.i += 1;
                }
                Some(Json::Num)
            }
            _ => None,
        }
    }

    fn parse_str(&mut self) -> Option<String> {
        if *self.b.get(self.i)? != b'"' {
            return None;
        }
        self.i += 1;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if c == b'"' {
                return Some(out);
            }
            if c == b'\\' {
                let esc = *self.b.get(self.i)?;
                self.i += 1;
                match esc {
                    b'"' | b'\\' | b'/' => out.push(esc as char),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
                        self.i += 4;
                        if let Ok(code) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                    }
                    other => out.push(other as char),
                }
            } else {
                out.push(c as char);
            }
        }
        None
    }

    fn parse_arr(&mut self) -> Option<Json> {
        self.i += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Some(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match *self.b.get(self.i)? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(Json::Arr(items));
                }
                _ => return None,
            }
        }
    }

    fn parse_obj(&mut self) -> Option<Json> {
        self.i += 1;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Some(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let k = self.parse_str()?;
            self.skip_ws();
            if *self.b.get(self.i)? != b':' {
                return None;
            }
            self.i += 1;
            let v = self.parse_value()?;
            pairs.push((k, v));
            self.skip_ws();
            match *self.b.get(self.i)? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(Json::Obj(pairs));
                }
                _ => return None,
            }
        }
    }
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_label_filters(line: &str, out: &mut Vec<(String, Option<String>)>) -> bool {
    let mut added = false;
    for part in line.trim().split('&') {
        if let Some((raw_k, raw_v)) = part.split_once('=') {
            if raw_k == "label" {
                let decoded = pct_decode(raw_v);
                if let Some((lk, lv)) = decoded.split_once('=') {
                    out.push((lk.to_string(), Some(lv.to_string())));
                    added = true;
                } else if !decoded.is_empty() {
                    out.push((decoded, None));
                    added = true;
                }
            }
        }
    }
    added
}

fn decode_chunked(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let crlf = raw.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&raw[..crlf]).ok()?.trim();
        let hex = line.split(';').next()?.trim();
        let len = usize::from_str_radix(hex, 16).ok()?;
        raw = &raw[crlf + 2..];
        if len == 0 {
            return Some(out);
        }
        if raw.len() < len + 2 {
            return None;
        }
        out.extend_from_slice(&raw[..len]);
        raw = &raw[len + 2..];
    }
}

fn docker_unix_request(req: &str) -> io::Result<Vec<u8>> {
    let mut sock = UnixStream::connect("/var/run/docker.sock")?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
    sock.write_all(req.as_bytes())?;
    sock.flush()?;
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp)?;
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing header separator"))?;
    let headers = String::from_utf8_lossy(&resp[..split]).to_ascii_lowercase();
    let body = &resp[split + 4..];
    if headers.contains("transfer-encoding: chunked") {
        decode_chunked(body).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunked"))
    } else {
        Ok(body.to_vec())
    }
}

fn reap_matching_containers(filters: &[(String, Option<String>)]) {
    if filters.is_empty() {
        return;
    }
    let body = match docker_unix_request(
        "GET /v1.41/containers/json?all=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ryuk: failed to list containers via docker.sock: {e}");
            return;
        }
    };

    let mut parser = Parser { b: &body, i: 0 };
    let Some(Json::Arr(containers)) = parser.parse_value() else {
        eprintln!("ryuk: unexpected containers json payload");
        return;
    };

    for item in containers {
        let Json::Obj(fields) = item else { continue };
        let mut id = None;
        let mut image = "";
        let mut labels: Option<&Vec<(String, Json)>> = None;
        for (k, v) in &fields {
            match (k.as_str(), v) {
                ("Id", Json::Str(s)) => id = Some(s.as_str()),
                ("Image", Json::Str(s)) => image = s.as_str(),
                ("Labels", Json::Obj(pairs)) => labels = Some(pairs),
                _ => {}
            }
        }
        if image.contains("testcontainers/ryuk") {
            continue;
        }
        let (Some(id), Some(labels)) = (id, labels) else {
            continue;
        };
        let matched = filters.iter().any(|(fk, fv)| {
            labels.iter().any(|(lk, lv)| match lv {
                Json::Str(s) => lk == fk && fv.as_ref().map(|expected| expected == s).unwrap_or(true),
                _ => false,
            })
        });
        if matched {
            let del_req = format!(
                "DELETE /v1.41/containers/{id}?v=true&force=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            );
            match docker_unix_request(&del_req) {
                Ok(_) => eprintln!("ryuk: reaped container {id}"),
                Err(e) => eprintln!("ryuk: failed to delete {id}: {e}"),
            }
        }
    }
}

fn handle_client(stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let mut reader = BufReader::new(stream);
    let mut filters = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    continue;
                }
                if parse_label_filters(&line, &mut filters) {
                    let _ = reader.get_mut().write_all(b"ACK\n");
                    let _ = reader.get_mut().flush();
                } else {
                    let _ = reader.get_mut().write_all(b"ERR invalid filter\n");
                    let _ = reader.get_mut().flush();
                }
            }
        }
    }
    if !filters.is_empty() {
        thread::sleep(Duration::from_millis(150));
        reap_matching_containers(&filters);
    }
}

fn main() {
    unsafe {
        signal(15, on_signal);
        signal(2, on_signal);
    }
    let listener = TcpListener::bind("0.0.0.0:8080").expect("bind 0.0.0.0:8080");
    listener.set_nonblocking(true).expect("set_nonblocking");

    println!("Pinging Docker...");
    println!("Started");
    let _ = io::stdout().flush();

    while !SHUTDOWN.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || handle_client(stream));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}
'@

    $Dockerfile = @"
FROM $RustAlpineImage AS builder
RUN apk add --no-cache busybox-static >/dev/null
WORKDIR /src
COPY echo-http.rs ryuk.rs ./
RUN rustc --edition 2021 -O -C opt-level=z -C panic=abort -C strip=symbols -C target-feature=+crt-static echo-http.rs -o /echo-http && \
    rustc --edition 2021 -O -C opt-level=z -C panic=abort -C strip=symbols -C target-feature=+crt-static ryuk.rs -o /ryuk && \
    mkdir -p /out-echo/bin /out-echo/etc /out-echo/tmp /out-echo/work && \
    cp /echo-http /out-echo/echo-http && chmod 0755 /out-echo/echo-http && \
    cp /bin/busybox.static /out-echo/bin/busybox && chmod 0755 /out-echo/bin/busybox && \
    for cmd in sh cat echo printf ls mkdir rm sleep setsid chmod touch tar; do ln -s busybox "/out-echo/bin/`$cmd"; done && \
    printf 'root:x:0:0:root:/root:/bin/sh\n' > /out-echo/etc/passwd && \
    printf 'root:x:0:\n' > /out-echo/etc/group && \
    chmod 0644 /out-echo/etc/passwd /out-echo/etc/group && \
    chmod 1777 /out-echo/tmp && chmod 0777 /out-echo/work && \
    mkdir -p /out-ryuk/var/run && \
    cp /ryuk /out-ryuk/ryuk && chmod 0755 /out-ryuk/ryuk

FROM scratch AS echo-http
COPY --from=builder /out-echo/ /
EXPOSE 8080
ENTRYPOINT ["/echo-http"]

FROM scratch AS ryuk
COPY --from=builder /out-ryuk/ /
EXPOSE 8080
ENTRYPOINT ["/ryuk"]
"@

    [System.IO.File]::WriteAllText((Join-Path $BuildRoot "echo-http.rs"), ($EchoRs -replace "`r`n", "`n"))
    [System.IO.File]::WriteAllText((Join-Path $BuildRoot "ryuk.rs"), ($RyukRs -replace "`r`n", "`n"))
    [System.IO.File]::WriteAllText((Join-Path $BuildRoot "Dockerfile"), ($Dockerfile -replace "`r`n", "`n"))

    $EchoTar = Join-Path $OutDirPath "echo-http.tar"
    $RyukTar = Join-Path $OutDirPath "ryuk.tar"

    Write-Host "Building offline OCI test image minipod-e2e/echo-http:1.0 ($DockerPlatform)..."
    & docker build --platform $DockerPlatform --target echo-http -t "minipod-e2e/echo-http:1.0" $BuildRoot
    if ($LASTEXITCODE -ne 0) {
        throw "docker build echo-http failed with exit code $LASTEXITCODE"
    }
    & docker save -o $EchoTar "minipod-e2e/echo-http:1.0"
    if ($LASTEXITCODE -ne 0) {
        throw "docker save echo-http failed with exit code $LASTEXITCODE"
    }

    Write-Host "Building offline OCI test image testcontainers/ryuk:0.11.0 ($DockerPlatform)..."
    & docker build --platform $DockerPlatform --target ryuk -t "testcontainers/ryuk:0.11.0" $BuildRoot
    if ($LASTEXITCODE -ne 0) {
        throw "docker build ryuk failed with exit code $LASTEXITCODE"
    }
    & docker tag "testcontainers/ryuk:0.11.0" "docker.io/testcontainers/ryuk:0.11.0"
    if ($LASTEXITCODE -ne 0) {
        throw "docker tag docker.io/testcontainers/ryuk:0.11.0 failed with exit code $LASTEXITCODE"
    }
    & docker save -o $RyukTar "testcontainers/ryuk:0.11.0"
    if ($LASTEXITCODE -ne 0) {
        throw "docker save ryuk failed with exit code $LASTEXITCODE"
    }

    $EchoSize = (Get-Item $EchoTar).Length
    $RyukSize = (Get-Item $RyukTar).Length
    Write-Host "Built test OCI archives:"
    Write-Host "  $EchoTar ($EchoSize bytes)"
    Write-Host "  $RyukTar ($RyukSize bytes)"
} finally {
    if (Test-Path $BuildRoot) {
        Remove-Item -Recurse -Force -Path $BuildRoot -ErrorAction SilentlyContinue
    }
}
