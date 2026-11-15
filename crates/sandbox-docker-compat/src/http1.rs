//! Bounded HTTP/1.1 wire framing, smuggling validation, carry-over buffering, and body streaming.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Maximum permitted byte length of an HTTP/1.1 request or response head (including `\r\n\r\n`).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default maximum buffered body size (16 MiB) for JSON/control payloads read into memory.
pub const MAX_BUFFERED_BODY_BYTES: usize = 16 * 1024 * 1024;

const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
const STREAM_COPY_BUF_BYTES: usize = 16 * 1024;

/// Errors returned during HTTP/1.1 wire parsing, smuggling checks, or body streaming.
#[derive(Debug)]
pub enum HttpError {
    Io(io::Error),
    MalformedHead(String),
    HeadersTooLarge { limit: usize },
    BodyTooLarge { limit: usize },
    InvalidChunk(String),
    UnexpectedEof,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "HTTP I/O error: {err}"),
            Self::MalformedHead(msg) => write!(f, "malformed HTTP head: {msg}"),
            Self::HeadersTooLarge { limit } => {
                write!(f, "HTTP headers exceed limit of {limit} bytes")
            }
            Self::BodyTooLarge { limit } => {
                write!(f, "HTTP body exceeds buffered limit of {limit} bytes")
            }
            Self::InvalidChunk(msg) => write!(f, "invalid HTTP chunked encoding: {msg}"),
            Self::UnexpectedEof => write!(f, "unexpected EOF while reading HTTP message"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for HttpError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Framing mode for an HTTP/1.1 message body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyMode {
    Empty,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

/// Parsed HTTP/1.1 request start-line and validated headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestHead {
    pub method: String,
    pub raw_target: String,
    pub path: String,
    pub query: Option<String>,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequestHead {
    /// Returns the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// Returns all header values matching `name` (case-insensitive) in wire order.
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        find_headers_all(&self.headers, name)
    }

    /// Returns the parsed `Content-Length` when exactly one valid numeric header is present.
    pub fn content_length(&self) -> Option<u64> {
        parse_single_content_length(&self.headers)
    }

    /// Returns `true` when `Transfer-Encoding` ends with `chunked` (case-insensitive).
    pub fn is_chunked(&self) -> bool {
        has_chunked_encoding(&self.headers)
    }

    /// Returns `true` when `Connection` includes `upgrade` and a non-empty `Upgrade` header is set.
    pub fn wants_upgrade(&self) -> bool {
        has_connection_token(&self.headers, "upgrade")
            && self.header("upgrade").is_some_and(|v| !v.trim().is_empty())
    }

    /// Returns `true` when the connection must not be reused after this request/response pair.
    pub fn wants_close(&self) -> bool {
        connection_wants_close(&self.version, &self.headers)
    }

    /// Determines the HTTP/1.1 request body framing mode.
    pub fn body_mode(&self) -> BodyMode {
        if self.is_chunked() {
            BodyMode::Chunked
        } else if let Some(len) = self.content_length() {
            BodyMode::ContentLength(len)
        } else {
            BodyMode::Empty
        }
    }
}

/// Parsed HTTP/1.1 response status-line and validated headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponseHead {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponseHead {
    /// Returns the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// Returns all header values matching `name` (case-insensitive) in wire order.
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        find_headers_all(&self.headers, name)
    }

    /// Returns the parsed `Content-Length` when exactly one valid numeric header is present.
    pub fn content_length(&self) -> Option<u64> {
        parse_single_content_length(&self.headers)
    }

    /// Returns `true` when `Transfer-Encoding` ends with `chunked` (case-insensitive).
    pub fn is_chunked(&self) -> bool {
        has_chunked_encoding(&self.headers)
    }

    /// Returns `true` when the connection should be closed after this response.
    pub fn wants_close(&self) -> bool {
        connection_wants_close(&self.version, &self.headers)
    }

    /// Returns `true` when the status code is `101 Switching Protocols` / `101 UPGRADED`.
    pub fn is_upgrade(&self) -> bool {
        self.status == 101
    }

    /// Determines the HTTP/1.1 response body framing mode per RFC 9112 §6.3.
    pub fn body_mode(&self, request_method: &str) -> BodyMode {
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..=199).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return BodyMode::Empty;
        }
        if self.is_chunked() {
            BodyMode::Chunked
        } else if let Some(len) = self.content_length() {
            BodyMode::ContentLength(len)
        } else {
            BodyMode::UntilEof
        }
    }
}

/// Buffered reader wrapper that preserves bytes already read past `\r\n\r\n` or chunk boundaries
/// so subsequent body readers or `hijack::relay_upgraded` receive every unconsumed byte verbatim.
#[derive(Debug)]
pub struct PrefixedReader<R> {
    inner: R,
    unconsumed: Vec<u8>,
    pos: usize,
}

impl<R> PrefixedReader<R> {
    /// Creates a new `PrefixedReader` with an empty carry-over buffer.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            unconsumed: Vec::new(),
            pos: 0,
        }
    }

    /// Creates a `PrefixedReader` pre-populated with unconsumed prefix bytes.
    pub fn with_prefix(inner: R, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            unconsumed: prefix,
            pos: 0,
        }
    }

    /// Returns a slice of unconsumed carry-over bytes currently buffered in memory.
    pub fn unconsumed(&self) -> &[u8] {
        &self.unconsumed[self.pos..]
    }

    /// Drains and returns all currently buffered unconsumed bytes.
    pub fn take_unconsumed(&mut self) -> Vec<u8> {
        self.drain_unconsumed()
    }

    /// Consumes the wrapper and returns `(inner_stream, unconsumed_bytes)`.
    pub fn into_parts(mut self) -> (R, Vec<u8>) {
        let remaining = self.drain_unconsumed();
        (self.inner, remaining)
    }

    fn drain_unconsumed(&mut self) -> Vec<u8> {
        if self.pos >= self.unconsumed.len() {
            self.unconsumed.clear();
            self.pos = 0;
            return Vec::new();
        }
        if self.pos == 0 {
            return std::mem::take(&mut self.unconsumed);
        }
        let out = self.unconsumed[self.pos..].to_vec();
        self.unconsumed.clear();
        self.pos = 0;
        out
    }

    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.pos >= self.unconsumed.len() {
            self.unconsumed.clear();
            self.pos = 0;
        } else {
            self.unconsumed.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn advance_pos(&mut self, consumed: usize) {
        self.pos += consumed;
        if self.pos >= self.unconsumed.len() {
            self.unconsumed.clear();
            self.pos = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> PrefixedReader<R> {
    async fn read_head_bytes(&mut self, allow_clean_eof: bool) -> Result<Option<Vec<u8>>, HttpError> {
        self.compact();
        let mut scanned_up_to = 0usize;
        let mut tmp = [0u8; 4096];

        loop {
            let search_from = scanned_up_to.saturating_sub(3);
            if let Some(rel_end) = find_double_crlf(&self.unconsumed[search_from..]) {
                let header_end = search_from + rel_end + 4;
                if header_end > MAX_HEADER_BYTES {
                    return Err(HttpError::HeadersTooLarge {
                        limit: MAX_HEADER_BYTES,
                    });
                }
                let head = self.unconsumed[..header_end].to_vec();
                self.advance_pos(header_end);
                return Ok(Some(head));
            }

            if self.unconsumed.len() >= MAX_HEADER_BYTES {
                return Err(HttpError::HeadersTooLarge {
                    limit: MAX_HEADER_BYTES,
                });
            }

            scanned_up_to = self.unconsumed.len();
            let n = self.inner.read(&mut tmp).await?;
            if n == 0 {
                if self.unconsumed.is_empty() && allow_clean_eof {
                    return Ok(None);
                }
                return Err(HttpError::UnexpectedEof);
            }
            self.unconsumed.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_line_crlf(&mut self, max_len: usize) -> Result<String, HttpError> {
        self.compact();
        let mut scanned_up_to = 0usize;
        let mut tmp = [0u8; 1024];

        loop {
            for idx in scanned_up_to..self.unconsumed.len() {
                if self.unconsumed[idx] == b'\n' {
                    if idx == 0 || self.unconsumed[idx - 1] != b'\r' {
                        return Err(HttpError::InvalidChunk(
                            "bare LF without CR in chunk line".to_owned(),
                        ));
                    }
                    let line_end = idx - 1;
                    if idx + 1 > max_len {
                        return Err(HttpError::InvalidChunk(format!(
                            "chunk line exceeds {max_len} bytes"
                        )));
                    }
                    let line_bytes = &self.unconsumed[..line_end];
                    if line_bytes.contains(&b'\r') {
                        return Err(HttpError::InvalidChunk(
                            "bare CR inside chunk line".to_owned(),
                        ));
                    }
                    let line = std::str::from_utf8(line_bytes)
                        .map_err(|_| HttpError::InvalidChunk("non-UTF-8 chunk line".to_owned()))?
                        .to_owned();
                    self.advance_pos(idx + 1);
                    return Ok(line);
                }
            }

            if self.unconsumed.len() >= max_len {
                return Err(HttpError::InvalidChunk(format!(
                    "chunk line exceeds {max_len} bytes"
                )));
            }

            scanned_up_to = self.unconsumed.len();
            let n = self.inner.read(&mut tmp).await?;
            if n == 0 {
                return Err(HttpError::UnexpectedEof);
            }
            self.unconsumed.extend_from_slice(&tmp[..n]);
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.unconsumed.len() {
            let avail = self.unconsumed.len() - self.pos;
            let to_copy = avail.min(buf.remaining());
            let end = self.pos + to_copy;
            buf.put_slice(&self.unconsumed[self.pos..end]);
            self.advance_pos(to_copy);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrefixedReader<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Reads and validates an HTTP/1.1 request head, returning `Ok(None)` on clean EOF before bytes arrive.
pub async fn read_request_head<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> Result<Option<HttpRequestHead>, HttpError> {
    let Some(raw_head) = reader.read_head_bytes(true).await? else {
        return Ok(None);
    };
    let head = parse_request_head_bytes(&raw_head)?;
    Ok(Some(head))
}

/// Reads and validates an HTTP/1.1 response head.
pub async fn read_response_head<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> Result<HttpResponseHead, HttpError> {
    let raw_head = reader
        .read_head_bytes(false)
        .await?
        .ok_or(HttpError::UnexpectedEof)?;
    parse_response_head_bytes(&raw_head)
}

/// Serializes and flushes an HTTP/1.1 request head onto `writer`.
pub async fn write_request_head<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &HttpRequestHead,
) -> Result<(), HttpError> {
    ensure_no_crlf_or_nul(&head.method, "method")?;
    ensure_no_crlf_or_nul(&head.raw_target, "request-target")?;
    ensure_no_crlf_or_nul(&head.version, "HTTP version")?;

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.raw_target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.version.as_bytes());
    out.extend_from_slice(b"\r\n");
    append_headers(&mut out, &head.headers)?;
    out.extend_from_slice(b"\r\n");

    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Serializes and flushes an HTTP/1.1 response head onto `writer`.
pub async fn write_response_head<W: AsyncWrite + Unpin>(
    writer: &mut W,
    head: &HttpResponseHead,
) -> Result<(), HttpError> {
    ensure_no_crlf_or_nul(&head.version, "HTTP version")?;
    ensure_no_crlf_or_nul(&head.reason, "reason phrase")?;
    if !(100..=599).contains(&head.status) {
        return Err(HttpError::MalformedHead(format!(
            "invalid HTTP status code {}",
            head.status
        )));
    }

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(head.version.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.reason.as_bytes());
    out.extend_from_slice(b"\r\n");
    append_headers(&mut out, &head.headers)?;
    out.extend_from_slice(b"\r\n");

    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

/// Writes a Docker Engine API compatible JSON error response `{"message": "..."}`.
pub async fn write_json_error<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    reason: &str,
    message: &str,
    close_conn: bool,
) -> Result<(), HttpError> {
    let body = serde_json::json!({ "message": message }).to_string();
    let mut headers = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Content-Length".to_owned(), body.len().to_string()),
    ];
    if close_conn {
        headers.push(("Connection".to_owned(), "close".to_owned()));
    }
    let head = HttpResponseHead {
        version: "HTTP/1.1".to_owned(),
        status,
        reason: reason.to_owned(),
        headers,
    };
    write_response_head(writer, &head).await?;
    writer.write_all(body.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads and decodes a bounded HTTP/1.1 message body (`ContentLength` or `Chunked`) into RAM.
pub async fn read_body_bytes<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
    mode: BodyMode,
    max_bytes: usize,
) -> Result<Vec<u8>, HttpError> {
    match mode {
        BodyMode::Empty => Ok(Vec::new()),
        BodyMode::ContentLength(len) => {
            if len > max_bytes as u64 {
                return Err(HttpError::BodyTooLarge { limit: max_bytes });
            }
            let target = len as usize;
            let mut out = Vec::with_capacity(target.min(64 * 1024));
            let mut remaining = target;
            let mut buf = [0u8; STREAM_COPY_BUF_BYTES];
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(HttpError::UnexpectedEof);
                }
                out.extend_from_slice(&buf[..n]);
                remaining -= n;
            }
            Ok(out)
        }
        BodyMode::Chunked => {
            let mut out = Vec::new();
            loop {
                let line = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES).await?;
                let chunk_len = parse_chunk_size_line(&line)?;
                if chunk_len == 0 {
                    let _trailers = read_chunked_trailers(reader).await?;
                    break;
                }
                let next_total = (out.len() as u64)
                    .checked_add(chunk_len)
                    .ok_or(HttpError::BodyTooLarge { limit: max_bytes })?;
                if next_total > max_bytes as u64 {
                    return Err(HttpError::BodyTooLarge { limit: max_bytes });
                }
                let mut remaining = chunk_len as usize;
                let mut buf = [0u8; STREAM_COPY_BUF_BYTES];
                while remaining > 0 {
                    let to_read = remaining.min(buf.len());
                    let n = reader.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        return Err(HttpError::UnexpectedEof);
                    }
                    out.extend_from_slice(&buf[..n]);
                    remaining -= n;
                }
                expect_chunk_crlf(reader).await?;
            }
            Ok(out)
        }
        BodyMode::UntilEof => {
            let mut out = Vec::new();
            let mut buf = [0u8; STREAM_COPY_BUF_BYTES];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if out.len().saturating_add(n) > max_bytes {
                    return Err(HttpError::BodyTooLarge { limit: max_bytes });
                }
                out.extend_from_slice(&buf[..n]);
            }
            Ok(out)
        }
    }
}

/// Streams an HTTP/1.1 body through in fixed-size slices without buffering unbounded streams in RAM.
///
/// Flushes writes after every read slice and every chunk so streaming endpoints (`/logs?follow=1`,
/// `/events`) deliver output incrementally in real time. Returns total payload bytes forwarded.
pub async fn forward_body<R, W>(
    reader: &mut PrefixedReader<R>,
    writer: &mut W,
    mode: BodyMode,
) -> Result<u64, HttpError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; STREAM_COPY_BUF_BYTES];
    match mode {
        BodyMode::Empty => Ok(0),
        BodyMode::ContentLength(total) => {
            let mut remaining = total;
            while remaining > 0 {
                let to_read = (remaining as usize).min(buf.len());
                let n = reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    return Err(HttpError::UnexpectedEof);
                }
                writer.write_all(&buf[..n]).await?;
                writer.flush().await?;
                remaining -= n as u64;
            }
            Ok(total)
        }
        BodyMode::UntilEof => {
            let mut total = 0u64;
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
                writer.flush().await?;
                total = total.saturating_add(n as u64);
            }
            Ok(total)
        }
        BodyMode::Chunked => {
            let mut total = 0u64;
            loop {
                let line = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES).await?;
                let chunk_len = parse_chunk_size_line(&line)?;
                if chunk_len == 0 {
                    let trailers = read_chunked_trailers(reader).await?;
                    writer.write_all(b"0\r\n").await?;
                    if !trailers.is_empty() {
                        let mut trailer_buf = Vec::new();
                        append_headers(&mut trailer_buf, &trailers)?;
                        writer.write_all(&trailer_buf).await?;
                    }
                    writer.write_all(b"\r\n").await?;
                    writer.flush().await?;
                    return Ok(total);
                }

                let header = format!("{chunk_len:x}\r\n");
                writer.write_all(header.as_bytes()).await?;

                let mut remaining = chunk_len;
                while remaining > 0 {
                    let to_read = (remaining as usize).min(buf.len());
                    let n = reader.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        return Err(HttpError::UnexpectedEof);
                    }
                    writer.write_all(&buf[..n]).await?;
                    writer.flush().await?;
                    remaining -= n as u64;
                }
                expect_chunk_crlf(reader).await?;
                writer.write_all(b"\r\n").await?;
                writer.flush().await?;

                total = total
                    .checked_add(chunk_len)
                    .ok_or_else(|| HttpError::InvalidChunk("chunked payload overflow".to_owned()))?;
            }
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn split_head_lines(raw_head: &[u8]) -> Result<Vec<&[u8]>, HttpError> {
    let without_term = raw_head
        .strip_suffix(b"\r\n\r\n")
        .ok_or_else(|| HttpError::MalformedHead("missing CRLFCRLF terminator".to_owned()))?;

    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut idx = 0usize;
    while idx < without_term.len() {
        match without_term[idx] {
            b'\n' => {
                return Err(HttpError::MalformedHead(
                    "bare LF without CR inside header block".to_owned(),
                ));
            }
            b'\r' => {
                if idx + 1 >= without_term.len() || without_term[idx + 1] != b'\n' {
                    return Err(HttpError::MalformedHead(
                        "bare CR without LF inside header block".to_owned(),
                    ));
                }
                lines.push(&without_term[start..idx]);
                idx += 2;
                start = idx;
            }
            _ => idx += 1,
        }
    }
    lines.push(&without_term[start..]);
    Ok(lines)
}

fn parse_request_head_bytes(raw_head: &[u8]) -> Result<HttpRequestHead, HttpError> {
    let lines = split_head_lines(raw_head)?;
    let (&first_line, header_lines) = lines
        .split_first()
        .ok_or_else(|| HttpError::MalformedHead("empty HTTP request".to_owned()))?;

    let start_str = std::str::from_utf8(first_line)
        .map_err(|_| HttpError::MalformedHead("non-UTF-8 request line".to_owned()))?;
    let parts: Vec<&str> = start_str.split(' ').collect();
    if parts.len() != 3 {
        return Err(HttpError::MalformedHead(
            "request line must have exactly 3 SP-separated parts".to_owned(),
        ));
    }
    let (method, raw_target, version) = (parts[0], parts[1], parts[2]);
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(HttpError::MalformedHead(format!(
            "invalid HTTP method '{method}'"
        )));
    }
    if raw_target.is_empty()
        || raw_target
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7F)
    {
        return Err(HttpError::MalformedHead(
            "invalid request-target".to_owned(),
        ));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::MalformedHead(format!(
            "unsupported HTTP version '{version}'"
        )));
    }

    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (raw_target.to_owned(), None),
    };

    let headers = parse_and_validate_headers(header_lines, true)?;
    Ok(HttpRequestHead {
        method: method.to_owned(),
        raw_target: raw_target.to_owned(),
        path,
        query,
        version: version.to_owned(),
        headers,
    })
}

fn parse_response_head_bytes(raw_head: &[u8]) -> Result<HttpResponseHead, HttpError> {
    let lines = split_head_lines(raw_head)?;
    let (&first_line, header_lines) = lines
        .split_first()
        .ok_or_else(|| HttpError::MalformedHead("empty HTTP response".to_owned()))?;

    let start_str = std::str::from_utf8(first_line)
        .map_err(|_| HttpError::MalformedHead("non-UTF-8 status line".to_owned()))?;
    let (version, rest) = start_str.split_once(' ').ok_or_else(|| {
        HttpError::MalformedHead("response status line missing version/status".to_owned())
    })?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::MalformedHead(format!(
            "unsupported HTTP version '{version}'"
        )));
    }

    let (status_str, reason) = match rest.split_once(' ') {
        Some((s, r)) => (s, r),
        None => (rest, ""),
    };
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::MalformedHead(format!(
            "invalid HTTP status code '{status_str}'"
        )));
    }
    let status: u16 = status_str
        .parse()
        .map_err(|_| HttpError::MalformedHead("invalid status code".to_owned()))?;
    if !(100..=599).contains(&status) {
        return Err(HttpError::MalformedHead(format!(
            "HTTP status out of range: {status}"
        )));
    }
    if reason.bytes().any(is_disallowed_header_char) {
        return Err(HttpError::MalformedHead(
            "invalid control character in reason phrase".to_owned(),
        ));
    }

    let headers = parse_and_validate_headers(header_lines, true)?;
    Ok(HttpResponseHead {
        version: version.to_owned(),
        status,
        reason: reason.to_owned(),
        headers,
    })
}

fn parse_and_validate_headers(
    header_lines: &[&[u8]],
    allow_framing_headers: bool,
) -> Result<Vec<(String, String)>, HttpError> {
    let mut headers = Vec::with_capacity(header_lines.len());
    for &line in header_lines {
        if line.is_empty() {
            return Err(HttpError::MalformedHead(
                "unexpected empty header line".to_owned(),
            ));
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(HttpError::MalformedHead(
                "obsolete line folding in HTTP headers is forbidden".to_owned(),
            ));
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| HttpError::MalformedHead("header line missing ':'".to_owned()))?;

        let name_bytes = &line[..colon];
        let val_bytes = &line[colon + 1..];
        if name_bytes.is_empty() || !name_bytes.iter().copied().all(is_tchar) {
            return Err(HttpError::MalformedHead(
                "invalid HTTP header field name".to_owned(),
            ));
        }
        if val_bytes.iter().copied().any(is_disallowed_header_char) {
            return Err(HttpError::MalformedHead(
                "invalid control character in header value".to_owned(),
            ));
        }

        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| HttpError::MalformedHead("non-UTF-8 header name".to_owned()))?
            .to_owned();
        let val = std::str::from_utf8(val_bytes)
            .map_err(|_| HttpError::MalformedHead("non-UTF-8 header value".to_owned()))?
            .trim_matches(|c| c == ' ' || c == '\t')
            .to_owned();
        headers.push((name, val));
    }

    validate_framing_headers(&headers, allow_framing_headers)?;
    Ok(headers)
}

fn validate_framing_headers(
    headers: &[(String, String)],
    allow_framing_headers: bool,
) -> Result<(), HttpError> {
    let cl_values = find_headers_all(headers, "content-length");
    let te_values = find_headers_all(headers, "transfer-encoding");
    let host_values = find_headers_all(headers, "host");

    if !allow_framing_headers
        && (!cl_values.is_empty() || !te_values.is_empty() || !host_values.is_empty())
    {
        return Err(HttpError::InvalidChunk(
            "framing headers are forbidden in chunked trailers".to_owned(),
        ));
    }

    if host_values.len() > 1 {
        return Err(HttpError::MalformedHead(
            "duplicate Host header is forbidden".to_owned(),
        ));
    }
    if cl_values.len() > 1 {
        return Err(HttpError::MalformedHead(
            "duplicate or conflicting Content-Length headers are forbidden".to_owned(),
        ));
    }
    if !cl_values.is_empty() && !te_values.is_empty() {
        return Err(HttpError::MalformedHead(
            "simultaneous Content-Length and Transfer-Encoding headers are forbidden".to_owned(),
        ));
    }

    if let Some(&cl_raw) = cl_values.first() {
        parse_strict_content_length(cl_raw).ok_or_else(|| {
            HttpError::MalformedHead(format!("invalid Content-Length value '{cl_raw}'"))
        })?;
    }

    if !te_values.is_empty() {
        validate_transfer_encoding_values(&te_values)?;
    }

    Ok(())
}

fn parse_strict_content_length(raw: &str) -> Option<u64> {
    let trimmed = raw.trim_matches(|c| c == ' ' || c == '\t');
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

fn validate_transfer_encoding_values(values: &[&str]) -> Result<(), HttpError> {
    let mut codings = Vec::new();
    for raw in values {
        for part in raw.split(',') {
            let token = part.trim_matches(|c| c == ' ' || c == '\t');
            if token.is_empty() || !token.bytes().all(is_tchar) {
                return Err(HttpError::MalformedHead(format!(
                    "invalid Transfer-Encoding token '{token}'"
                )));
            }
            codings.push(token.to_ascii_lowercase());
        }
    }
    if codings.is_empty() {
        return Err(HttpError::MalformedHead(
            "empty Transfer-Encoding header".to_owned(),
        ));
    }
    let last = codings.last().map(String::as_str);
    if last != Some("chunked") {
        return Err(HttpError::MalformedHead(
            "Transfer-Encoding must terminate with 'chunked'".to_owned(),
        ));
    }
    for coding in &codings[..codings.len() - 1] {
        match coding.as_str() {
            "gzip" | "x-gzip" | "deflate" | "compress" => {}
            "chunked" => {
                return Err(HttpError::MalformedHead(
                    "duplicate 'chunked' in Transfer-Encoding".to_owned(),
                ));
            }
            other => {
                return Err(HttpError::MalformedHead(format!(
                    "unsupported Transfer-Encoding '{other}'"
                )));
            }
        }
    }
    Ok(())
}

fn parse_chunk_size_line(line: &str) -> Result<u64, HttpError> {
    let size_part = match line.split_once(';') {
        Some((size_raw, ext)) => {
            if ext.bytes().any(is_disallowed_header_char) {
                return Err(HttpError::InvalidChunk(
                    "invalid control character in chunk extension".to_owned(),
                ));
            }
            size_raw.trim_end_matches(|c| c == ' ' || c == '\t')
        }
        None => line,
    };

    if size_part.is_empty() || !size_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HttpError::InvalidChunk(format!(
            "invalid chunk size '{size_part}'"
        )));
    }
    u64::from_str_radix(size_part, 16)
        .map_err(|_| HttpError::InvalidChunk(format!("chunk size overflow '{size_part}'")))
}

async fn read_chunked_trailers<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> Result<Vec<(String, String)>, HttpError> {
    let mut raw_lines: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let line = reader.read_line_crlf(MAX_HEADER_BYTES).await?;
        if line.is_empty() {
            break;
        }
        total_bytes = total_bytes.saturating_add(line.len() + 2);
        if total_bytes > MAX_HEADER_BYTES {
            return Err(HttpError::HeadersTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        raw_lines.push(line);
    }
    if raw_lines.is_empty() {
        return Ok(Vec::new());
    }
    let refs: Vec<&[u8]> = raw_lines.iter().map(String::as_bytes).collect();
    parse_and_validate_headers(&refs, false)
}

async fn expect_chunk_crlf<R: AsyncRead + Unpin>(
    reader: &mut PrefixedReader<R>,
) -> Result<(), HttpError> {
    let mut crlf = [0u8; 2];
    match reader.read_exact(&mut crlf).await {
        Ok(_) => {
            if crlf != *b"\r\n" {
                return Err(HttpError::InvalidChunk(
                    "missing CRLF after chunk payload".to_owned(),
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(HttpError::UnexpectedEof),
        Err(err) => Err(HttpError::Io(err)),
    }
}

fn append_headers(out: &mut Vec<u8>, headers: &[(String, String)]) -> Result<(), HttpError> {
    for (name, val) in headers {
        ensure_no_crlf_or_nul(name, "header name")?;
        ensure_no_crlf_or_nul(val, "header value")?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(HttpError::MalformedHead(format!(
                "invalid outgoing header name '{name}'"
            )));
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}

fn ensure_no_crlf_or_nul(s: &str, label: &str) -> Result<(), HttpError> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(HttpError::MalformedHead(format!(
            "forbidden CR/LF/NUL byte in {label}"
        )));
    }
    Ok(())
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn find_headers_all<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

fn parse_single_content_length(headers: &[(String, String)]) -> Option<u64> {
    let cls = find_headers_all(headers, "content-length");
    if cls.len() != 1 {
        return None;
    }
    parse_strict_content_length(cls[0])
}

fn has_chunked_encoding(headers: &[(String, String)]) -> bool {
    let tes = find_headers_all(headers, "transfer-encoding");
    if tes.is_empty() {
        return false;
    }
    let mut last_token: Option<String> = None;
    for raw in tes {
        for part in raw.split(',') {
            let tok = part.trim_matches(|c| c == ' ' || c == '\t');
            if !tok.is_empty() {
                last_token = Some(tok.to_ascii_lowercase());
            }
        }
    }
    last_token.as_deref() == Some("chunked")
}

fn has_connection_token(headers: &[(String, String)], target: &str) -> bool {
    for raw in find_headers_all(headers, "connection") {
        for part in raw.split(',') {
            let tok = part.trim_matches(|c| c == ' ' || c == '\t');
            if tok.eq_ignore_ascii_case(target) {
                return true;
            }
        }
    }
    false
}

fn connection_wants_close(version: &str, headers: &[(String, String)]) -> bool {
    if has_connection_token(headers, "close") {
        return true;
    }
    version == "HTTP/1.0" && !has_connection_token(headers, "keep-alive")
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_disallowed_header_char(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7F
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn parses_request_head_preserves_carryover_bytes_past_double_crlf() {
        let raw = b"POST /v1.43/exec/abc/start?Detach=false HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n{\"Detach\":false}stdin-prebuf";
        let mut reader = PrefixedReader::new(&raw[..]);

        let head = read_request_head(&mut reader)
            .await
            .expect("request head parses")
            .expect("request present");

        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/v1.43/exec/abc/start");
        assert_eq!(head.query.as_deref(), Some("Detach=false"));
        assert_eq!(head.content_length(), Some(16));
        assert!(head.wants_upgrade());
        assert!(!head.wants_close());
        assert_eq!(head.body_mode(), BodyMode::ContentLength(16));

        let body = read_body_bytes(&mut reader, head.body_mode(), MAX_BUFFERED_BODY_BYTES)
            .await
            .expect("body reads exact content-length");
        assert_eq!(body, br#"{"Detach":false}"#);

        let (_inner, leftover) = reader.into_parts();
        assert_eq!(leftover, b"stdin-prebuf");
    }

    #[tokio::test]
    async fn parses_101_upgraded_response_as_empty_body_and_preserves_payload() {
        let raw = b"HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n\x01\x00\x00\x00\x00\x00\x00\x05hello";
        let mut reader = PrefixedReader::new(&raw[..]);

        let resp = read_response_head(&mut reader)
            .await
            .expect("101 response parses");

        assert!(resp.is_upgrade());
        assert_eq!(resp.status, 101);
        assert_eq!(resp.reason, "UPGRADED");
        assert_eq!(resp.body_mode("POST"), BodyMode::Empty);

        let (_inner, pre_buf) = reader.into_parts();
        assert_eq!(pre_buf, b"\x01\x00\x00\x00\x00\x00\x00\x05hello");
    }

    #[tokio::test]
    async fn response_body_mode_handles_head_204_304_chunked_and_until_eof() {
        let head_resp = HttpResponseHead {
            version: "HTTP/1.1".to_owned(),
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![("Content-Length".to_owned(), "512".to_owned())],
        };
        assert_eq!(head_resp.body_mode("HEAD"), BodyMode::Empty);
        assert_eq!(head_resp.body_mode("GET"), BodyMode::ContentLength(512));

        let no_content = HttpResponseHead {
            version: "HTTP/1.1".to_owned(),
            status: 204,
            reason: "No Content".to_owned(),
            headers: Vec::new(),
        };
        assert_eq!(no_content.body_mode("DELETE"), BodyMode::Empty);

        let not_modified = HttpResponseHead {
            version: "HTTP/1.1".to_owned(),
            status: 304,
            reason: "Not Modified".to_owned(),
            headers: vec![("Content-Length".to_owned(), "100".to_owned())],
        };
        assert_eq!(not_modified.body_mode("GET"), BodyMode::Empty);

        let chunked = HttpResponseHead {
            version: "HTTP/1.1".to_owned(),
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![("Transfer-Encoding".to_owned(), "Chunked".to_owned())],
        };
        assert_eq!(chunked.body_mode("GET"), BodyMode::Chunked);

        let eof_resp = HttpResponseHead {
            version: "HTTP/1.0".to_owned(),
            status: 200,
            reason: "OK".to_owned(),
            headers: Vec::new(),
        };
        assert!(eof_resp.wants_close());
        assert_eq!(eof_resp.body_mode("GET"), BodyMode::UntilEof);
    }

    #[tokio::test]
    async fn decodes_and_forwards_chunked_bodies_preserving_trailing_bytes() {
        let raw = b"POST /images/load HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: ok\r\n\r\nNEXT";
        let mut reader = PrefixedReader::new(&raw[..]);
        let req = read_request_head(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.body_mode(), BodyMode::Chunked);

        let decoded = read_body_bytes(&mut reader, req.body_mode(), MAX_BUFFERED_BODY_BYTES)
            .await
            .expect("chunked body decodes");
        assert_eq!(decoded, b"hello world");
        let (_inner, leftover) = reader.into_parts();
        assert_eq!(leftover, b"NEXT");

        // Now verify streaming forward_body produces valid chunked framing for downstream peer.
        let mut forward_reader = PrefixedReader::new(&raw[..]);
        let f_req = read_request_head(&mut forward_reader).await.unwrap().unwrap();
        let (mut sink_write, sink_read) = tokio::io::duplex(4096);
        let forward_task = tokio::spawn(async move {
            write_request_head(&mut sink_write, &f_req).await.unwrap();
            let copied = forward_body(&mut forward_reader, &mut sink_write, f_req.body_mode())
                .await
                .unwrap();
            sink_write.shutdown().await.unwrap();
            (copied, forward_reader.into_parts().1)
        });

        let mut peer_reader = PrefixedReader::new(sink_read);
        let peer_head = read_request_head(&mut peer_reader).await.unwrap().unwrap();
        let peer_body = read_body_bytes(&mut peer_reader, peer_head.body_mode(), 1024)
            .await
            .unwrap();
        let (copied, leftover_fwd) = forward_task.await.unwrap();
        assert_eq!(copied, 11);
        assert_eq!(peer_body, b"hello world");
        assert_eq!(leftover_fwd, b"NEXT");
    }

    #[tokio::test]
    async fn rejects_http_smuggling_vectors() {
        let cases: &[(&str, &[u8])] = &[
            (
                "duplicate Content-Length",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            ),
            (
                "conflicting Content-Length",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello",
            ),
            (
                "simultaneous Content-Length and Transfer-Encoding",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            ),
            (
                "negative Content-Length",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
            ),
            (
                "plus-signed Content-Length",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n",
            ),
            (
                "overflow Content-Length",
                b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999999\r\n\r\n",
            ),
            (
                "space before colon in header name",
                b"GET /x HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n",
            ),
            (
                "obs-fold header",
                b"GET /x HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            ),
            (
                "unknown Transfer-Encoding",
                b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
            ),
            (
                "bare LF inside header block",
                b"GET /x HTTP/1.1\r\nHost: a\nX-Evil: 1\r\n\r\n",
            ),
        ];

        for (label, raw) in cases {
            let mut reader = PrefixedReader::new(*raw);
            let err = read_request_head(&mut reader)
                .await
                .expect_err(&format!("{label} must be rejected"));
            assert!(
                matches!(err, HttpError::MalformedHead(_)),
                "{label}: unexpected error {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_chunk_sizes_and_oversized_headers() {
        let plus_chunk = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
        let mut r1 = PrefixedReader::new(&plus_chunk[..]);
        let h1 = read_request_head(&mut r1).await.unwrap().unwrap();
        let err1 = read_body_bytes(&mut r1, h1.body_mode(), 1024)
            .await
            .expect_err("plus-prefixed chunk size must be rejected");
        assert!(matches!(err1, HttpError::InvalidChunk(_)));

        let trailer_cl = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\n";
        let mut r2 = PrefixedReader::new(&trailer_cl[..]);
        let h2 = read_request_head(&mut r2).await.unwrap().unwrap();
        let err2 = read_body_bytes(&mut r2, h2.body_mode(), 1024)
            .await
            .expect_err("Content-Length in trailer must be rejected");
        assert!(matches!(err2, HttpError::InvalidChunk(_)));

        let mut huge = b"GET / HTTP/1.1\r\nHost: a\r\nX-Big: ".to_vec();
        huge.resize(MAX_HEADER_BYTES + 128, b'a');
        huge.extend_from_slice(b"\r\n\r\n");
        let mut r3 = PrefixedReader::new(BufReader::new(&huge[..]));
        let err3 = read_request_head(&mut r3)
            .await
            .expect_err("headers > 64 KiB must be rejected");
        assert!(matches!(
            err3,
            HttpError::HeadersTooLarge {
                limit: MAX_HEADER_BYTES
            }
        ));
    }

    #[tokio::test]
    async fn write_json_error_emits_docker_json_message() {
        let mut sink = Vec::new();
        write_json_error(&mut sink, 400, "Bad Request", "bind mount denied", true)
            .await
            .expect("writes JSON error");

        let mut reader = PrefixedReader::new(&sink[..]);
        let head = read_response_head(&mut reader).await.unwrap();
        assert_eq!(head.status, 400);
        assert_eq!(head.header("content-type"), Some("application/json"));
        assert!(head.wants_close());

        let body = read_body_bytes(&mut reader, head.body_mode("POST"), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "bind mount denied");
    }

    #[tokio::test]
    async fn keep_alive_pipelined_requests_and_streaming_content_length_forward() {
        let pipelined = b"POST /v1.43/containers/create HTTP/1.1\r\nHost: localhost\r\nContent-Length: 18\r\n\r\n{\"Image\":\"alpine\"}GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut reader = PrefixedReader::new(&pipelined[..]);

        let req1 = read_request_head(&mut reader).await.unwrap().unwrap();
        assert_eq!(req1.path, "/v1.43/containers/create");
        let mut forwarded = Vec::new();
        let n = forward_body(&mut reader, &mut forwarded, req1.body_mode())
            .await
            .unwrap();
        assert_eq!(n, 18);
        assert_eq!(forwarded, br#"{"Image":"alpine"}"#);

        let req2 = read_request_head(&mut reader).await.unwrap().unwrap();
        assert_eq!(req2.method, "GET");
        assert_eq!(req2.path, "/_ping");
        assert_eq!(req2.body_mode(), BodyMode::Empty);

        assert!(read_request_head(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn forward_body_content_length_flushes_each_slice_immediately() {
        let (mut src_write, src_read) = tokio::io::duplex(4096);
        let (sink_write, mut sink_read) = tokio::io::duplex(4096);

        let forward_task = tokio::spawn(async move {
            let mut r = PrefixedReader::new(src_read);
            let mut w = sink_write;
            forward_body(&mut r, &mut w, BodyMode::ContentLength(10))
                .await
                .unwrap()
        });

        src_write.write_all(b"slice").await.unwrap();
        src_write.flush().await.unwrap();

        let mut first = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sink_read.read_exact(&mut first),
        )
        .await
        .expect("first slice must flush before full body arrives")
        .unwrap();
        assert_eq!(&first, b"slice");

        src_write.write_all(b"-tail").await.unwrap();
        src_write.flush().await.unwrap();

        let mut second = [0u8; 5];
        sink_read.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"-tail");
        assert_eq!(forward_task.await.unwrap(), 10);
    }
}
