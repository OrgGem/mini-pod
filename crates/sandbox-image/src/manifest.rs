//! Canonical bundle manifest model, strict validator, and deterministic line-oriented codec.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::str::FromStr;

use sandbox_core::{GuestArch, SandboxError};

use crate::crypto::{decode_hex_exact, encode_hex};

/// Canonical filename for the signed bundle manifest inside a Portable Runtime Bundle.
pub const MANIFEST_FILENAME: &str = "manifest.v1";

/// Canonical filename for the hex-encoded Ed25519 detached signature over [`MANIFEST_FILENAME`].
pub const SIGNATURE_FILENAME: &str = "manifest.sig";

/// Supported canonical manifest format version.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Maximum accepted byte length for an untrusted bundle manifest (`1 MiB`).
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Role of an artifact file within a Portable Runtime Bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactRole {
    Kernel,
    Initrd,
    BaseRootfsQcow2,
    TinyInit,
    GuestAgent,
    QemuSystemBinary,
    QemuImgBinary,
    Firmware,
    SupportFile,
}

impl ArtifactRole {
    /// Returns the canonical lowercase string identifier for this artifact role.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Initrd => "initrd",
            Self::BaseRootfsQcow2 => "base_rootfs_qcow2",
            Self::TinyInit => "tiny_init",
            Self::GuestAgent => "guest_agent",
            Self::QemuSystemBinary => "qemu_system_binary",
            Self::QemuImgBinary => "qemu_img_binary",
            Self::Firmware => "firmware",
            Self::SupportFile => "support_file",
        }
    }
}

impl fmt::Display for ArtifactRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ArtifactRole {
    type Err = SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kernel" => Ok(Self::Kernel),
            "initrd" => Ok(Self::Initrd),
            "base_rootfs_qcow2" => Ok(Self::BaseRootfsQcow2),
            "tiny_init" => Ok(Self::TinyInit),
            "guest_agent" => Ok(Self::GuestAgent),
            "qemu_system_binary" => Ok(Self::QemuSystemBinary),
            "qemu_img_binary" => Ok(Self::QemuImgBinary),
            "firmware" => Ok(Self::Firmware),
            "support_file" => Ok(Self::SupportFile),
            _ => Err(SandboxError::InvalidSpec(format!(
                "unknown bundle artifact role '{s}'"
            ))),
        }
    }
}

/// Single verified file record inside a [`BundleManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFileEntry {
    pub role: ArtifactRole,
    pub rel_path: String,
    pub sha256: [u8; 32],
    pub size_bytes: u64,
}

/// Signed metadata and artifact inventory for a Portable Runtime Bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleManifest {
    pub format_version: u32,
    pub bundle_id: String,
    pub host_os: String,
    pub guest_arch: GuestArch,
    pub source_pins: BTreeMap<String, String>,
    pub entries: Vec<BundleFileEntry>,
}

impl BundleManifest {
    /// Validates all domain, pinning, path-safety, uniqueness, and boot-role invariants.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.format_version != MANIFEST_FORMAT_VERSION {
            return Err(SandboxError::InvalidSpec(format!(
                "unsupported manifest format_version {}; expected {}",
                self.format_version, MANIFEST_FORMAT_VERSION
            )));
        }
        validate_bundle_id(&self.bundle_id)?;
        validate_host_os(&self.host_os)?;

        if self.source_pins.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "manifest source_pins must not be empty".to_owned(),
            ));
        }
        for (key, value) in &self.source_pins {
            validate_pin_entry(key, value)?;
        }

        let mut seen_paths = BTreeSet::new();
        let mut has_kernel = false;
        let mut has_initrd = false;
        let mut has_base_rootfs = false;

        for entry in &self.entries {
            validate_rel_path(&entry.rel_path)?;
            if !seen_paths.insert(entry.rel_path.as_str()) {
                return Err(SandboxError::InvalidSpec(format!(
                    "duplicate manifest entry rel_path '{}'",
                    entry.rel_path
                )));
            }
            match entry.role {
                ArtifactRole::Kernel => has_kernel = true,
                ArtifactRole::Initrd => has_initrd = true,
                ArtifactRole::BaseRootfsQcow2 => has_base_rootfs = true,
                _ => {}
            }
        }

        if !has_kernel || !has_initrd || !has_base_rootfs {
            return Err(SandboxError::InvalidSpec(
                "manifest must include at least one Kernel, Initrd, and BaseRootfsQcow2 entry"
                    .to_owned(),
            ));
        }

        Ok(())
    }

    /// Validates all invariants and encodes this manifest in canonical deterministic LF text format.
    pub fn encode_canonical(&self) -> Result<String, SandboxError> {
        self.validate()?;

        let mut sorted_entries: Vec<&BundleFileEntry> = self.entries.iter().collect();
        sorted_entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));

        let mut out = String::new();
        writeln!(out, "format_version={}", self.format_version)
            .map_err(|err| SandboxError::Internal(err.to_string()))?;
        writeln!(out, "bundle_id={}", self.bundle_id)
            .map_err(|err| SandboxError::Internal(err.to_string()))?;
        writeln!(out, "host_os={}", self.host_os)
            .map_err(|err| SandboxError::Internal(err.to_string()))?;
        writeln!(out, "guest_arch={}", self.guest_arch)
            .map_err(|err| SandboxError::Internal(err.to_string()))?;
        writeln!(out, "pin_count={}", self.source_pins.len())
            .map_err(|err| SandboxError::Internal(err.to_string()))?;

        for (key, value) in &self.source_pins {
            writeln!(out, "pin {key}={value}")
                .map_err(|err| SandboxError::Internal(err.to_string()))?;
        }

        writeln!(out, "entry_count={}", sorted_entries.len())
            .map_err(|err| SandboxError::Internal(err.to_string()))?;

        for entry in sorted_entries {
            writeln!(
                out,
                "entry {} {} {} {}",
                entry.role,
                entry.size_bytes,
                encode_hex(&entry.sha256),
                entry.rel_path
            )
            .map_err(|err| SandboxError::Internal(err.to_string()))?;
        }

        if out.len() > MAX_MANIFEST_BYTES {
            return Err(SandboxError::InvalidSpec(format!(
                "encoded manifest size {} bytes exceeds maximum allowed {} bytes",
                out.len(),
                MAX_MANIFEST_BYTES
            )));
        }

        Ok(out)
    }

    /// Strictly parses canonical manifest text, rejecting non-canonical ordering, whitespace, or trailing data.
    pub fn parse_untrusted(text: &str) -> Result<Self, SandboxError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(SandboxError::InvalidSpec(format!(
                "manifest size {} bytes exceeds maximum allowed {} bytes",
                text.len(),
                MAX_MANIFEST_BYTES
            )));
        }
        if text.contains('\r') {
            return Err(SandboxError::InvalidSpec(
                "manifest must use LF line endings; CR is forbidden".to_owned(),
            ));
        }
        let body = text.strip_suffix('\n').ok_or_else(|| {
            SandboxError::InvalidSpec("canonical manifest must end with a trailing LF".to_owned())
        })?;

        let mut lines = body.split('\n');

        let format_version = parse_canonical_u32(strip_line_prefix(
            next_line(&mut lines, "format_version")?,
            "format_version=",
        )?)?;
        if format_version != MANIFEST_FORMAT_VERSION {
            return Err(SandboxError::InvalidSpec(format!(
                "unsupported manifest format_version {format_version}; expected {MANIFEST_FORMAT_VERSION}"
            )));
        }

        let bundle_id =
            strip_line_prefix(next_line(&mut lines, "bundle_id")?, "bundle_id=")?.to_owned();
        validate_bundle_id(&bundle_id)?;

        let host_os = strip_line_prefix(next_line(&mut lines, "host_os")?, "host_os=")?.to_owned();
        validate_host_os(&host_os)?;

        let guest_arch =
            strip_line_prefix(next_line(&mut lines, "guest_arch")?, "guest_arch=")?
                .parse::<GuestArch>()?;

        let pin_count = parse_canonical_usize(strip_line_prefix(
            next_line(&mut lines, "pin_count")?,
            "pin_count=",
        )?)?;
        if pin_count == 0 {
            return Err(SandboxError::InvalidSpec(
                "manifest source_pins must not be empty".to_owned(),
            ));
        }

        let mut source_pins = BTreeMap::new();
        let mut prev_pin_key: Option<String> = None;
        for _ in 0..pin_count {
            let line = next_line(&mut lines, "pin")?;
            let rest = strip_line_prefix(line, "pin ")?;
            let (key, value) = rest.split_once('=').ok_or_else(|| {
                SandboxError::InvalidSpec(format!("malformed source_pin line: '{line}'"))
            })?;
            validate_pin_entry(key, value)?;
            if let Some(prev) = &prev_pin_key {
                if key <= prev.as_str() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "source_pins must be strictly sorted with unique keys (got '{key}' after '{prev}')"
                    )));
                }
            }
            prev_pin_key = Some(key.to_owned());
            source_pins.insert(key.to_owned(), value.to_owned());
        }

        let entry_count = parse_canonical_usize(strip_line_prefix(
            next_line(&mut lines, "entry_count")?,
            "entry_count=",
        )?)?;

        let mut entries = Vec::with_capacity(entry_count.min(MAX_MANIFEST_BYTES / 32));
        let mut prev_rel_path: Option<String> = None;
        for _ in 0..entry_count {
            let line = next_line(&mut lines, "entry")?;
            let rest = strip_line_prefix(line, "entry ")?;
            let (role_str, rest) = rest.split_once(' ').ok_or_else(|| {
                SandboxError::InvalidSpec(format!("malformed entry line (missing size): '{line}'"))
            })?;
            let (size_str, rest) = rest.split_once(' ').ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "malformed entry line (missing sha256): '{line}'"
                ))
            })?;
            let (sha_str, rel_path) = rest.split_once(' ').ok_or_else(|| {
                SandboxError::InvalidSpec(format!(
                    "malformed entry line (missing rel_path): '{line}'"
                ))
            })?;

            let role = role_str.parse::<ArtifactRole>()?;
            let size_bytes = parse_canonical_u64(size_str)?;
            let sha256 = parse_canonical_sha256_hex(sha_str)?;
            validate_rel_path(rel_path)?;

            if let Some(prev) = &prev_rel_path {
                if rel_path <= prev.as_str() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "manifest entries must be strictly sorted by unique rel_path (got '{rel_path}' after '{prev}')"
                    )));
                }
            }
            prev_rel_path = Some(rel_path.to_owned());
            entries.push(BundleFileEntry {
                role,
                rel_path: rel_path.to_owned(),
                sha256,
                size_bytes,
            });
        }

        if let Some(extra) = lines.next() {
            return Err(SandboxError::InvalidSpec(format!(
                "unexpected trailing manifest line: '{extra}'"
            )));
        }

        let manifest = Self {
            format_version,
            bundle_id,
            host_os,
            guest_arch,
            source_pins,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

fn next_line<'a>(
    lines: &mut std::str::Split<'a, char>,
    expected: &str,
) -> Result<&'a str, SandboxError> {
    lines.next().ok_or_else(|| {
        SandboxError::InvalidSpec(format!("unexpected end of manifest while expecting {expected}"))
    })
}

fn strip_line_prefix<'a>(line: &'a str, prefix: &str) -> Result<&'a str, SandboxError> {
    line.strip_prefix(prefix).ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "expected manifest line starting with '{prefix}', got '{line}'"
        ))
    })
}

fn parse_canonical_u64(s: &str) -> Result<u64, SandboxError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SandboxError::InvalidSpec(format!(
            "expected canonical unsigned integer, got '{s}'"
        )));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(SandboxError::InvalidSpec(format!(
            "canonical integer must not have leading zeros: '{s}'"
        )));
    }
    s.parse::<u64>()
        .map_err(|err| SandboxError::InvalidSpec(format!("invalid integer '{s}': {err}")))
}

fn parse_canonical_u32(s: &str) -> Result<u32, SandboxError> {
    let val = parse_canonical_u64(s)?;
    u32::try_from(val)
        .map_err(|_| SandboxError::InvalidSpec(format!("integer '{s}' exceeds u32 range")))
}

fn parse_canonical_usize(s: &str) -> Result<usize, SandboxError> {
    let val = parse_canonical_u64(s)?;
    usize::try_from(val)
        .map_err(|_| SandboxError::InvalidSpec(format!("integer '{s}' exceeds usize range")))
}

fn parse_canonical_sha256_hex(s: &str) -> Result<[u8; 32], SandboxError> {
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(SandboxError::InvalidSpec(format!(
            "SHA-256 digest must be 64 lowercase hex characters, got '{s}'"
        )));
    }
    decode_hex_exact::<32>(s)
}

fn validate_bundle_id(bundle_id: &str) -> Result<(), SandboxError> {
    let bytes = bundle_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(SandboxError::InvalidSpec(format!(
            "bundle_id length must be 1..=128 bytes, got {}",
            bytes.len()
        )));
    }
    if bundle_id == "." || bundle_id == ".." {
        return Err(SandboxError::InvalidSpec(format!(
            "bundle_id cannot be '{bundle_id}'"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(SandboxError::InvalidSpec(format!(
            "bundle_id '{bundle_id}' contains characters outside [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

fn validate_host_os(host_os: &str) -> Result<(), SandboxError> {
    match host_os {
        "windows" | "linux" | "macos" | "any" => Ok(()),
        _ => Err(SandboxError::InvalidSpec(format!(
            "unsupported manifest host_os '{host_os}'; expected 'windows', 'linux', 'macos', or 'any'"
        ))),
    }
}

fn validate_pin_entry(key: &str, value: &str) -> Result<(), SandboxError> {
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
    {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid source_pin key '{key}'; expected non-empty ASCII [a-z0-9_.-]+"
        )));
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid source_pin value for '{key}': must be non-empty without control characters"
        )));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SandboxError::InvalidSpec(format!(
            "source_pin value for '{key}' cannot be whitespace-only"
        )));
    }
    if trimmed.eq_ignore_ascii_case("latest") || trimmed.to_ascii_lowercase().ends_with(":latest") {
        return Err(SandboxError::InvalidSpec(format!(
            "source_pin '{key}' must be pinned to a specific version or digest, not '{value}'"
        )));
    }
    Ok(())
}

fn validate_rel_path(rel_path: &str) -> Result<(), SandboxError> {
    if rel_path.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "manifest entry rel_path must not be empty".to_owned(),
        ));
    }
    if rel_path.trim() != rel_path {
        return Err(SandboxError::InvalidSpec(format!(
            "manifest entry rel_path '{rel_path}' must not have leading or trailing whitespace"
        )));
    }
    if rel_path.starts_with('/') || rel_path.ends_with('/') {
        return Err(SandboxError::InvalidSpec(format!(
            "manifest entry rel_path '{rel_path}' must not start or end with '/'"
        )));
    }
    if rel_path.contains('\\') || rel_path.contains(':') {
        return Err(SandboxError::InvalidSpec(format!(
            "manifest entry rel_path '{rel_path}' must not contain '\\' or ':'"
        )));
    }
    if rel_path.chars().any(char::is_control) {
        return Err(SandboxError::InvalidSpec(format!(
            "manifest entry rel_path '{rel_path}' contains forbidden control characters"
        )));
    }
    for segment in rel_path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(SandboxError::InvalidSpec(format!(
                "manifest entry rel_path '{rel_path}' contains invalid path segment '{segment}'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_pins() -> BTreeMap<String, String> {
        let mut pins = BTreeMap::new();
        pins.insert("alpine".to_owned(), "3.20.3".to_owned());
        pins.insert("kernel".to_owned(), "6.6.60".to_owned());
        pins.insert("qemu".to_owned(), "9.1.0".to_owned());
        pins
    }

    fn base_entries() -> Vec<BundleFileEntry> {
        vec![
            BundleFileEntry {
                role: ArtifactRole::Kernel,
                rel_path: "boot/vmlinuz".to_owned(),
                sha256: [0xaa; 32],
                size_bytes: 2_097_152,
            },
            BundleFileEntry {
                role: ArtifactRole::BaseRootfsQcow2,
                rel_path: "images/rootfs.qcow2".to_owned(),
                sha256: [0xcc; 32],
                size_bytes: 16_777_216,
            },
            BundleFileEntry {
                role: ArtifactRole::Initrd,
                rel_path: "boot/initrd.img".to_owned(),
                sha256: [0xbb; 32],
                size_bytes: 524_288,
            },
        ]
    }

    fn valid_manifest(arch: GuestArch) -> BundleManifest {
        BundleManifest {
            format_version: MANIFEST_FORMAT_VERSION,
            bundle_id: "minipod-2026.11-rc1".to_owned(),
            host_os: "windows".to_owned(),
            guest_arch: arch,
            source_pins: base_pins(),
            entries: base_entries(),
        }
    }

    #[test]
    fn canonical_roundtrip_works_for_x86_64_and_aarch64_and_sorts_entries() {
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            let manifest = valid_manifest(arch);
            let encoded = manifest.encode_canonical().unwrap();
            let parsed = BundleManifest::parse_untrusted(&encoded).unwrap();

            assert_eq!(parsed.guest_arch, arch);
            assert_eq!(parsed.bundle_id, manifest.bundle_id);
            assert_eq!(parsed.source_pins, manifest.source_pins);
            // Entries in canonical encoding are sorted lexicographically by rel_path.
            let paths: Vec<&str> = parsed.entries.iter().map(|e| e.rel_path.as_str()).collect();
            assert_eq!(
                paths,
                vec!["boot/initrd.img", "boot/vmlinuz", "images/rootfs.qcow2"]
            );
            assert_eq!(parsed.encode_canonical().unwrap(), encoded);
        }
    }

    #[test]
    fn rejects_traversal_invalid_rel_paths_and_duplicate_entries() {
        let bad_paths = [
            "",
            "../x",
            "a/../b",
            "a/..",
            "./boot/vmlinuz",
            "boot/./vmlinuz",
            ".",
            "..",
            "/abs/path",
            "boot//vmlinuz",
            "boot/vmlinuz/",
            r"a\b",
            "C:x",
            "C:/x",
            "boot/vmlinuz\0",
            "boot/vmlinuz\n",
            " boot/vmlinuz",
            "boot/vmlinuz ",
        ];

        for bad in bad_paths {
            let mut m = valid_manifest(GuestArch::X86_64);
            m.entries.push(BundleFileEntry {
                role: ArtifactRole::SupportFile,
                rel_path: bad.to_owned(),
                sha256: [0x01; 32],
                size_bytes: 12,
            });
            assert!(
                matches!(m.encode_canonical(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for rel_path '{bad}'"
            );
        }

        // Duplicate rel_path must be rejected even if roles differ.
        let mut dup = valid_manifest(GuestArch::X86_64);
        dup.entries.push(BundleFileEntry {
            role: ArtifactRole::SupportFile,
            rel_path: "boot/vmlinuz".to_owned(),
            sha256: [0xff; 32],
            size_bytes: 99,
        });
        assert!(matches!(dup.encode_canonical(), Err(SandboxError::InvalidSpec(_))));
    }

    #[test]
    fn rejects_invalid_bundle_id_and_host_os() {
        for bad_id in ["", ".", "..", "bad/id", "bad id", &"a".repeat(129)] {
            let mut m = valid_manifest(GuestArch::X86_64);
            m.bundle_id = bad_id.to_owned();
            assert!(
                matches!(m.encode_canonical(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for bundle_id '{bad_id}'"
            );
        }

        for bad_os in ["", "freebsd", "Windows", "all"] {
            let mut m = valid_manifest(GuestArch::X86_64);
            m.host_os = bad_os.to_owned();
            assert!(matches!(
                m.encode_canonical(),
                Err(SandboxError::InvalidSpec(_))
            ));
        }
    }

    #[test]
    fn rejects_missing_required_boot_roles() {
        for missing_role in [
            ArtifactRole::Kernel,
            ArtifactRole::Initrd,
            ArtifactRole::BaseRootfsQcow2,
        ] {
            let mut m = valid_manifest(GuestArch::X86_64);
            m.entries.retain(|e| e.role != missing_role);
            assert!(
                matches!(m.encode_canonical(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec when missing role {missing_role}"
            );
        }
    }

    #[test]
    fn rejects_empty_or_unpinned_latest_source_pins() {
        let mut empty_pins = valid_manifest(GuestArch::X86_64);
        empty_pins.source_pins.clear();
        assert!(matches!(
            empty_pins.encode_canonical(),
            Err(SandboxError::InvalidSpec(_))
        ));

        for bad_pin in ["latest", "LATEST", "alpine:latest", "alpine:LaTeX_latest", "alpine:LaTeSt"] {
            if bad_pin == "alpine:LaTeX_latest" {
                // Verify non-`:latest` suffix is accepted as a real pin.
                let mut ok = valid_manifest(GuestArch::X86_64);
                ok.source_pins
                    .insert("alpine".to_owned(), bad_pin.to_owned());
                assert!(ok.encode_canonical().is_ok());
                continue;
            }
            let mut m = valid_manifest(GuestArch::X86_64);
            m.source_pins
                .insert("alpine".to_owned(), bad_pin.to_owned());
            assert!(
                matches!(m.encode_canonical(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for unpinned value '{bad_pin}'"
            );
        }

        let mut bad_key = valid_manifest(GuestArch::X86_64);
        bad_key
            .source_pins
            .insert("BAD_KEY".to_owned(), "1.0.0".to_owned());
        assert!(matches!(
            bad_key.encode_canonical(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn parse_untrusted_rejects_non_canonical_whitespace_crlf_unsorted_and_trailing_garbage() {
        let valid = valid_manifest(GuestArch::Aarch64).encode_canonical().unwrap();

        // Missing trailing LF
        assert!(BundleManifest::parse_untrusted(valid.trim_end_matches('\n')).is_err());

        // CRLF line endings
        let crlf = valid.replace('\n', "\r\n");
        assert!(BundleManifest::parse_untrusted(&crlf).is_err());

        // Trailing garbage line
        let with_garbage = format!("{valid}extra=line\n");
        assert!(BundleManifest::parse_untrusted(&with_garbage).is_err());

        // Uppercase SHA-256 hex in entry line
        let uppercase_sha = valid.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(BundleManifest::parse_untrusted(&uppercase_sha).is_err());

        // Unsorted entry lines
        let unsorted = valid.replace(
            "entry initrd 524288 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb boot/initrd.img\nentry kernel 2097152 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa boot/vmlinuz\n",
            "entry kernel 2097152 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa boot/vmlinuz\nentry initrd 524288 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb boot/initrd.img\n",
        );
        assert!(BundleManifest::parse_untrusted(&unsorted).is_err());
    }

    #[test]
    fn artifact_role_roundtrip_and_unknown_rejection() {
        for role in [
            ArtifactRole::Kernel,
            ArtifactRole::Initrd,
            ArtifactRole::BaseRootfsQcow2,
            ArtifactRole::TinyInit,
            ArtifactRole::GuestAgent,
            ArtifactRole::QemuSystemBinary,
            ArtifactRole::QemuImgBinary,
            ArtifactRole::Firmware,
            ArtifactRole::SupportFile,
        ] {
            let text = role.to_string();
            assert_eq!(text, role.as_str());
            assert_eq!(text.parse::<ArtifactRole>(), Ok(role));
        }
        assert!(matches!(
            "unknown_role".parse::<ArtifactRole>(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }
}
