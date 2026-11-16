//! Ed25519 manifest signature verification, hex helpers, and streaming SHA-256 primitives.

use std::io::{ErrorKind, Read};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sandbox_core::SandboxError;
use sha2::{Digest, Sha256};

use crate::manifest::{BundleManifest, MAX_MANIFEST_BYTES};

const SHA256_BUFFER_BYTES: usize = 64 * 1024;

/// Placeholder embedded Ed25519 verifying key for Portable Runtime Bundle manifests.
///
/// This is a valid non-identity Curve25519 compressed point used as a placeholder
/// release verifying key; no release private/secret key bytes are stored in source control.
pub const EMBEDDED_BUNDLE_PUBLIC_KEY: [u8; 32] = [
    122, 69, 245, 133, 170, 6, 230, 86, 43, 186, 63, 33, 104, 159, 117, 231, 24, 4, 68, 67, 173,
    114, 141, 50, 175, 71, 99, 179, 34, 22, 34, 104,
];

/// Verifies Ed25519 signatures over untrusted bundle manifest bytes before parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleVerifier {
    verifying_key: VerifyingKey,
}

impl BundleVerifier {
    /// Creates a verifier backed by [`EMBEDDED_BUNDLE_PUBLIC_KEY`].
    pub fn embedded() -> Result<Self, SandboxError> {
        Self::with_public_key(EMBEDDED_BUNDLE_PUBLIC_KEY)
    }

    /// Creates a verifier from an explicit 32-byte Ed25519 verifying key, rejecting invalid or weak keys.
    pub fn with_public_key(pub_key: [u8; 32]) -> Result<Self, SandboxError> {
        let verifying_key = VerifyingKey::from_bytes(&pub_key).map_err(|err| {
            SandboxError::PolicyViolation(format!("invalid Ed25519 bundle verifying key: {err}"))
        })?;
        if verifying_key.is_weak() {
            return Err(SandboxError::PolicyViolation(
                "weak or small-order Ed25519 bundle verifying key is rejected".to_owned(),
            ));
        }
        Ok(Self { verifying_key })
    }

    /// Verifies `signature_hex_or_bytes` against `manifest_bytes` strictly before UTF-8 decoding or parsing.
    pub fn verify_and_parse_manifest(
        &self,
        manifest_bytes: &[u8],
        signature_hex_or_bytes: &[u8],
    ) -> Result<BundleManifest, SandboxError> {
        if manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(SandboxError::InvalidSpec(format!(
                "manifest size {} bytes exceeds maximum allowed {} bytes",
                manifest_bytes.len(),
                MAX_MANIFEST_BYTES
            )));
        }

        let sig_str = std::str::from_utf8(signature_hex_or_bytes).map_err(|err| {
            SandboxError::PolicyViolation(format!("manifest signature is not valid UTF-8: {err}"))
        })?;
        let sig_bytes = decode_hex_exact::<64>(sig_str.trim()).map_err(|err| {
            SandboxError::PolicyViolation(format!("malformed Ed25519 signature hex: {err}"))
        })?;
        let signature = Signature::from_bytes(&sig_bytes);

        // Trust boundary: authenticate exact raw bytes before any UTF-8 conversion or manifest parsing.
        self.verifying_key
            .verify_strict(manifest_bytes, &signature)
            .map_err(|err| {
                SandboxError::PolicyViolation(format!(
                    "manifest Ed25519 signature verification failed: {err}"
                ))
            })?;

        let manifest_text = std::str::from_utf8(manifest_bytes).map_err(|err| {
            SandboxError::InvalidSpec(format!("verified manifest is not valid UTF-8: {err}"))
        })?;
        BundleManifest::parse_untrusted(manifest_text)
    }
}

/// Derives the 32-byte Ed25519 public verifying key from a 32-byte secret seed.
pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// Signs raw manifest bytes with `secret` and returns the 128-char lowercase hex signature.
pub fn sign_manifest_hex(secret: &[u8; 32], manifest_bytes: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(secret);
    let signature: Signature = signing_key.sign(manifest_bytes);
    encode_hex(&signature.to_bytes())
}

/// Encodes `bytes` as a lowercase hexadecimal string.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a fixed-size hexadecimal string (`2 * N` characters) into `[u8; N]`.
pub fn decode_hex_exact<const N: usize>(hex_str: &str) -> Result<[u8; N], SandboxError> {
    let raw = hex_str.as_bytes();
    if raw.len() != N * 2 {
        return Err(SandboxError::InvalidSpec(format!(
            "expected {} hex characters, got {}",
            N * 2,
            raw.len()
        )));
    }
    let mut out = [0u8; N];
    for (i, pair) in raw.as_chunks::<2>().0.iter().enumerate() {
        let hi = decode_hex_nibble(pair[0])?;
        let lo = decode_hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, SandboxError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SandboxError::InvalidSpec(format!(
            "invalid hexadecimal byte 0x{byte:02x}"
        ))),
    }
}

/// Streams all bytes from `reader` with a 64 KiB buffer and returns `(sha256_digest, total_bytes)`.
pub fn sha256_reader<R: Read>(reader: &mut R) -> Result<([u8; 32], u64), SandboxError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; SHA256_BUFFER_BYTES];
    let mut total_bytes: u64 = 0;

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                total_bytes = total_bytes.checked_add(n as u64).ok_or_else(|| {
                    SandboxError::InvalidSpec("stream size exceeds u64 range".to_owned())
                })?;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(SandboxError::Internal(format!(
                    "failed to read stream while computing SHA-256: {err}"
                )));
            }
        }
    }

    Ok((hasher.finalize().into(), total_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ArtifactRole, BundleFileEntry};
    use sandbox_core::GuestArch;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    fn sample_manifest() -> BundleManifest {
        let mut source_pins = BTreeMap::new();
        source_pins.insert("alpine".to_owned(), "3.20.3".to_owned());
        source_pins.insert("qemu".to_owned(), "9.1.0".to_owned());

        BundleManifest {
            format_version: 1,
            bundle_id: "minipod-test-bundle-1".to_owned(),
            host_os: "windows".to_owned(),
            guest_arch: GuestArch::X86_64,
            source_pins,
            entries: vec![
                BundleFileEntry {
                    role: ArtifactRole::Kernel,
                    rel_path: "boot/vmlinuz".to_owned(),
                    sha256: [0x11; 32],
                    size_bytes: 1024,
                },
                BundleFileEntry {
                    role: ArtifactRole::Initrd,
                    rel_path: "boot/initrd.img".to_owned(),
                    sha256: [0x22; 32],
                    size_bytes: 2048,
                },
                BundleFileEntry {
                    role: ArtifactRole::BaseRootfsQcow2,
                    rel_path: "images/rootfs.qcow2".to_owned(),
                    sha256: [0x33; 32],
                    size_bytes: 4096,
                },
            ],
        }
    }

    #[test]
    fn embedded_verifier_constructs_and_rejects_weak_keys() {
        let embedded = BundleVerifier::embedded().expect("embedded placeholder public key must load");
        let manifest_bytes = sample_manifest().encode_canonical().unwrap().into_bytes();
        let bad_sig = vec![b'0'; 128];
        assert!(matches!(
            embedded.verify_and_parse_manifest(&manifest_bytes, &bad_sig),
            Err(SandboxError::PolicyViolation(_))
        ));

        // Identity point in Ed25519 (y = 1, x = 0) and all-zero point must be rejected as weak.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(matches!(
            BundleVerifier::with_public_key(identity),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(matches!(
            BundleVerifier::with_public_key([0u8; 32]),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn valid_signature_verifies_and_parses_canonical_manifest() {
        let secret = [0x42u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        let manifest = sample_manifest();
        let canonical = manifest.encode_canonical().unwrap();
        let sig_with_newline = format!("{}\n", sign_manifest_hex(&secret, canonical.as_bytes()));

        let parsed = verifier
            .verify_and_parse_manifest(canonical.as_bytes(), sig_with_newline.as_bytes())
            .unwrap();
        assert_eq!(parsed.bundle_id, manifest.bundle_id);
        assert_eq!(parsed.entries.len(), 3);
    }

    #[test]
    fn tampered_manifest_and_garbage_manifest_fail_at_signature_verification() {
        let secret = [0x55u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        let canonical = sample_manifest().encode_canonical().unwrap();
        let sig_hex = sign_manifest_hex(&secret, canonical.as_bytes());

        // Flip 1 byte in the verified manifest payload.
        let mut tampered = canonical.into_bytes();
        tampered[0] ^= 0x01;
        assert!(matches!(
            verifier.verify_and_parse_manifest(&tampered, sig_hex.as_bytes()),
            Err(SandboxError::PolicyViolation(_))
        ));

        // Invalid-UTF-8 and invalid-syntax garbage with a bad signature must fail signature check
        // (PolicyViolation) BEFORE manifest UTF-8 decoding or parsing runs (which would return InvalidSpec).
        let garbage_bytes: &[u8] = b"\xff\xfe\x00not a valid manifest\n";
        assert!(matches!(
            verifier.verify_and_parse_manifest(garbage_bytes, sig_hex.as_bytes()),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn wrong_public_key_and_malformed_signature_are_rejected() {
        let secret = [0x11u8; 32];
        let wrong_secret = [0x99u8; 32];
        let wrong_verifier =
            BundleVerifier::with_public_key(public_key_from_secret(&wrong_secret)).unwrap();

        let canonical = sample_manifest().encode_canonical().unwrap();
        let sig_hex = sign_manifest_hex(&secret, canonical.as_bytes());
        assert!(matches!(
            wrong_verifier.verify_and_parse_manifest(canonical.as_bytes(), sig_hex.as_bytes()),
            Err(SandboxError::PolicyViolation(_))
        ));

        let right_verifier =
            BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        for bad_sig in [
            &b""[..],
            &b"abcd"[..],
            &vec![b'z'; 128][..],
            &vec![b'a'; 126][..],
            &[0xff, 0xfe][..],
        ] {
            assert!(matches!(
                right_verifier.verify_and_parse_manifest(canonical.as_bytes(), bad_sig),
                Err(SandboxError::PolicyViolation(_))
            ));
        }
    }

    #[test]
    fn sha256_reader_matches_known_vectors_across_empty_and_multi_chunk_inputs() {
        // Empty input SHA-256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let mut empty = Cursor::new(&[][..]);
        let (digest, len) = sha256_reader(&mut empty).unwrap();
        assert_eq!(len, 0);
        assert_eq!(
            encode_hex(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Multi-chunk (>64 KiB) deterministic payload: 150,000 bytes of 0x61 ('a').
        let payload = vec![b'a'; 150_000];
        let mut cursor = Cursor::new(payload.as_slice());
        let (digest, len) = sha256_reader(&mut cursor).unwrap();
        assert_eq!(len, 150_000);
        assert_eq!(
            encode_hex(&digest),
            "1ef149b3d0000b5a74c1d390452b9b5e00bae34d4bef1b52f6b4f65997f0da62"
        );
    }

    #[test]
    fn oversized_manifest_is_rejected_before_verification() {
        let verifier = BundleVerifier::embedded().unwrap();
        let oversized = vec![b'a'; MAX_MANIFEST_BYTES + 1];
        let dummy_sig = vec![b'0'; 128];
        assert!(matches!(
            verifier.verify_and_parse_manifest(&oversized, &dummy_sig),
            Err(SandboxError::InvalidSpec(_))
        ));
    }
}
