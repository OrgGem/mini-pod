#![forbid(unsafe_code)]
//! Layer 3 image adapter boundary: Ed25519 manifest & SHA-256 bundle verification,
//! atomic directory swap, and atomic qcow2 Copy-on-Write overlay creation.

pub mod crypto;
pub mod manifest;

pub use crypto::{
    decode_hex_exact, encode_hex, public_key_from_secret, sha256_reader, sign_manifest_hex,
    BundleVerifier, EMBEDDED_BUNDLE_PUBLIC_KEY,
};
pub use manifest::{
    ArtifactRole, BundleFileEntry, BundleManifest, MANIFEST_FILENAME, MANIFEST_FORMAT_VERSION,
    MAX_MANIFEST_BYTES, SIGNATURE_FILENAME,
};
