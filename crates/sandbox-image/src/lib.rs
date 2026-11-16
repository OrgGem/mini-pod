#![forbid(unsafe_code)]
//! Layer 3 image adapter boundary: Ed25519 manifest & SHA-256 bundle verification,
//! atomic directory swap, and atomic qcow2 Copy-on-Write overlay creation.

pub mod adapter;
pub mod crypto;
pub mod installer;
pub mod manifest;
pub mod qcow2;

pub use adapter::BundleOverlayStore;
pub use crypto::{
    decode_hex_exact, encode_hex, public_key_from_secret, sha256_reader, sign_manifest_hex,
    BundleVerifier, EMBEDDED_BUNDLE_PUBLIC_KEY,
};
pub use installer::{install_bundle_atomic, verify_installed_bundle, InstalledBundle};
pub use manifest::{
    ArtifactRole, BundleFileEntry, BundleManifest, MANIFEST_FILENAME, MANIFEST_FORMAT_VERSION,
    MAX_MANIFEST_BYTES, SIGNATURE_FILENAME,
};
pub use qcow2::{
    clean_qemu_host_path, create_qcow2_overlay_atomic, create_qcow2_overlay_atomic_with_runner,
    inspect_qcow2_header, HelperCommandOutput, HelperCommandRunner, Qcow2HeaderInfo,
};
