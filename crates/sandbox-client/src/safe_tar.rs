//! Client-side safe host tar packing and extraction backed by [`sandbox_core::safe_tar`].

use std::path::Path;

use sandbox_core::SandboxError;

/// Packs a host regular file or directory tree into an in-memory GNU tar archive bounded by
/// `max_bytes`, inspecting every path component with `symlink_metadata` and rejecting symlinks,
/// Windows reparse points, and non-regular/non-directory nodes.
pub fn pack_path_to_tar_bytes(src: &Path, max_bytes: u64) -> Result<Vec<u8>, SandboxError> {
    sandbox_core::safe_tar::pack_host_path_to_tar(src, max_bytes)
}

/// Safely extracts `tar_bytes` into `dst`, enforcing `max_entries`, `max_bytes`, strict relative
/// UTF-8 path validation, `Regular`/`Directory` entry-type allowlisting, and atomic per-file staging.
pub fn extract_tar_bytes_safely(
    tar_bytes: &[u8],
    dst: &Path,
    max_bytes: u64,
    max_entries: usize,
) -> Result<u64, SandboxError> {
    sandbox_core::safe_tar::extract_tar_safely(tar_bytes, dst, max_bytes, max_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-client-tar-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn client_safe_tar_delegates_roundtrip() {
        let tmp = TestTempDir::new("delegate");
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("nested").join("hello.txt"), b"client safe tar").unwrap();

        let tar_bytes = pack_path_to_tar_bytes(&src, 64 * 1024).unwrap();
        let extracted = extract_tar_bytes_safely(&tar_bytes, &dst, 64 * 1024, 16).unwrap();

        assert_eq!(extracted, b"client safe tar".len() as u64);
        assert_eq!(
            fs::read(dst.join("nested").join("hello.txt")).unwrap(),
            b"client safe tar"
        );
    }
}
