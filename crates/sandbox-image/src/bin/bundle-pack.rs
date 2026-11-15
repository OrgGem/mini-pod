#![forbid(unsafe_code)]
//! CLI tool to generate Ed25519 signing keypairs and pack/sign Portable Runtime Bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use sandbox_core::{GuestArch, SandboxError};
use sandbox_image::installer::validate_bundle_tree;
use sandbox_image::{
    decode_hex_exact, encode_hex, public_key_from_secret, sha256_reader, sign_manifest_hex,
    verify_installed_bundle, ArtifactRole, BundleFileEntry, BundleManifest, BundleVerifier,
    MANIFEST_FILENAME, MANIFEST_FORMAT_VERSION, SIGNATURE_FILENAME,
};

const MAX_SECRET_KEY_FILE_BYTES: usize = 4096;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

enum CliCommand {
    Help,
    GenerateKeypair {
        secret_hex_out: PathBuf,
        pub_hex_out: PathBuf,
    },
    Pack(PackArgs),
}

struct PackArgs {
    bundle_dir: PathBuf,
    bundle_id: String,
    host_os: String,
    guest_arch: GuestArch,
    source_pins: BTreeMap<String, String>,
    entries: Vec<(ArtifactRole, String)>,
    secret_key_file: PathBuf,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run_cli(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("bundle-pack error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(args: &[String]) -> Result<(), SandboxError> {
    match parse_cli_args(args)? {
        CliCommand::Help => {
            println!("{}", usage_text());
            Ok(())
        }
        CliCommand::GenerateKeypair {
            secret_hex_out,
            pub_hex_out,
        } => cmd_generate_keypair(&secret_hex_out, &pub_hex_out),
        CliCommand::Pack(pack_args) => cmd_pack(pack_args),
    }
}

fn usage_text() -> &'static str {
    "Usage:\n  \
     bundle-pack --generate-keypair <secret_hex_out> <pub_hex_out>\n  \
     bundle-pack --bundle-dir <dir> --bundle-id <id> --host-os <os> --guest-arch <arch> \\\n    \
     --pin <k=v> ... --entry <role=rel_path> ... --secret-key-file <path>"
}

fn parse_cli_args(args: &[String]) -> Result<CliCommand, SandboxError> {
    if args.is_empty() {
        return Err(SandboxError::InvalidSpec(format!(
            "missing arguments\n{}",
            usage_text()
        )));
    }
    if args[0] == "--help" || args[0] == "-h" {
        return Ok(CliCommand::Help);
    }

    if args[0] == "--generate-keypair" {
        if args.len() != 3 {
            return Err(SandboxError::InvalidSpec(
                "--generate-keypair requires exactly <secret_hex_out> <pub_hex_out>".to_owned(),
            ));
        }
        return Ok(CliCommand::GenerateKeypair {
            secret_hex_out: PathBuf::from(&args[1]),
            pub_hex_out: PathBuf::from(&args[2]),
        });
    }

    let mut bundle_dir: Option<PathBuf> = None;
    let mut bundle_id: Option<String> = None;
    let mut host_os: Option<String> = None;
    let mut guest_arch: Option<GuestArch> = None;
    let mut source_pins: BTreeMap<String, String> = BTreeMap::new();
    let mut entries: Vec<(ArtifactRole, String)> = Vec::new();
    let mut secret_key_file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args.get(i + 1).ok_or_else(|| {
            SandboxError::InvalidSpec(format!("flag '{flag}' requires a value"))
        })?;
        i += 2;

        match flag {
            "--bundle-dir" => set_once(&mut bundle_dir, PathBuf::from(value), flag)?,
            "--bundle-id" => set_once(&mut bundle_id, value.clone(), flag)?,
            "--host-os" => set_once(&mut host_os, value.clone(), flag)?,
            "--guest-arch" => set_once(&mut guest_arch, value.parse::<GuestArch>()?, flag)?,
            "--secret-key-file" => set_once(&mut secret_key_file, PathBuf::from(value), flag)?,
            "--pin" => {
                let (k, v) = value.split_once('=').ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "--pin value '{value}' must be in <key=value> format"
                    ))
                })?;
                if source_pins.insert(k.to_owned(), v.to_owned()).is_some() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "duplicate --pin key '{k}'"
                    )));
                }
            }
            "--entry" => {
                let (role_str, rel_path) = value.split_once('=').ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "--entry value '{value}' must be in <role=rel_path> format"
                    ))
                })?;
                let role = role_str.parse::<ArtifactRole>()?;
                entries.push((role, rel_path.to_owned()));
            }
            "--generate-keypair" => {
                return Err(SandboxError::InvalidSpec(
                    "--generate-keypair cannot be combined with bundle packing flags".to_owned(),
                ));
            }
            other => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown argument '{other}'\n{}",
                    usage_text()
                )));
            }
        }
    }

    Ok(CliCommand::Pack(PackArgs {
        bundle_dir: require_arg(bundle_dir, "--bundle-dir")?,
        bundle_id: require_arg(bundle_id, "--bundle-id")?,
        host_os: require_arg(host_os, "--host-os")?,
        guest_arch: require_arg(guest_arch, "--guest-arch")?,
        source_pins,
        entries,
        secret_key_file: require_arg(secret_key_file, "--secret-key-file")?,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), SandboxError> {
    if slot.is_some() {
        return Err(SandboxError::InvalidSpec(format!(
            "duplicate flag '{flag}'"
        )));
    }
    *slot = Some(value);
    Ok(())
}

fn require_arg<T>(slot: Option<T>, flag: &str) -> Result<T, SandboxError> {
    slot.ok_or_else(|| SandboxError::InvalidSpec(format!("missing required flag '{flag}'")))
}

fn cmd_generate_keypair(secret_hex_out: &Path, pub_hex_out: &Path) -> Result<(), SandboxError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret)
        .map_err(|err| SandboxError::Internal(format!("OS CSPRNG failed: {err}")))?;

    let pub_key = public_key_from_secret(&secret);
    BundleVerifier::with_public_key(pub_key)?;

    let secret_hex = format!("{}\n", encode_hex(&secret));
    let pub_hex = format!("{}\n", encode_hex(&pub_key));

    write_atomic_synced(secret_hex_out, secret_hex.as_bytes(), true)?;
    write_atomic_synced(pub_hex_out, pub_hex.as_bytes(), false)?;

    println!(
        "generated Ed25519 bundle keypair: pub={}",
        encode_hex(&pub_key)
    );
    Ok(())
}

fn cmd_pack(args: PackArgs) -> Result<(), SandboxError> {
    let secret = read_secret_key_hex(&args.secret_key_file)?;
    let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret))?;

    let provisional_entries: Vec<BundleFileEntry> = args
        .entries
        .iter()
        .map(|(role, rel_path)| BundleFileEntry {
            role: *role,
            rel_path: rel_path.clone(),
            sha256: [0u8; 32],
            size_bytes: 0,
        })
        .collect();
    let provisional = BundleManifest {
        format_version: MANIFEST_FORMAT_VERSION,
        bundle_id: args.bundle_id.clone(),
        host_os: args.host_os.clone(),
        guest_arch: args.guest_arch,
        source_pins: args.source_pins.clone(),
        entries: provisional_entries,
    };
    // Validate bundle_id, host_os, pins, rel_path safety, uniqueness, and required roles before I/O.
    provisional.validate()?;

    let declared_rel_paths: BTreeSet<&str> = args
        .entries
        .iter()
        .map(|(_, rel_path)| rel_path.as_str())
        .collect();
    validate_bundle_tree(&args.bundle_dir, &declared_rel_paths)?;

    let mut hashed_entries = Vec::with_capacity(args.entries.len());
    for (role, rel_path) in args.entries {
        let host_path = rel_path_to_host(&args.bundle_dir, &rel_path);
        ensure_regular_non_link(&host_path)?;
        let mut file = fs::File::open(&host_path).map_err(|err| {
            SandboxError::Internal(format!(
                "failed to open bundle entry '{}' for hashing: {err}",
                host_path.display()
            ))
        })?;
        let (sha256, size_bytes) = sha256_reader(&mut file)?;
        hashed_entries.push(BundleFileEntry {
            role,
            rel_path,
            sha256,
            size_bytes,
        });
    }

    let manifest = BundleManifest {
        format_version: MANIFEST_FORMAT_VERSION,
        bundle_id: args.bundle_id,
        host_os: args.host_os,
        guest_arch: args.guest_arch,
        source_pins: args.source_pins,
        entries: hashed_entries,
    };
    let canonical = manifest.encode_canonical()?;
    let sig_hex = format!("{}\n", sign_manifest_hex(&secret, canonical.as_bytes()));

    write_atomic_synced(
        &args.bundle_dir.join(MANIFEST_FILENAME),
        canonical.as_bytes(),
        false,
    )?;
    write_atomic_synced(
        &args.bundle_dir.join(SIGNATURE_FILENAME),
        sig_hex.as_bytes(),
        false,
    )?;

    verify_installed_bundle(&args.bundle_dir, &verifier)?;
    Ok(())
}

fn read_secret_key_hex(path: &Path) -> Result<[u8; 32], SandboxError> {
    let meta = ensure_regular_non_link(path)?;
    if meta.len() > MAX_SECRET_KEY_FILE_BYTES as u64 {
        return Err(SandboxError::InvalidSpec(format!(
            "secret key file '{}' exceeds {} bytes",
            path.display(),
            MAX_SECRET_KEY_FILE_BYTES
        )));
    }
    let file = fs::File::open(path).map_err(|err| map_io_error(path, "open secret key", err))?;
    let mut raw = Vec::new();
    file.take((MAX_SECRET_KEY_FILE_BYTES as u64) + 1)
        .read_to_end(&mut raw)
        .map_err(|err| map_io_error(path, "read secret key", err))?;
    if raw.len() > MAX_SECRET_KEY_FILE_BYTES {
        return Err(SandboxError::InvalidSpec(format!(
            "secret key file '{}' exceeds {} bytes",
            path.display(),
            MAX_SECRET_KEY_FILE_BYTES
        )));
    }
    let hex_str = std::str::from_utf8(&raw).map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "secret key file '{}' is not valid UTF-8: {err}",
            path.display()
        ))
    })?;
    decode_hex_exact::<32>(hex_str.trim())
}

fn ensure_regular_non_link(path: &Path) -> Result<fs::Metadata, SandboxError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| map_io_error(path, "inspect path metadata", err))?;
    check_no_reparse_or_symlink(path, &meta)?;
    if !meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "expected regular file at '{}'",
            path.display()
        )));
    }
    Ok(meta)
}

fn check_no_reparse_or_symlink(path: &Path, meta: &fs::Metadata) -> Result<(), SandboxError> {
    if meta.file_type().is_symlink() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing symlink at '{}'",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing Windows reparse point at '{}'",
                path.display()
            )));
        }
    }
    #[cfg(not(windows))]
    let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
    Ok(())
}

fn write_atomic_synced(
    target_path: &Path,
    bytes: &[u8],
    restrict_owner_only: bool,
) -> Result<(), SandboxError> {
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "output path '{}' must end with a valid UTF-8 filename",
                target_path.display()
            ))
        })?;
    let parent = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    match fs::symlink_metadata(parent) {
        Ok(meta) => {
            check_no_reparse_or_symlink(parent, &meta)?;
            if !meta.file_type().is_dir() {
                return Err(SandboxError::PolicyViolation(format!(
                    "output parent '{}' must be a regular directory",
                    parent.display()
                )));
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(parent)
                .map_err(|e| map_io_error(parent, "create output parent directory", e))?;
        }
        Err(err) => return Err(map_io_error(parent, "inspect output parent directory", err)),
    }

    match fs::symlink_metadata(target_path) {
        Ok(_) => {
            let _ = ensure_regular_non_link(target_path)?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(map_io_error(target_path, "inspect output path", err)),
    }

    let tmp_path = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut tmp_guard = TempFileGuard(Some(tmp_path.clone()));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if restrict_owner_only { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = restrict_owner_only;

    let mut file = opts
        .open(&tmp_path)
        .map_err(|err| map_io_error(&tmp_path, "create temporary output file", err))?;
    file.write_all(bytes)
        .map_err(|err| map_io_error(&tmp_path, "write temporary output file", err))?;
    file.sync_all()
        .map_err(|err| map_io_error(&tmp_path, "sync temporary output file", err))?;
    drop(file);

    fs::rename(&tmp_path, target_path)
        .map_err(|err| map_io_error(target_path, "rename temporary output file", err))?;
    tmp_guard.0 = None;
    Ok(())
}

fn rel_path_to_host(root: &Path, rel_path: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for segment in rel_path.split('/') {
        out.push(segment);
    }
    out
}

fn map_io_error(path: &Path, action: &str, err: std::io::Error) -> SandboxError {
    match err.kind() {
        ErrorKind::NotFound => {
            SandboxError::NotFound(format!("cannot {action} '{}': {err}", path.display()))
        }
        ErrorKind::PermissionDenied => SandboxError::PolicyViolation(format!(
            "permission denied while attempting to {action} '{}': {err}",
            path.display()
        )),
        _ => SandboxError::Internal(format!("failed to {action} '{}': {err}", path.display())),
    }
}

struct TempFileGuard(Option<PathBuf>);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-pack-test-{label}-{}-{}",
                std::process::id(),
                NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
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
    fn keypair_generation_and_pack_sign_verify_end_to_end() {
        let tmp = TestTempDir::new("e2e");
        let secret_path = tmp.path().join("keys").join("bundle.key");
        let pub_path = tmp.path().join("keys").join("bundle.pub");

        let gen_args: Vec<String> = vec![
            "--generate-keypair".into(),
            secret_path.to_string_lossy().into_owned(),
            pub_path.to_string_lossy().into_owned(),
        ];
        run_cli(&gen_args).expect("generate-keypair must succeed");

        let pub_bytes = fs::read_to_string(&pub_path).unwrap();
        let pub_key = decode_hex_exact::<32>(pub_bytes.trim()).unwrap();
        let verifier = BundleVerifier::with_public_key(pub_key).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let bundle_dir = tmp.path().join("bundle");
        fs::create_dir_all(bundle_dir.join("boot")).unwrap();
        fs::create_dir_all(bundle_dir.join("images")).unwrap();
        fs::write(bundle_dir.join("boot").join("vmlinuz"), b"kernel").unwrap();
        fs::write(bundle_dir.join("boot").join("initrd.img"), b"initrd").unwrap();
        fs::write(bundle_dir.join("images").join("rootfs.qcow2"), b"qcow2").unwrap();

        let pack_args: Vec<String> = vec![
            "--bundle-dir".into(),
            bundle_dir.to_string_lossy().into_owned(),
            "--bundle-id".into(),
            "minipod-pack-test".into(),
            "--host-os".into(),
            "any".into(),
            "--guest-arch".into(),
            "x86_64".into(),
            "--pin".into(),
            "alpine=3.20.3".into(),
            "--pin".into(),
            "qemu=9.1.0".into(),
            "--entry".into(),
            "kernel=boot/vmlinuz".into(),
            "--entry".into(),
            "initrd=boot/initrd.img".into(),
            "--entry".into(),
            "base_rootfs_qcow2=images/rootfs.qcow2".into(),
            "--secret-key-file".into(),
            secret_path.to_string_lossy().into_owned(),
        ];
        run_cli(&pack_args).expect("pack must succeed");
        verify_installed_bundle(&bundle_dir, &verifier).expect("packed bundle must verify");

        // Re-packing when manifest.v1 and manifest.sig already exist must succeed.
        run_cli(&pack_args).expect("re-pack with existing manifest.v1/manifest.sig must succeed");

        // Adding an undeclared extra file must fail packing.
        fs::write(bundle_dir.join("version.dll"), b"rogue").unwrap();
        assert!(matches!(
            run_cli(&pack_args),
            Err(SandboxError::PolicyViolation(_))
        ));
    }
}
