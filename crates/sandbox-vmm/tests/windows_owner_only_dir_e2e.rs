#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::SandboxError;
use sandbox_vmm::os::windows::{
    create_new_owner_only_dir, create_owner_only_dir, current_user_sid_string,
    validate_owner_only_dacl,
};

struct OwnerOnlyTempDir(PathBuf);

impl OwnerOnlyTempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mini-pod-exclusive-dir-{}-{nanos}",
            std::process::id()
        ));
        create_owner_only_dir(&path).expect("create owner-only fixture directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for OwnerOnlyTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exclusive_create_rejects_existing_owner_only_directory_without_mutation() {
    let directory = OwnerOnlyTempDir::new();

    let new_directory = directory.path().join("new-output");
    create_new_owner_only_dir(&new_directory)
        .expect("exclusive create should create a missing owner-only directory");
    assert!(new_directory.is_dir());

    let existing_directory = directory.path().join("existing-output");
    create_owner_only_dir(&existing_directory).expect("create pre-existing owner-only directory");
    let sentinel = existing_directory.join("sentinel.txt");
    fs::write(&sentinel, b"preserve this file")
        .expect("write sentinel in pre-existing owner-only directory");

    assert!(matches!(
        create_new_owner_only_dir(&existing_directory),
        Err(SandboxError::PolicyViolation(_))
    ));
    assert_eq!(
        fs::read(&sentinel).expect("sentinel must remain after exclusive create failure"),
        b"preserve this file"
    );

    create_owner_only_dir(&existing_directory).expect("idempotent owner-only validation succeeds");
    assert_eq!(
        fs::read(&sentinel).expect("idempotent validation must preserve sentinel"),
        b"preserve this file"
    );
}

#[test]
fn validator_accepts_local_admin_alias_only_when_it_is_the_owner() {
    let owner_sid = current_user_sid_string().expect("current user SID");
    let local_account_domain = match (
        std::env::var("USERDOMAIN"),
        std::env::var("COMPUTERNAME"),
    ) {
        (Ok(user_domain), Ok(computer_name)) => {
            user_domain.eq_ignore_ascii_case(&computer_name)
        }
        _ => false,
    };
    let owner_is_local_admin = owner_sid.ends_with("-500");

    let local_admin_result = validate_owner_only_dacl(
        "D:P(A;OICI;FA;;;LA)",
        &owner_sid,
        true,
        "local-admin-alias-test",
    );
    if owner_is_local_admin && !local_account_domain {
        // A domain RID 500 is ambiguous here: LA can resolve to the machine account or to a domain alias.
    } else {
        assert_eq!(
            local_admin_result.is_ok(),
            owner_is_local_admin,
            "LA should be accepted only when it resolves to current owner SID {owner_sid}: {local_admin_result:?}"
        );
    }

    assert!(matches!(
        validate_owner_only_dacl(
            "D:P(A;OICI;FA;;;BA)",
            &owner_sid,
            true,
            "wrong-alias-test"
        ),
        Err(SandboxError::PolicyViolation(_))
    ));
}
