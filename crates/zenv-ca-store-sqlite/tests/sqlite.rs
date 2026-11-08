#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use zenv_ca_core::RevocationReason;
use zenv_ca_store::testkit::{concurrent_writers_keep_chain_intact, sample_cert};
use zenv_ca_store::{CaStore, IssuanceMethod, Role};
use zenv_ca_store_sqlite::SqliteStore;

fn fresh() -> Option<Box<dyn CaStore>> {
    Some(Box::new(SqliteStore::open_in_memory().unwrap()))
}

// The backend-agnostic behaviour every store must have.
zenv_ca_store::conformance_tests!(fresh);

#[test]
fn concurrent_handles_on_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    let a: Arc<dyn CaStore> = Arc::new(SqliteStore::open(&path).unwrap());
    let b: Arc<dyn CaStore> = Arc::new(SqliteStore::open(&path).unwrap());
    concurrent_writers_keep_chain_intact(a, b);
}

#[test]
fn audit_chain_is_tamper_evident_and_file_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    {
        let store = SqliteStore::open(&path).unwrap();
        store.create_token("ops", Role::Admin, "cli:root").unwrap();
        store
            .insert_certificate(
                &sample_cert("aa01", "a.dmz.zenv.internal", 30),
                IssuanceMethod::Csr,
                "ops",
            )
            .unwrap();
        store.revoke("aa01", RevocationReason::Superseded, "ops").unwrap();
        let v = store.verify_audit_chain().unwrap();
        assert!(v.intact);
        assert_eq!(v.entries, 3);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The append-only triggers block naive tampering...
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(
        raw.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 2", [])
            .is_err()
    );
    assert!(raw.execute("DELETE FROM audit_log WHERE id = 2", []).is_err());
    // ...and if an attacker drops the triggers, the hash chain still exposes the edit.
    raw.execute_batch(
        "DROP TRIGGER audit_log_no_update; UPDATE audit_log SET actor = 'mallory' WHERE id = 2;",
    )
    .unwrap();
    drop(raw);

    let v = SqliteStore::open(&path).unwrap().verify_audit_chain().unwrap();
    assert!(!v.intact);
    assert_eq!(v.first_broken_id, Some(2));
}

#[test]
fn reopening_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    SqliteStore::open(&path)
        .unwrap()
        .create_token("x", Role::Admin, "t")
        .unwrap();
    let store = SqliteStore::open(&path).unwrap();
    assert!(store.has_admin().unwrap());
    assert_eq!(store.backend(), "sqlite");
}

#[test]
fn newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.db");
    drop(SqliteStore::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    assert!(matches!(
        SqliteStore::open(&path),
        Err(zenv_ca_store::StoreError::SchemaTooNew(99))
    ));
}
