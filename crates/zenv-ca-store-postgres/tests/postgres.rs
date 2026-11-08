//! Runs against a real PostgreSQL when `ZENV_CA_TEST_POSTGRES_URL` is set, e.g.
//!
//! ```text
//! ZENV_CA_TEST_POSTGRES_URL='postgresql://zenv:secret@127.0.0.1:5432/zenv_test' \
//!     cargo test -p zenv-ca-store-postgres
//! ```
//!
//! Every test works in its own throwaway schema, so point it at a disposable database.
//! Without the variable the database tests are skipped (they pass with a "skipped" note).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use zenv_ca_core::RevocationReason;
use zenv_ca_store::testkit::{concurrent_writers_keep_chain_intact, sample_cert};
use zenv_ca_store::{CaStore, IssuanceMethod, Role, StoreError};
use zenv_ca_store_postgres::{PostgresOptions, PostgresStore};

const URL_VAR: &str = "ZENV_CA_TEST_POSTGRES_URL";

fn url() -> Option<String> {
    std::env::var(URL_VAR).ok().filter(|u| !u.is_empty())
}

/// Creates a unique, empty schema and returns its name.
fn new_schema(url: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "zca_t{}_{}_{:08x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        rand::random::<u32>()
    );
    let mut admin = postgres::Client::connect(url, postgres::NoTls).unwrap();
    admin.batch_execute(&format!("CREATE SCHEMA {name}")).unwrap();
    name
}

fn options(url: &str, schema: &str) -> PostgresOptions {
    PostgresOptions {
        schema: Some(schema.to_owned()),
        pool_size: 3,
        ..PostgresOptions::new(url)
    }
}

fn fresh() -> Option<Box<dyn CaStore>> {
    let url = url()?;
    let schema = new_schema(&url);
    Some(Box::new(PostgresStore::open(&options(&url, &schema)).unwrap()))
}

zenv_ca_store::conformance_tests!(fresh);

#[test]
fn two_instances_share_one_chain() {
    let Some(url) = url() else { return };
    let schema = new_schema(&url);
    // Two independent pools on the same schema = two daemon instances.
    let a: Arc<dyn CaStore> = Arc::new(PostgresStore::open(&options(&url, &schema)).unwrap());
    let b: Arc<dyn CaStore> = Arc::new(PostgresStore::open(&options(&url, &schema)).unwrap());
    concurrent_writers_keep_chain_intact(a, b);
}

#[test]
fn audit_log_is_append_only_and_tamper_evident() {
    let Some(url) = url() else { return };
    let schema = new_schema(&url);
    let store = PostgresStore::open(&options(&url, &schema)).unwrap();
    store.create_token("ops", Role::Admin, "cli:root").unwrap();
    store
        .insert_certificate(
            &sample_cert("aa01", "a.dmz.zenv.internal", 30),
            IssuanceMethod::Csr,
            "ops",
        )
        .unwrap();
    store.revoke("aa01", RevocationReason::Superseded, "ops").unwrap();
    assert!(store.verify_audit_chain().unwrap().intact);

    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.batch_execute(&format!("SET search_path TO {schema}"))
        .unwrap();
    for sql in [
        "UPDATE audit_log SET actor = 'mallory' WHERE id = 2",
        "DELETE FROM audit_log WHERE id = 2",
        "TRUNCATE audit_log",
    ] {
        let err = raw.batch_execute(sql).unwrap_err();
        let message = err
            .as_db_error()
            .map(|d| d.message().to_owned())
            .unwrap_or_default();
        assert!(message.contains("append-only"), "{sql}: {err:?}");
    }
    // Someone who can disable the trigger can edit rows, but the hash chain exposes it.
    raw.batch_execute(
        "ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
         UPDATE audit_log SET actor = 'mallory' WHERE id = 2;",
    )
    .unwrap();
    let v = store.verify_audit_chain().unwrap();
    assert!(!v.intact);
    assert_eq!(v.first_broken_id, Some(2));
}

#[test]
fn reopening_is_idempotent_and_newer_schema_is_refused() {
    let Some(url) = url() else { return };
    let schema = new_schema(&url);
    PostgresStore::open(&options(&url, &schema))
        .unwrap()
        .create_token("x", Role::Admin, "t")
        .unwrap();
    let store = PostgresStore::open(&options(&url, &schema)).unwrap();
    assert!(store.has_admin().unwrap());
    assert_eq!(store.backend(), "postgres");

    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.batch_execute(&format!(
        "UPDATE {schema}.zenv_ca_schema_version SET version = 99"
    ))
    .unwrap();
    assert!(matches!(
        PostgresStore::open(&options(&url, &schema)),
        Err(StoreError::SchemaTooNew(99))
    ));
}

#[test]
fn bad_settings_fail_fast() {
    // No server needed: these fail before connecting.
    let bad_schema = PostgresOptions {
        schema: Some("Robert'); DROP TABLE x;--".into()),
        ..PostgresOptions::new("postgresql://u@127.0.0.1/db")
    };
    assert!(matches!(
        PostgresStore::open(&bad_schema),
        Err(StoreError::Configuration(_))
    ));
    assert!(matches!(
        PostgresStore::open(&PostgresOptions::new("not a url ://")),
        Err(StoreError::Configuration(_))
    ));
}
