//! Shared application state and the blocking-work bridge.

use std::sync::{Arc, RwLock};

use time::{Duration, OffsetDateTime};
use zenv_ca_core::{CertificateAuthority, CrlDocument};
use zenv_ca_store::Store;

use crate::error::{ApiError, ApiResult};

/// State shared by all handlers (cheap to clone).
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

#[derive(Debug, Clone)]
struct CachedCrl {
    doc: CrlDocument,
    revision: (i64, i64),
}

#[derive(Debug)]
struct Inner {
    ca: CertificateAuthority,
    store: Store,
    crl_cache: RwLock<Option<CachedCrl>>,
    crl_validity: Duration,
    tls_enabled: bool,
}

impl AppState {
    /// Builds the state.
    pub fn new(ca: CertificateAuthority, store: Store, crl_validity: Duration, tls_enabled: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                ca,
                store,
                crl_cache: RwLock::new(None),
                crl_validity,
                tls_enabled,
            }),
        }
    }

    /// The signing authority.
    pub fn ca(&self) -> &CertificateAuthority {
        &self.inner.ca
    }

    /// The database.
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// Whether the listener is HTTPS (controls HSTS).
    pub fn tls_enabled(&self) -> bool {
        self.inner.tls_enabled
    }

    /// Runs CPU-heavy or blocking work (signing, key generation, SQLite) off the async
    /// executor threads.
    pub async fn blocking<T, F>(&self, f: F) -> ApiResult<T>
    where
        F: FnOnce(&AppState) -> ApiResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let state = self.clone();
        tokio::task::spawn_blocking(move || f(&state)).await?
    }

    /// Returns the cached CRL if it is still in the first half of its lifetime **and** no
    /// revocation happened since it was signed (including revocations made via the CLI);
    /// otherwise re-signs it.
    pub fn current_crl(&self) -> ApiResult<CrlDocument> {
        let now = OffsetDateTime::now_utc();
        let revision = self.store().revocation_revision()?;
        if let Some(cached) = self.read_cache() {
            let fresh_until = cached.doc.next_update - self.inner.crl_validity / 2;
            if now < fresh_until && cached.revision == revision {
                return Ok(cached.doc);
            }
        }
        self.refresh_crl()
    }

    /// Re-signs the CRL from the inventory (called after every revocation).
    pub fn refresh_crl(&self) -> ApiResult<CrlDocument> {
        let mut cache = self
            .inner
            .crl_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let revision = self.store().revocation_revision()?;
        let entries = self.store().crl_entries()?;
        let number = self.store().next_crl_number("system", entries.len())?;
        let doc = self
            .ca()
            .build_crl(&entries, number, self.inner.crl_validity)
            .map_err(ApiError::from)?;
        tracing::info!(crl_number = number, entries = entries.len(), "CRL signed");
        *cache = Some(CachedCrl {
            doc: doc.clone(),
            revision,
        });
        Ok(doc)
    }

    fn read_cache(&self) -> Option<CachedCrl> {
        self.inner
            .crl_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
