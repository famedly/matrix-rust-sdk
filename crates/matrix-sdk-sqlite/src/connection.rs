// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Connection management for `matrix-sdk-sqlite`.
//!
//! Two backends are provided behind `cfg(target_family)`:
//!
//! - **Native** (`native` module): a custom [`deadpool`] implementation for
//!   `rusqlite` with a pool of connections. See the [`native`] module
//!   documentation for the rationale behind the custom implementation.
//! - **WASM** (`wasm` module): a single `rusqlite::Connection` backed by the
//!   OPFS `sahpool` VFS. There is no pool, because the module runs inside a
//!   single Web Worker. See the [`wasm`] module documentation for details.

// ===========================================================================
// Native (non-WASM) connection implementation — deadpool-based
// ===========================================================================

#[cfg(not(target_family = "wasm"))]
mod native {
    //! An implementation of `deadpool` for `rusqlite`.
    //!
    //! Initially, we were using `deadpool-sqlite`, that is also using
    //! `rusqlite` as the SQLite interface. However, in the implementation of
    //! [`deadpool::managed::Manager`], when recycling an object (i.e. an SQLite
    //! connection), [a SQL query is run to detect whether the connection is
    //! still alive][connection-test]. It creates performance issues:
    //!
    //! 1. It runs a prepared SQL query, which has a non-negligle cost. Imagine
    //!    each connection is used to run on average one query; when recycled, a
    //!    second query was constantly run. Even if it's a simple query, it
    //!    requires to prepare a statement, to run and to query it.
    //! 2. The SQL query was run in a blocking task. Indeed,
    //!    `deadpool_runtime::spawn_blocking` is used (via
    //!    `deadpool_sync::SyncWrapper::interact`), which includes [blocking the
    //!    thread, acquiring a lock][spawn_blocking] etc. All this has more
    //!    performance cost.
    //!
    //! Measures have shown it is a performance bottleneck for us, especially on
    //! Android. Why specifically on Android and not other systems? This is
    //! still unclear at the time of writing (2025-11-11), despites having spent
    //! several days digging and trying to find an answer to this question.
    //!
    //! We have tried to use another approach to test the aliveness of the
    //! connections without running queries. It has involved patching `rusqlite`
    //! to add more bindings to SQLite, and patching `deadpool` itself, but
    //! without any successful results.
    //!
    //! Finally, we have started questioning the reason of this test: why
    //! testing whether the connection was still alive? After all, there is no
    //! reason a connection should die in our case:
    //!
    //! - all connections are local,
    //! - all interactions are behind [WAL], which is local only,
    //! - even if for an unknown reason the connection died, using it next time
    //!   would create an error… exactly what would happen when recycling the
    //!   connection.
    //!
    //! Consequently, we have created a new implementation of `deadpool` for
    //! `rusqlite` that doesn't test the aliveness of the connections when
    //! recycled. We assume they are all alive.
    //!
    //! This implementation is, at the time of writing (2025-11-11):
    //!
    //! - 3.5 times faster on Android than `deadpool-sqlite`, removing the lock
    //!   and thread contention entirely,
    //! - 2 times faster on iOS.
    //!
    //! [connection-test]: https://github.com/deadpool-rs/deadpool/blob/d6f7d58756f0cc7bdd1f3d54d820c1332d67e4d5/crates/deadpool-sqlite/src/lib.rs#L80-L100
    //! [spawn_blocking]: https://github.com/deadpool-rs/deadpool/blob/d6f7d58756f0cc7bdd1f3d54d820c1332d67e4d5/crates/deadpool-sync/src/lib.rs#L113-L131
    //! [WAL]: https://www.sqlite.org/wal.html

    use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

    pub use deadpool::managed::reexports::*;
    use deadpool::managed::{self, Metrics, PoolConfig, RecycleError};
    use deadpool_sync::SyncWrapper;
    use tokio::sync::Mutex;
    use tracing::{info, warn};

    /// The default runtime used by `matrix-sdk-sqlite` for `deadpool`.
    pub const RUNTIME: Runtime = Runtime::Tokio1;

    deadpool::managed_reexports!(
        "matrix-sdk-sqlite",
        Manager,
        managed::Object<Manager>,
        rusqlite::Error,
        Infallible
    );

    /// Type representing a connection to SQLite from the [`Pool`].
    pub type Connection = Object;

    /// [`Manager`][managed::Manager] for creating and recycling SQLite
    /// [`Connection`]s.
    #[derive(Debug)]
    pub struct Manager {
        pub(crate) database_path: PathBuf,
    }

    impl Manager {
        /// Creates a new [`Manager`] for a database.
        #[must_use]
        pub fn new(database_path: PathBuf) -> Self {
            Self { database_path }
        }
    }

    impl managed::Manager for Manager {
        type Type = SyncWrapper<rusqlite::Connection>;
        type Error = rusqlite::Error;

        async fn create(&self) -> Result<Self::Type, Self::Error> {
            let path = self.database_path.clone();
            SyncWrapper::new(RUNTIME, move || rusqlite::Connection::open(path)).await
        }

        async fn recycle(
            &self,
            conn: &mut Self::Type,
            _: &Metrics,
        ) -> managed::RecycleResult<Self::Error> {
            if conn.is_mutex_poisoned() {
                return Err(RecycleError::Message(
                    "Mutex is poisoned. Connection is considered unusable.".into(),
                ));
            }
            Ok(())
        }
    }

    /// Gracefully close the store-owned write connection.
    ///
    /// Callers are expected to remove the enclosing [`SqliteConnections`] from
    /// the store before calling this helper so no new write acquisitions can
    /// happen through the store API.
    ///
    /// 1. Waits for any in-flight write to complete by acquiring the lock.
    /// 2. Runs a WAL checkpoint (TRUNCATE) to flush pending data to the main
    ///    database file and release WAL locks.
    /// 3. Drops the store-owned `Arc` on a blocking thread.
    ///
    /// This is still best effort: if another cloned `Arc` or an
    /// `OwnedMutexGuard<Connection>` is still alive elsewhere, the underlying
    /// SQLite connection may remain alive until that handle is dropped.
    pub async fn close_connection(write_connection: Arc<Mutex<Connection>>) {
        // Acquire the lock to wait for any in-flight write to complete.
        let guard = write_connection.lock().await;

        // Flush WAL and release locks while we still own the connection.
        let _ = guard
            .interact(|raw| {
                raw.execute_batch("PRAGMA locking_mode = NORMAL; PRAGMA wal_checkpoint(TRUNCATE);")
                    .ok();
            })
            .await;

        drop(guard);

        // Drop the store-owned Arc on a blocking thread.
        let _ = tokio::task::spawn_blocking(move || drop(write_connection)).await;
    }

    /// Live database connections held by each SQLite store.
    ///
    /// Wrapped in `Option<SqliteConnections>` guarded by a `Mutex` inside each
    /// store; `Some` means the store is active, `None` means it is closed.
    pub(crate) struct SqliteConnections {
        /// The pool of read connections.
        pub pool: Pool,
        /// The dedicated write connection.
        ///
        /// This lives behind `Arc<Mutex<_>>` so stores can clone the `Arc` and
        /// obtain an `OwnedMutexGuard<Connection>` without holding the outer
        /// `connections` mutex across await points.
        pub write_connection: Arc<Mutex<Connection>>,
    }

    /// Close a store by taking its connections out.
    ///
    /// After this returns, any new call to `read()` or `write()` through the
    /// store will fail with [`crate::error::Error::StoreClosed`] until
    /// [`reopen_connections`] is called.
    ///
    /// Idempotent: if the store is already closed this is a no-op.
    pub(crate) async fn close_connections(
        connections: &Mutex<Option<SqliteConnections>>,
        label: &str,
    ) {
        let mut guard = connections.lock().await;
        let Some(conns) = guard.take() else {
            // Already closed — idempotent.
            return;
        };

        let SqliteConnections { pool, write_connection } = conns;

        // Close the pool. Idle read connections are dropped immediately;
        // in-flight reads complete and their connections are discarded (not
        // recycled) on release. New pool.get() calls return PoolError::Closed.
        pool.close();

        let status = pool.status();
        info!(
            size = status.size,
            max_size = status.max_size,
            available = status.available,
            "{label} pause: pool closed"
        );

        // Close the write connection: wait for any in-flight write to finish,
        // run a WAL checkpoint, then drop on a blocking thread.
        close_connection(write_connection).await;

        let status = pool.status();
        info!(
            size = status.size,
            max_size = status.max_size,
            available = status.available,
            "{label} pause: write connection released"
        );

        // Wait for any in-flight read connections to drain.
        // The write connection has already been released above, so
        // pool.status().size == 0 now correctly means every connection is gone
        // and no SQLite file locks are held.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while pool.status().size > 0 {
            if tokio::time::Instant::now() >= deadline {
                let status = pool.status();
                warn!(
                    size = status.size,
                    max_size = status.max_size,
                    available = status.available,
                    "Timed out waiting for SQLite pool connections to drain"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Resume a store by rebuilding its connections.
    ///
    /// Idempotent: if the store is already active this is a no-op.
    pub(crate) async fn reopen_connections(
        connections: &Mutex<Option<SqliteConnections>>,
        db_path: PathBuf,
        pool_config: PoolConfig,
        runtime_config: crate::RuntimeConfig,
    ) -> crate::error::Result<()> {
        use crate::utils::SqliteAsyncConnExt as _;

        let mut guard = connections.lock().await;
        if guard.is_some() {
            // Not closed — idempotent.
            return Ok(());
        }

        // Rebuild the pool (connections are created lazily on first get()).
        let pool = Pool::builder(Manager::new(db_path))
            .config(pool_config)
            .runtime(RUNTIME)
            .build()
            .map_err(|e| crate::error::Error::InvalidData {
                details: format!("Failed to rebuild connection pool: {e}"),
            })?;

        let write_conn = pool.get().await?;
        // Re-apply runtime config (WAL mode, busy timeout, etc.)
        write_conn.apply_runtime_config(runtime_config).await?;

        *guard =
            Some(SqliteConnections { pool, write_connection: Arc::new(Mutex::new(write_conn)) });

        Ok(())
    }
}

#[cfg(not(target_family = "wasm"))]
pub use native::*;
// Target-neutral aliases, so that shared code (e.g. `error.rs`) does not need
// to distinguish between the pool-based native backend and the single
// connection WASM backend.
#[cfg(not(target_family = "wasm"))]
pub use native::{CreatePoolError as OpenConnectionError, PoolError as AcquireConnectionError};
#[cfg(not(target_family = "wasm"))]
pub(crate) use native::{SqliteConnections, close_connections, reopen_connections};

// ===========================================================================
// WASM connection implementation — single connection, no pool
// ===========================================================================

#[cfg(target_family = "wasm")]
mod wasm {
    use std::{cell::RefCell, rc::Rc};

    use send_wrapper::SendWrapper;
    use tracing::{info, warn};

    /// A thin wrapper around `rusqlite::Connection` for WASM.
    ///
    /// Uses `SendWrapper<Rc<RefCell>>` to satisfy the `Send + Sync` bounds
    /// required by the async store traits.
    ///
    /// `SendWrapper` panics at runtime if accessed from a thread other than the
    /// one that created it. This is safe under the expected WASM deployment:
    ///   1. The entire WASM module runs inside a single Web Worker.
    ///   2. All calls are dispatched to that Worker via message passing.
    ///   3. The `Connection` is created and accessed exclusively on the Worker
    ///      thread, so `SendWrapper`'s thread check always passes.
    ///
    /// This applies to both WASM-without-atomics (trivially single-threaded)
    /// and WASM-with-atomics (single Worker, message-passing dispatch). Using
    /// `Rc<RefCell>` instead of `Arc<Mutex>` avoids unnecessary atomic overhead
    /// on the inherently single-threaded Worker.
    pub struct Connection {
        inner: SendWrapper<Rc<RefCell<rusqlite::Connection>>>,
    }

    impl Connection {
        pub(crate) fn new(conn: rusqlite::Connection) -> Self {
            Self { inner: SendWrapper::new(Rc::new(RefCell::new(conn))) }
        }

        /// Run a synchronous closure against the underlying
        /// `rusqlite::Connection`.
        ///
        /// This is the WASM equivalent of `SyncWrapper::interact` — the closure
        /// runs inline (no thread hop) and cannot be cancelled, so unlike the
        /// native version it is infallible.
        pub fn interact<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut rusqlite::Connection) -> R,
        {
            f(&mut self.inner.borrow_mut())
        }
    }

    impl Clone for Connection {
        fn clone(&self) -> Self {
            Self { inner: SendWrapper::new(Rc::clone(&self.inner)) }
        }
    }

    /// Error when acquiring a connection.
    ///
    /// Equivalent of the native `PoolError`.
    #[derive(Debug, thiserror::Error)]
    pub enum AcquireConnectionError {
        #[error("WASM SQLite error: {0}")]
        Backend(#[from] rusqlite::Error),
    }

    /// Error when opening the database connection.
    ///
    /// Equivalent of the native `CreatePoolError`.
    #[derive(Debug, thiserror::Error)]
    pub enum OpenConnectionError {
        #[error("WASM SQLite init error: {0}")]
        Backend(#[from] rusqlite::Error),
    }

    pub(crate) struct SqliteConnections {
        pub conn: Connection,
        pub write_connection: std::sync::Arc<tokio::sync::Mutex<Connection>>,
    }

    impl SqliteConnections {
        pub fn new(conn: Connection) -> Self {
            let write_conn = conn.clone();
            Self {
                conn,
                write_connection: std::sync::Arc::new(tokio::sync::Mutex::new(write_conn)),
            }
        }
    }

    pub(crate) async fn close_connections(
        connections: &tokio::sync::Mutex<Option<SqliteConnections>>,
        label: &str,
    ) {
        let mut guard = connections.lock().await;
        if let Some(conns) = guard.take() {
            // Flush WAL before dropping so OPFS has a compact checkpointed
            // database before the worker releases its sync access handles.
            if let Err(e) =
                conns.conn.interact(|raw| raw.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"))
            {
                warn!("{label} pause: WAL checkpoint error: {e}");
            }
            // Drop `conns` — when the last Rc<RefCell<Connection>> reference
            // count reaches zero, rusqlite::Connection::drop calls
            // sqlite3_close which triggers the VFS xClose/xSync.
            drop(conns);
            info!("{label} pause: WASM connection closed");
        }
    }

    pub(crate) async fn reopen_connections(
        connections: &tokio::sync::Mutex<Option<SqliteConnections>>,
        db_name: &str,
        runtime_config: crate::RuntimeConfig,
    ) -> crate::error::Result<()> {
        use crate::utils::SqliteAsyncConnExt as _;

        let mut guard = connections.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let conn =
            open_wasm_connection(db_name).await.map_err(|e| crate::error::Error::InvalidData {
                details: format!("Failed to reopen WASM connection: {e}"),
            })?;
        conn.apply_runtime_config(runtime_config).await?;
        *guard = Some(SqliteConnections::new(conn));

        Ok(())
    }

    /// Open a WASM database connection using the OPFS sahpool VFS.
    pub(crate) async fn open_wasm_connection(
        db_name: &str,
    ) -> Result<Connection, OpenConnectionError> {
        use sqlite_wasm_vfs::sahpool::{OpfsSAHPoolCfgBuilder, install as install_sahpool};

        fn map_vfs_err(
            context: &str,
            error: sqlite_wasm_vfs::sahpool::OpfsSAHError,
        ) -> OpenConnectionError {
            OpenConnectionError::Backend(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                Some(format!("{context}: {error:?}")),
            ))
        }

        // The worker opens four SDK databases. With WAL enabled, each database
        // needs two file slots (main database + WAL file), so sahpool needs
        // more slots than its single-database default of 6.
        const OPFS_SAHPOOL_MINIMUM_CAPACITY: u32 = 16;
        let cfg =
            OpfsSAHPoolCfgBuilder::new().initial_capacity(OPFS_SAHPOOL_MINIMUM_CAPACITY).build();

        let util = install_sahpool::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
            .await
            .map_err(|e| map_vfs_err("sahpool VFS install failed", e))?;

        // `install` is idempotent: if the VFS was already installed (e.g. by
        // another store or the embedding application), our `initial_capacity`
        // is ignored. The pool does not grow on demand — opening a database
        // fails once all slots are taken — so explicitly ensure the capacity
        // we need is actually available.
        util.reserve_minimum_capacity(OPFS_SAHPOOL_MINIMUM_CAPACITY)
            .await
            .map_err(|e| map_vfs_err("failed to reserve sahpool VFS capacity", e))?;

        let raw = rusqlite::Connection::open(db_name).map_err(OpenConnectionError::Backend)?;

        for (name, statement) in [
            ("foreign_keys", "PRAGMA foreign_keys = ON;"),
            // The page size must be set before the database is created and
            // cannot be changed anymore once WAL mode is entered, so this must
            // come before the `journal_mode` PRAGMA.
            ("page_size", "PRAGMA page_size = 4096;"),
            // The sahpool VFS does not implement the shared-memory primitives
            // (`xShmMap` & co.), so SQLite silently refuses to switch to WAL
            // unless the connection is in exclusive locking mode, where the
            // WAL index lives on the heap instead. Exclusive locking is fine
            // here: there is only ever a single connection per database.
            // See <https://www.sqlite.org/wal.html#noshm>.
            ("locking_mode", "PRAGMA locking_mode = EXCLUSIVE;"),
            ("journal_mode", "PRAGMA journal_mode = WAL;"),
            ("synchronous", "PRAGMA synchronous = NORMAL;"),
            ("temp_store", "PRAGMA temp_store = MEMORY;"),
        ] {
            raw.execute_batch(statement).map_err(|e| {
                OpenConnectionError::Backend(match e {
                    rusqlite::Error::SqliteFailure(err, message) => rusqlite::Error::SqliteFailure(
                        err,
                        Some(format!(
                            "failed to apply PRAGMA {name} to {db_name}: {}",
                            message.unwrap_or_else(|| err.to_string())
                        )),
                    ),
                    other => other,
                })
            })?;
        }

        Ok(Connection::new(raw))
    }
}

#[cfg(target_family = "wasm")]
pub use wasm::*;
#[cfg(target_family = "wasm")]
pub(crate) use wasm::{SqliteConnections, close_connections, reopen_connections};
