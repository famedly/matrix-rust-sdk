// Copyright 2022 The Matrix.org Foundation C.I.C.
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

#![cfg_attr(
    not(any(feature = "state-store", feature = "crypto-store", feature = "event-cache")),
    allow(dead_code, unused_imports)
)]

mod connection;
#[cfg(feature = "crypto-store")]
mod crypto_store;
mod error;
#[cfg(feature = "event-cache")]
mod event_cache_store;
#[cfg(feature = "event-cache")]
mod media_store;
#[cfg(feature = "state-store")]
mod state_store;
mod utils;

use std::fmt;
#[cfg(target_family = "wasm")]
use std::path::Path;
#[cfg(not(target_family = "wasm"))]
use std::{
    cmp::max,
    path::{Path, PathBuf},
};

#[cfg(not(target_family = "wasm"))]
use deadpool::managed::PoolConfig;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "crypto-store")]
pub use self::crypto_store::SqliteCryptoStore;
pub use self::error::OpenStoreError;
#[cfg(feature = "event-cache")]
pub use self::event_cache_store::SqliteEventCacheStore;
#[cfg(feature = "event-cache")]
pub use self::media_store::SqliteMediaStore;
#[cfg(feature = "state-store")]
pub use self::state_store::{DATABASE_NAME as STATE_STORE_DATABASE_NAME, SqliteStateStore};

#[cfg(all(test, not(target_family = "wasm")))]
matrix_sdk_test_utils::init_tracing_for_tests!();

/// An enum used to store the secret that gives access to a store
#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub enum Secret {
    // Cryptographic key used to open the store
    Key(Box<[u8; 32]>),
    // Passphrase used to open the store
    PassPhrase(Zeroizing<String>),
}

// ===========================================================================
// Native SqliteStoreConfig — connection pool based
// ===========================================================================

/// A configuration structure used for opening a store.
#[cfg(not(target_family = "wasm"))]
#[derive(Clone)]
pub struct SqliteStoreConfig {
    /// Path to the database, without the file name.
    path: PathBuf,
    /// Secret to open the store, if any
    secret: Option<Secret>,
    /// The pool configuration for [`deadpool`].
    pool_config: PoolConfig,
    /// The runtime configuration to apply when opening an SQLite connection.
    runtime_config: RuntimeConfig,
}

#[cfg(not(target_family = "wasm"))]
impl fmt::Debug for SqliteStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStoreConfig")
            .field("path", &self.path)
            .field("pool_config", &self.pool_config)
            .field("runtime_config", &self.runtime_config)
            .finish_non_exhaustive()
    }
}

/// The minimum size of the connections pool.
///
/// We need at least 2 connections: one connection for write operations, and one
/// connection for read operations.
#[cfg(not(target_family = "wasm"))]
const POOL_MINIMUM_SIZE: usize = 2;

#[cfg(not(target_family = "wasm"))]
impl SqliteStoreConfig {
    /// Create a new [`SqliteStoreConfig`] with a path representing the
    /// directory containing the store database.
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            path: path.as_ref().to_path_buf(),
            pool_config: PoolConfig::new(max(POOL_MINIMUM_SIZE, num_cpus::get_physical() * 4)),
            runtime_config: RuntimeConfig::default(),
            secret: None,
        }
    }

    /// Similar to [`SqliteStoreConfig::new`], but with defaults tailored for a
    /// low memory usage environment.
    ///
    /// The following defaults are set:
    ///
    /// * The `pool_max_size` is set to the number of physical CPU, so one
    ///   connection per physical thread,
    /// * The `cache_size` is set to 500Kib,
    /// * The `journal_size_limit` is set to 2Mib.
    pub fn with_low_memory_config<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self::new(path)
            // Maximum one connection per physical thread.
            .pool_max_size(num_cpus::get_physical())
            // Cache size is 500Kib.
            .cache_size(500_000)
            // Journal size limit is 2Mib.
            .journal_size_limit(2_000_000)
    }

    /// Override the path.
    pub fn path<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        self.path = path.as_ref().to_path_buf();
        self
    }

    /// Define the passphrase if the store is encoded.
    pub fn passphrase(mut self, passphrase: Option<&str>) -> Self {
        self.secret =
            passphrase.map(|passphrase| Secret::PassPhrase(Zeroizing::new(passphrase.to_owned())));
        self
    }

    /// Define the key if the store is encoded.
    pub fn key(mut self, key: Option<&[u8; 32]>) -> Self {
        self.secret = key.map(|key| Secret::Key(Box::new(*key)));
        self
    }

    /// Define the maximum pool size for [`deadpool`].
    ///
    /// See [`deadpool::managed::PoolConfig::max_size`] to learn more.
    pub fn pool_max_size(mut self, max_size: usize) -> Self {
        self.pool_config.max_size = max(POOL_MINIMUM_SIZE, max_size);
        self
    }

    /// Optimize the database.
    ///
    /// The SQLite documentation recommends to run this regularly and after any
    /// schema change. The easiest is to do it consistently when the store is
    /// constructed, after eventual migrations.
    ///
    /// See [`PRAGMA optimize`] to learn more.
    ///
    /// The default value is `true`.
    ///
    /// [`PRAGMA optimize`]: https://www.sqlite.org/pragma.html#pragma_optimize
    pub fn optimize(mut self, optimize: bool) -> Self {
        self.runtime_config.optimize = optimize;
        self
    }

    /// Define the maximum size in **bytes** the SQLite cache can use.
    ///
    /// See [`PRAGMA cache_size`] to learn more.
    ///
    /// The default value is 2Mib.
    ///
    /// [`PRAGMA cache_size`]: https://www.sqlite.org/pragma.html#pragma_cache_size
    pub fn cache_size(mut self, cache_size: u32) -> Self {
        self.runtime_config.cache_size = cache_size;
        self
    }

    /// Limit the size of the WAL file, in **bytes**.
    ///
    /// By default, while the DB connections of the databases are open, [the
    /// size of the WAL file can keep increasing][size_wal_file] depending on
    /// the size needed for the transactions. A critical case is `VACUUM`
    /// which basically writes the content of the DB file to the WAL file
    /// before writing it back to the DB file, so we end up taking twice the
    /// size of the database.
    ///
    /// By setting this limit, the WAL file is truncated after its content is
    /// written to the database, if it is bigger than the limit.
    ///
    /// See [`PRAGMA journal_size_limit`] to learn more. The value `limit`
    /// corresponds to `N` in `PRAGMA journal_size_limit = N`.
    ///
    /// The default value is 10Mib.
    ///
    /// [size_wal_file]: https://www.sqlite.org/wal.html#avoiding_excessively_large_wal_files
    /// [`PRAGMA journal_size_limit`]: https://www.sqlite.org/pragma.html#pragma_journal_size_limit
    pub fn journal_size_limit(mut self, limit: u32) -> Self {
        self.runtime_config.journal_size_limit = limit;
        self
    }

    /// Returns the pool configuration.
    pub(crate) fn pool_config(&self) -> PoolConfig {
        self.pool_config
    }

    /// Returns the runtime configuration.
    pub(crate) fn runtime_config(&self) -> RuntimeConfig {
        self.runtime_config
    }

    /// Build a pool of active connections to a particular database.
    pub fn build_pool_of_connections(
        &self,
        database_name: &str,
    ) -> Result<connection::Pool, connection::CreatePoolError> {
        let path = self.path.join(database_name);
        let manager = connection::Manager::new(path);

        connection::Pool::builder(manager)
            .config(self.pool_config)
            .runtime(connection::RUNTIME)
            .build()
            .map_err(connection::CreatePoolError::Build)
    }
}

// ===========================================================================
// WASM SqliteStoreConfig — single connection, OPFS-backed
// ===========================================================================

/// A configuration structure used for opening a store.
///
/// # WASM specifics
///
/// On the `wasm32-unknown-unknown` target, the stores are backed by SQLite
/// databases living in the [Origin Private File System] (OPFS). This comes
/// with constraints that the embedding application must uphold:
///
/// - **Single dedicated Web Worker.** All stores must be created and used from
///   one dedicated Web Worker. OPFS synchronous access handles are unavailable
///   on the main thread, and the connection wrapper panics when accessed from a
///   thread other than the one that created it.
/// - **No concurrent tabs.** OPFS synchronous access handles are exclusive per
///   agent. A second tab or worker opening the same stores will fail with an
///   `OpenStoreError`. Coordinate access at the application level, e.g. with a
///   `SharedWorker` or the [Web Locks API].
/// - **Queries run synchronously.** Unlike the native backend, which executes
///   queries on blocking threads, queries on WASM run inline and block the
///   worker's event loop until they complete.
/// - **The path is a name prefix.** OPFS has no filesystem hierarchy; the
///   `path` passed to [`SqliteStoreConfig::new`] is used as a plain prefix for
///   the database names.
///
/// [Origin Private File System]: https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system
/// [Web Locks API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API
#[cfg(target_family = "wasm")]
#[derive(Clone)]
pub struct SqliteStoreConfig {
    /// Database name prefix (OPFS has no filesystem hierarchy).
    db_name: String,
    /// Secret to open the store, if any.
    secret: Option<Secret>,
    /// The runtime configuration to apply when opening an SQLite connection.
    runtime_config: RuntimeConfig,
}

#[cfg(target_family = "wasm")]
impl fmt::Debug for SqliteStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStoreConfig")
            .field("db_name", &self.db_name)
            .field("runtime_config", &self.runtime_config)
            .finish_non_exhaustive()
    }
}

#[cfg(target_family = "wasm")]
impl SqliteStoreConfig {
    /// Create a new [`SqliteStoreConfig`].
    ///
    /// On WASM, `path` is used as a database name prefix (OPFS has no
    /// filesystem hierarchy).
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            db_name: path.as_ref().to_string_lossy().into_owned(),
            runtime_config: RuntimeConfig::default(),
            secret: None,
        }
    }

    /// Similar to [`SqliteStoreConfig::new`], but with defaults tailored for a
    /// low memory usage environment.
    pub fn with_low_memory_config<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let mut s = Self::new(path);
        s.runtime_config.cache_size = 500_000;
        s.runtime_config.journal_size_limit = 2_000_000;
        s
    }

    /// Override the database name prefix.
    pub fn path<P>(mut self, path: P) -> Self
    where
        P: AsRef<Path>,
    {
        self.db_name = path.as_ref().to_string_lossy().into_owned();
        self
    }

    /// Define the passphrase if the store is encoded.
    pub fn passphrase(mut self, passphrase: Option<&str>) -> Self {
        self.secret =
            passphrase.map(|passphrase| Secret::PassPhrase(Zeroizing::new(passphrase.to_owned())));
        self
    }

    /// Define the key if the store is encoded.
    pub fn key(mut self, key: Option<&[u8; 32]>) -> Self {
        self.secret = key.map(|key| Secret::Key(Box::new(*key)));
        self
    }

    /// Optimize the database. See [`PRAGMA optimize`].
    ///
    /// [`PRAGMA optimize`]: https://www.sqlite.org/pragma.html#pragma_optimize
    pub fn optimize(mut self, optimize: bool) -> Self {
        self.runtime_config.optimize = optimize;
        self
    }

    /// Define the maximum size in **bytes** the SQLite cache can use.
    pub fn cache_size(mut self, cache_size: u32) -> Self {
        self.runtime_config.cache_size = cache_size;
        self
    }

    /// Limit the size of the WAL file, in **bytes**.
    pub fn journal_size_limit(mut self, limit: u32) -> Self {
        self.runtime_config.journal_size_limit = limit;
        self
    }

    /// Returns the runtime configuration.
    pub(crate) fn runtime_config(&self) -> RuntimeConfig {
        self.runtime_config
    }

    /// Build a single WASM connection for a given database.
    pub(crate) async fn build_wasm_connection(
        &self,
        database_name: &str,
    ) -> Result<connection::Connection, connection::OpenConnectionError> {
        let full_name = format!("{}-{}", self.db_name, database_name);
        connection::open_wasm_connection(&full_name).await
    }
}

// ===========================================================================
// Shared types
// ===========================================================================

/// This type represents values to set at runtime when a database is opened.
///
/// This configuration is applied by
/// [`utils::SqliteAsyncConnExt::apply_runtime_config`].
#[derive(Clone, Copy, Debug)]
struct RuntimeConfig {
    /// If `true`, [`utils::SqliteAsyncConnExt::optimize`] will be called.
    optimize: bool,

    /// Regardless of the value, [`utils::SqliteAsyncConnExt::cache_size`] will
    /// always be called with this value.
    cache_size: u32,

    /// Regardless of the value,
    /// [`utils::SqliteAsyncConnExt::journal_size_limit`] will always be called
    /// with this value.
    journal_size_limit: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            // Optimize is always applied.
            optimize: true,
            // A cache of 2Mib.
            cache_size: 2_000_000,
            // A limit of 10Mib.
            journal_size_limit: 10_000_000,
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::{
        ops::Not,
        path::{Path, PathBuf},
    };

    #[cfg(not(target_family = "wasm"))]
    use super::POOL_MINIMUM_SIZE;
    use super::{Secret, SqliteStoreConfig};

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_new() {
        let store_config = SqliteStoreConfig::new(Path::new("foo"));

        assert_eq!(store_config.pool_config.max_size, num_cpus::get_physical() * 4);
        assert!(store_config.runtime_config.optimize);
        assert_eq!(store_config.runtime_config.cache_size, 2_000_000);
        assert_eq!(store_config.runtime_config.journal_size_limit, 10_000_000);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_with_low_memory_config() {
        let store_config = SqliteStoreConfig::with_low_memory_config(Path::new("foo"));

        assert_eq!(store_config.pool_config.max_size, num_cpus::get_physical());
        assert!(store_config.runtime_config.optimize);
        assert_eq!(store_config.runtime_config.cache_size, 500_000);
        assert_eq!(store_config.runtime_config.journal_size_limit, 2_000_000);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_store_config_when_passphrase() {
        let store_config = SqliteStoreConfig::new(Path::new("foo"))
            .passphrase(Some("bar"))
            .pool_max_size(42)
            .optimize(false)
            .cache_size(43)
            .journal_size_limit(44);

        assert_eq!(store_config.path, PathBuf::from("foo"));
        assert_eq!(store_config.secret, Some(Secret::PassPhrase("bar".to_owned().into())));
        assert_eq!(store_config.pool_config.max_size, 42);
        assert!(store_config.runtime_config.optimize.not());
        assert_eq!(store_config.runtime_config.cache_size, 43);
        assert_eq!(store_config.runtime_config.journal_size_limit, 44);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_store_config_when_key() {
        let store_config = SqliteStoreConfig::new(Path::new("foo"))
            .key(Some(&[
                143, 27, 202, 78, 96, 55, 13, 149, 247, 8, 33, 120, 204, 92, 171, 66, 19, 238, 61,
                107, 132, 211, 40, 244, 71, 190, 99, 14, 173, 225, 6, 156,
            ]))
            .pool_max_size(42)
            .optimize(false)
            .cache_size(43)
            .journal_size_limit(44);

        assert_eq!(store_config.path, PathBuf::from("foo"));
        assert_eq!(
            store_config.secret,
            Some(Secret::Key(Box::new([
                143, 27, 202, 78, 96, 55, 13, 149, 247, 8, 33, 120, 204, 92, 171, 66, 19, 238, 61,
                107, 132, 211, 40, 244, 71, 190, 99, 14, 173, 225, 6, 156,
            ])))
        );
        assert_eq!(store_config.pool_config.max_size, 42);
        assert!(store_config.runtime_config.optimize.not());
        assert_eq!(store_config.runtime_config.cache_size, 43);
        assert_eq!(store_config.runtime_config.journal_size_limit, 44);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_store_config_path() {
        let store_config = SqliteStoreConfig::new(Path::new("foo")).path(Path::new("bar"));
        assert_eq!(store_config.path, PathBuf::from("bar"));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn test_pool_size_has_a_minimum() {
        let store_config = SqliteStoreConfig::new(Path::new("foo")).pool_max_size(1);
        assert_eq!(store_config.pool_config.max_size, POOL_MINIMUM_SIZE);
    }
}
