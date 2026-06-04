Add support for the `wasm32-unknown-unknown` target. On WASM the stores use a
single `rusqlite` connection backed by the OPFS `sahpool` VFS instead of a
`deadpool` connection pool. The stores must be created and used from a single
dedicated Web Worker, and opening the same stores from several tabs or
workers concurrently is not supported; see the `SqliteStoreConfig`
documentation for details.
