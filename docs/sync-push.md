# Sync Push v1 (development)

`POST /api/v1/vaults/:vault/sync/push` requires a developer Bearer token and Vault write permission. JSON fields: `operation_id` (UUID), `type` (`upsert` or `delete`), `item_id`, `expected_revision`, `nonce` (base64), `ciphertext` (base64), `crypto_version`.

- New item: `type=upsert`, omit `item_id`, set expected_revision=0. Returns assigned item ID and revision 1.
- Update: `type=upsert`, specify item_id and current expected_revision. Mismatch returns 409.
- Delete: `type=delete`, specify item_id and current expected_revision. Server creates a tombstone with incremented revision and emits `delete` event.
- Retrying the same operation_id with identical parameters returns the recorded item ID and revision (`replayed=true`) without repeating the write.
- Reusing the operation_id with different parameters returns 409.

One mutation, its SyncEvent and its SyncOperation are committed in a transaction. Pull with GET `/api/v1/vaults/:vault/sync?cursor=N` and fetch encrypted item data separately.

## Missing production guarantees

No device-bound enforcement of legacy CLI tokens; no encryption format validation, signed mutations, replay-proof event transparency, revision snapshots, deletion retention policy, safe multi-vault global cursor, bulk push, or key-epoch checks. The server must not be used for real passwords yet. If concurrent mutations hit SQLite, client retry/backoff and explicit database error mappings remain necessary.
