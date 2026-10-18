# Incremental vault sync — prototype v1

`GET /api/v1/vaults/:vault/sync?cursor=0` requires Bearer authentication and explicit Vault read permissions. Response: `{ "events": [{"id": 1,"vault_id":"...","item_id":"...","revision":1,"operation":"upsert","created_at":"..."}], "next_cursor":"1", "has_more":false }`.

The cursor is a decimal-encoded global append-only event ID. Each request returns at most 100 events for a **single vault**, sorted by ID. Reuse `next_cursor` while `has_more` is true. The server records an `upsert` event in the same SQLite transaction that creates or updates encrypted Item data. The event contains no plaintext secrets. Clients must fetch the encrypted Item and check revisions.

## Not yet implemented

- Tombstones and delete endpoint; encrypted revision snapshots/history; true atomic change-feed payloads.
- Sync push with idempotency keys and conflict-resolution strategy.
- Retention, checkpoint/snapshot bootstrap and cursor-expiration policies.
- Key-epoch binding, signed events, device-bound read sessions and anti-rollback safeguards.

**Development-only**. The change journal by itself is not a safe or complete multi-device synchronization protocol. Do not store real passwords.
