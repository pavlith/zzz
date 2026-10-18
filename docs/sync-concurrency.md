# Sync concurrency and key epoch — development contract

For `POST /api/v1/vaults/:vault/sync/push`, `key_epoch` is mandatory. New mutations compare it against the Vault record **inside the same SQLite transaction** as Item/ItemRevision/SyncEvent/SyncOperation writes; a mismatch yields HTTP 409 `key_epoch_mismatch`. Identical retries of already committed operation IDs are served from the idempotency record before epoch validation, so they return their original result even if the key epoch has changed.

Optimistic item updates require `expected_revision`; competing updates at the same revision can commit at most one successful write. The losing client should refresh the item and its immutable encrypted revision history, then resolve the conflict client-side rather than silently replacing ciphertext.

**Limitations:** The server currently has no authorized key-rotation endpoint or trusted-device enrollment, and older direct Item APIs have no key-epoch input. SQLite busy/locked errors are not yet mapped to a retry response; clients need bounded retries. No authenticated encryption protocol or cryptographic device trust is established. The project must not store real passwords.
