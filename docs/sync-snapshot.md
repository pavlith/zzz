# Vault snapshot bootstrap (prototype)

GET `/api/v1/vaults/:vault/snapshot?offset=0` requires a token and Vault read ACL. Returns up to 100 encrypted Items (including deletion tombstones), current `key_epoch`, `high_watermark` (decimal event ID), `next_offset`, and `has_more`.

For development, request pages until `has_more=false` and then pull events from the earliest returned high-watermark using GET `/api/v1/vaults/:vault/sync?cursor=...`. Apply events idempotently and refetch encrypted Item contents. The response is a **best-effort bootstrap view**, not a pinned historical snapshot: offset pagination can miss or repeat rows during concurrent writes; current-item fetches cannot reconstruct overwritten historical revisions.

Sync Push accepts optional `key_epoch`; a supplied epoch inconsistent with the Vault returns 409 `key_epoch_mismatch`. It is currently optional for backwards compatibility, so this is **not a security enforcement mechanism**. The server does not validate client encryption or establish key authenticity.

Before production: enforce a required key epoch in all mutation APIs, issue a consistent snapshot token or MVCC-style snapshot, version every encrypted revision, add event retention and cursor expiry, and test concurrent snapshot writes, conflict convergence and device revocation. Do not store real passwords in this prototype.
