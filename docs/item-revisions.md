# Encrypted Item Revision History — development

Each new/updated encrypted Item now creates an immutable `ItemRevision` row in the same database transaction as the current Item and its `SyncEvent`. Deletions append a revision with `deleted=true` and emit a tombstone event. The server stores ciphertext, nonce, crypto version and the Vault's current key epoch at the time of each upsert.

`GET /api/v1/vaults/:vault/items/:item/revisions?after=0` requires authenticated Vault read access, returns up to 100 revisions ordered by revision number, `next_revision` and `has_more`. This lets offline clients fetch historical encrypted versions for merge/conflict handling. It does **not** implement automatic merging.

This initial GORM migration does not backfill past revisions: existing Items from earlier deployments may have no history. The model does not itself validate ciphertext authenticity; all key distribution, authenticated encryption, rollback detection and recovery remain unfinished. Snapshots are still offset-based and are not pinned across pages. Do not store real passwords.
