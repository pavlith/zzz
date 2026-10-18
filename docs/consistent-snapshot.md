> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Consistent Vault snapshot (development v2)

GET `/api/v1/vaults/:vault/snapshot-consistent` returns immutable encrypted Item revisions at an event watermark. Response: `revisions`, `watermark` (decimal string), `next_after`, `has_more`, and `key_epoch`.

Request the first page without `watermark`. For subsequent pages send the same `watermark` and `after=<previous next_after>`. The SQL query selects the last SyncEvent for each Item at or below the watermark, then loads its matching immutable ItemRevision, so writes performed after the first page do not alter previously pinned versions. Following the last page, pull events with `cursor=watermark`.

`POST /api/v1/vaults/:vault/sync/push` now requires nonzero `key_epoch` and rejects stale values with HTTP 409.

## Remaining limitations

This is not a signed or expiring snapshot token. Existing encrypted records predating ItemRevision tracking are not backfilled. Historical records must be retained for a pinned snapshot to stay replayable. Consistency of vault key-epoch rotations is not yet ensured by the returned metadata. The original `/snapshot` endpoint remains available as legacy offset pagination and does not have these guarantees. The server still accepts non-device-bound developer tokens, and E2EE is incomplete. No production password data should be stored.
