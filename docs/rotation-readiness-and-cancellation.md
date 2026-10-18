# Rotation readiness and cancellation (development)

`GET /api/v1/vaults/:vault/rotation` requires Vault Manage and reports the pinned manifest size, number of matching staged envelopes, `missing_device_ids`, `invalid_device_ids`, and `envelopes_complete`. Validation rechecks each manifest recipient's current trusted/nonrevoked status and Vault read ACL, plus the current Vault key epoch. An empty manifest is never complete.

`POST /api/v1/vaults/:vault/rotation/cancel` requires Vault Manage. Within a database transaction it verifies the active epoch has not changed, marks the prepared rotation cancelled and deletes only DeviceKeyEnvelope rows for the proposed future epoch. It does not touch the active key epoch or current-epoch envelopes. A subsequent cancellation returns not found.

**Important:** `envelopes_complete` indicates server-side metadata coverage, not cryptographic correctness or authorization to activate. `can_activate` remains false and there is no activation API. Concurrent changes to device trust, group membership or permissions, unsigned envelopes, stale manifest devices, and race-free rotation state transitions need a separately designed, tested activation protocol. No real passwords should be stored in this prototype.
