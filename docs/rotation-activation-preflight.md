# Rotation activation preflight — development

`GET /api/v1/vaults/:vault/rotation/preflight` requires Vault Manage and executes the recipient/manifest and signature/quorum checks within one SQLite read transaction, returning a snapshot of the pending rotation's state and specific `blockers`.

It checks the prepared manifest SHA-256 digest, unchanged current epoch, nonempty eligible recipient manifest, current recipient trust and read ACL, newly eligible devices outside the manifest, staged next-epoch envelopes, and current valid signatures against the configured quorum.

Even if all database metadata checks pass, this endpoint **always** returns `can_activate: false`. It adds hard blockers `client_decryption_claims_unverifiable` and `historical_key_access_unverified`. The server cannot prove that client-wrapped envelopes decrypt to the intended new key, nor that all historical ciphertext will remain accessible. A read-only snapshot is not an atomic activation transaction and does not make subsequent activation race-free. No endpoint changes the active `key_epoch`.

## Signed envelope acknowledgements

After locally decrypting the staged envelope, each recipient device may submit `POST /api/v1/vaults/:vault/rotation/envelope-ack` with `device_id`, `envelope_sha256` (lowercase SHA-256 hex of the raw ciphertext bytes) and a base64 Ed25519 signature of the exact UTF-8 message `zzz-rotation-envelope-ack-v1:<vault_id>:<rotation_id>:<manifest_sha256>:<device_id>:<envelope_sha256>`. This signed statement is bound to the current staged ciphertext and trust state. Preflight exposes `valid_envelope_acks`, `required_envelope_acks` and blocks when any is absent/invalid. **The server cannot verify whether decryption actually succeeded or all historical keys are available.**

## Historical envelope coverage

Preflight derives `required_historical_epochs` from the distinct positive `key_epoch` values of retained `ItemRevision` records older than the rotation's `from_epoch`. For every pinned recipient, it requires one stored `DeviceKeyEnvelope` for each such epoch. It reports `historical_envelopes_complete` and `missing_historical_envelopes` entries (`device_id`, `key_epoch`), adding `historical_envelopes_missing` if coverage fails. An empty historical epoch set is complete only when the rotation has at least one recipient. This checks only metadata existence, not successful decryption, key correctness, or archives outside retained item revisions. The permanent hard blocker `historical_key_access_unverified` remains in effect, and `can_activate` remains false.

## Signed historical-envelope acknowledgements

A pinned recipient can submit `POST /api/v1/vaults/:vault/rotation/history-ack` with `device_id`, historical `key_epoch`, lowercase hex `envelope_sha256` (SHA-256 of ciphertext bytes), and base64 Ed25519 `signature`. The signed UTF-8 message is `zzz-rotation-history-ack-v1:<vault_id>:<rotation_id>:<manifest_sha256>:<device_id>:<epoch>:<envelope_sha256>`.

The server checks current trust, recipient membership and pinned signing/encryption key hashes, ciphertext hash and Ed25519 signature. Preflight reports `required_historical_acks` and `valid_historical_acks`, blocking on `historical_acknowledgements_missing`. Acknowledgement records are scoped to a particular rotation, epoch, device and ciphertext; changing the ciphertext invalidates the counted claim. These are authenticated client **claims** rather than server-verifiable evidence of successful decryption. The unconditional historical key access blocker and `can_activate: false` remain.
