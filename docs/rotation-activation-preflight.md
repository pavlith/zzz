# Rotation activation preflight — development

`GET /api/v1/vaults/:vault/rotation/preflight` requires Vault Manage and executes the recipient/manifest and signature/quorum checks within one SQLite read transaction, returning a snapshot of the pending rotation's state and specific `blockers`.

It checks the prepared manifest SHA-256 digest, unchanged current epoch, nonempty eligible recipient manifest, current recipient trust and read ACL, newly eligible devices outside the manifest, staged next-epoch envelopes, and current valid signatures against the configured quorum.

Even if all database metadata checks pass, this endpoint **always** returns `can_activate: false`. It adds hard blockers `envelope_decryptability_unverified` and `historical_key_access_unverified`. The server cannot prove that client-wrapped envelopes decrypt to the intended new key, nor that all historical ciphertext will remain accessible. A read-only snapshot is not an atomic activation transaction and does not make subsequent activation race-free. No endpoint changes the active `key_epoch`.
