# Item write epoch contract

All client-facing encrypted Item mutation APIs now require `key_epoch`:

- `POST /api/v1/vaults/:vault/items`
- `PUT /api/v1/vaults/:vault/items/:item`
- `POST /api/v1/vaults/:vault/sync/push`

Missing or zero `key_epoch` returns HTTP 400 `key_epoch_required`; a value different from the Vault's current key epoch returns HTTP 409 `key_epoch_mismatch`. Checks execute in the same SQLite transaction as the encrypted Item write. Existing direct Item clients must include the field.

**Key rotation is not implemented yet.** Do not simply increment the epoch: first establish authenticated device trust and key distribution, prepare encrypted envelopes for all authorized active devices, and design a rollback-safe rotation protocol. The server does not validate ciphertext security. Legacy user Bearer tokens are not production authentication. Do not store real passwords.
