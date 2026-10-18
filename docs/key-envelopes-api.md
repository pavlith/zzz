# Vault key envelopes API

Development-only endpoints:

- GET /api/v1/vaults/:vault/key-envelopes — read own active-device envelopes where user has Vault read permission.
- POST /api/v1/vaults/:vault/key-envelopes — write an opaque envelope for a device whose user has Vault read permission. Caller needs Vault manage permission. Body: device_id, key_epoch, crypto_version (1), ciphertext (base64).

Key epoch must equal the Vault's current key epoch. Duplicate envelopes for a device/vault/epoch are rejected by a unique database index.

**Not production E2EE:** The device registry does not establish public-key authenticity or private-key possession. Bearer tokens are not device-bound. The server cannot validate ciphertext cryptographically, and device revocation does not invalidate existing sessions or already-copied keys. No recovery or rotation flow is implemented. Never upload real secrets.
