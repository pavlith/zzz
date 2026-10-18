# Historical Key Envelopes — read-only development API

`GET /api/v1/vaults/:vault/key-envelopes/history?epoch=N` requires the caller's Vault Read permission. The epoch must be strictly positive and **less than** the current Vault `key_epoch`. The response contains only existing opaque `DeviceKeyEnvelope` records for the caller's own devices that are still verified, trusted and not revoked. Other users' devices, pending or revoked devices, current and future epochs are excluded. The response has `Cache-Control: no-store`.

This endpoint is intentionally read-only. Current `GET /api/v1/vaults/:vault/key-envelopes` continues to list current-epoch envelopes. Historical item revisions already expose their `key_epoch` metadata, allowing clients to identify which past key is needed.

**Not solved yet:** no rotation activation exists, there is no mechanism to rewrap historical keys for devices added later, no preservation/garbage-collection policy for retired device envelopes, and no cryptographic verification that historical ciphertext can actually be decrypted. Revoking a device prevents future envelope retrieval, but cannot erase keys or ciphertext previously downloaded by it. Existing development bearer tokens are not device-bound; therefore account-level authorization is not proof of the requesting physical device's identity. Production must require device-bound authorization and ensure history preservation before rotation may activate. Do not store real passwords.

## Client-side historical rewrap (development)

`POST /api/v1/vaults/:vault/key-envelopes/history/rewrap` accepts `source_device_id`, `device_id` (recipient), `key_epoch`, `crypto_version: 1`, base64 `ciphertext`, and base64 Ed25519 `signature`. The authenticated caller needs Vault Manage, and the signer must be a trusted device belonging to that caller. The target must be trusted and hold current Vault Read rights. The source must already possess an encrypted key envelope for the requested **historical** epoch; this is a metadata check, not proof that the source still has the plaintext key.

The signer signs the UTF-8 message `zzz-historical-key-rewrap-v1:<vault_id>:<epoch>:<source_device_id>:<device_id>:<sha256(ciphertext hex lowercase)>`. Server stores only client-produced opaque ciphertext. Duplicate `(vault,device,epoch)` envelopes are rejected by the unique constraint; active and future epochs are disallowed.

**Security limitations:** server signature verification authenticates the request, not successful client-side re-encryption or decryptability. The endpoint currently uses development account-level Bearer authorization, not a device-bound live session; a stolen token plus signing-key access can publish ciphertext. The target's key must be verified by the source client through an authenticated channel. Historical-key retention and revocation semantics remain unresolved, and rotation activation stays disabled. Never upload plaintext Vault Keys.
