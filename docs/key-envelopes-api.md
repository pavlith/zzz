# Vault key envelopes API (pre-v1)

**Status:** experimental; not approved for real passwords.

## Endpoints

- `GET /api/v1/vaults/:vault/key-envelopes`: return envelopes readable by the authenticated user subject to vault ACL.
- `POST /api/v1/vaults/:vault/key-envelopes`: submit one candidate-v1 signed envelope for a trusted device. Requires vault manage permission.
- `POST /api/v1/vaults/:vault/key-envelopes/history/rewrap`: submit a historical candidate-v1 envelope with an independently verified signed rewrap operation. Requires vault manage permission and an authorized source device with possession of the historical epoch.

## New-envelope request

```json
{
  "device_id": "22345678-1234-1234-1234-123456789abc",
  "key_epoch": 2,
  "envelope": {
    "protocol": "zzz-e2ee-candidate-v1"
  }
}
```

The `envelope` object above is **illustrative and incomplete**: the real payload must contain **all** required candidate-v1 fields. Construct it using `pkgs/e2ee/candidatev1` or `web/src/lib/crypto/candidate-v1.ts`, and consult [the complete wire specification](e2ee-wire-candidate-v1.md).

The server strictly parses the envelope, checks its vault/device/epoch binding, and compares the recipient public-key fingerprint against the registered trusted device key. Duplicate and unknown JSON members are rejected by the candidate parser. The canonical JSON is stored as bytes in the pre-v1 `device_key_envelopes.ciphertext` column; this legacy **column name does not imply raw ciphertext**. The `crypto_version` column is a fixed internal discriminator, not a client-supplied API field.

The historical rewrap endpoint accepts `source_device_id`, `device_id`, `key_epoch`, `envelope`, and `signature` (base64 Ed25519 signature of the historical rewrap message). The server validates source-device trust, ACL, historical epoch possession, operation signature and recipient fingerprint.

**Critical security boundary:** structural validation and matching a registered key do not prove signer identity or the authenticity of that registry key. Manifest authentication, trusted bootstrap, rollback protection, revocation and safe rotation activation remain unresolved. Do not upload real secrets.
