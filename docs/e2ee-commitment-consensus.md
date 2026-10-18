# Vault Key Commitment comparison (experimental)

`POST /api/v1/vaults/:vault/rotation/commitment` receives `device_id`, `manifest_sha256`, `key_commitment`, and a base64 Ed25519 `signature`. Clients should independently decrypt and verify their key, then calculate the exact key commitment defined in `pkgs/e2ee/verified_envelope.go`. They sign UTF-8 `zzz-rotation-device-commitment-v1:<vault_id>:<rotation_id>:<manifest_sha256>:<device_id>:<key_commitment>`.

The server requires the device to be an eligible pinned recipient with unchanged signing/encryption key fingerprints, verified/trusted/unrevoked status, and current Vault Read access. It verifies Ed25519 and stores at most one assertion per device/rotation.

Rotation Preflight computes `valid_key_commitments`, `required_key_commitments`, `key_commitment_conflict` and `key_commitment_consensus`. A disagreement between valid device claims triggers `key_commitment_conflict`; missing assertions trigger `key_commitments_incomplete`.

**Threat boundaries:** This detects differing *signed claims*, not true key possession or an honest majority. Devices can lie or collude; the server can omit assertions from a client's view, and the current service does not offer a key transparency log. Every client must obtain authenticated peer identities and exchange commitments independently, with protections against forked views. The current account Bearer tokens are not device-bound and no activation is enabled. The key commitment is safe only for random high-entropy 256-bit keys. Do not use real passwords.
