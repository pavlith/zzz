> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Signed device approval — development v1

A device must first register its public keys and complete proof of possession (`verified_at`). An already trusted, nonrevoked device for the **same account** may approve it.

1. `POST /api/v1/devices/:device/approval-challenge` with `{"approver_device_id":"..."}`. The target must be verified, pending trust and not revoked; the approver must be verified, trusted, and active.
2. Receive a one-time challenge ID and 32-byte nonce (base64), expiring after five minutes.
3. The trusted approver signs with its Ed25519 signing key the exact concatenation of UTF-8 `zzz-device-approval-v1:<user_id>:<target_id>:<approver_id>:<challenge_id>:`, followed by the target's raw 32-byte Ed25519 signing public key, its raw 32-byte encryption public key, and the raw nonce.
4. `POST /api/v1/devices/:device/approve` with `{"challenge_id":"...","signature":"<base64 Ed25519 signature>"}`. The server rechecks trust and verifies the signature; challenge consumption and setting `trusted_at` occur together in a transaction.

Changing target public keys or replaying an already-consumed approval will not produce a successful approval. Private signing keys never leave devices.

**Security limits:** no first-device trusted bootstrap is implemented. No ordinary API can create a first trusted device. Existing development-only bearer tokens are unbound to devices; the server authenticates the **approval signature**, not the source HTTP session. Production account authentication, signed enrollment policy, audit trail and recovery still require design, implementation and review. Do not use real passwords.
