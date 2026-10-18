# Removed: legacy verified envelope wrapper

**Status: retired before first release (2026-10-18).** The previous `pkgs/e2ee` `VerifiedEnvelope`, `SignWrappedKey` and `OpenVerifiedKey` functions have been deleted. Their signed wrapper and key-commitment bytes differ from candidate-v1 and must not be treated as interchangeable.

**Replacement prototype:** `pkgs/e2ee/candidatev1` and `web/src/lib/crypto/candidate-v1.ts`. Candidate-v1 signs the canonical envelope metadata and ciphertext with Ed25519, derives the recipient KEK with X25519/HKDF, authenticates AES-GCM associated data and checks a SHA-256 vault-key commitment. [Wire contract](e2ee-wire-candidate-v1.md).

A valid envelope does **not** authenticate the signer by itself. Clients must authenticate the expected signer, recipient device key and manifest independently; commitment comparison, rollback protection and rotation activation remain open. Do not use for real passwords.
