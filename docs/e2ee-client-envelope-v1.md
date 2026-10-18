# Removed: legacy client envelope v1

**Status: retired before first release (2026-10-18).** The old `pkgs/e2ee` `Wrap`/`Unwrap` implementation was deleted from `dev`. It was incompatible with the current candidate-v1 signed wire format and must not be restored for compatibility. There are no released clients or supported encrypted production vaults to migrate.

**Current experimental implementation:** `pkgs/e2ee/candidatev1` and `web/src/lib/crypto/candidate-v1.ts`. See [candidate wire specification](e2ee-wire-candidate-v1.md) and [pre-v1 cleanup audit](pre-v1-legacy-audit.md). Go ↔ WebCrypto interoperability tests run in CI, but this does not establish audited E2EE, signer identity, trusted manifests or safe rotation.

**Server warning:** opaque `crypto_version: 1` database/API envelopes are a separate unresolved legacy boundary, **not** an assertion that they contain candidate-v1 data. Do not silently reinterpret them or store real passwords.
