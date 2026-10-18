# Security roadmap

Status: development scaffold only. Never store real passwords or expose the server to public networks.

## Current
- Opaque item ciphertext storage. Server does not have a plaintext password field.
- CLI-provisioned random bearer token, SHA-256 token hashing at rest, 24-hour expiry.
- Workspace membership + explicit vault grant for item access.
- Conditional revision update to detect stale writes.

## Must complete before launch
1. Security threat model and formal cryptographic protocol; audited E2EE client encryption and verified key envelopes.
2. PAKE/device authentication, account recovery, rotation and revocation workflows; short session tokens and refresh handling.
3. Object-level authorization audit; prevent orphaned / cross-tenant references with DB constraints and service invariants.
4. Transactional event log, sync cursors, deletions, history and key epoch enforcement.
5. TLS-only deployment, rate limits, CSRF/CORS threat model, security headers and structured redacted logging.
6. Versioned migrations and restore tests, key/device state machine and independent cryptography review.

Development bearer tokens are **not** a substitute for 1Password-style account login. Vault ACL authorization does not distribute decryption keys.
