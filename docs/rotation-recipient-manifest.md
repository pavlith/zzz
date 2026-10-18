# Rotation recipient manifest (development)

Preparing a Vault key rotation now captures a database-backed list of verified, trusted, active devices that have Vault read access at preparation time. The list pins SHA-256 fingerprints of recipients' signing and encryption public keys in `RotationRecipient` records and is not automatically expanded when new devices join. Staging next-epoch envelopes requires that the device was included in the prepared manifest. Rotation status includes `required_recipients` and `staged_envelopes`.

This makes preparation reproducible but **does not make activation safe**. Revoked devices, changed ACL or group membership, a changed device key, or an altered recipient set require revalidation and likely cancellation/restart of the rotation. The manifest includes per-device public key fingerprints but still lacks signatures and an audited whole-manifest digest. Staged envelopes are opaque and their actual ability to decrypt a new vault key cannot be verified by the server. Concurrent prepare requests require further hardening through database constraints.

There is deliberately no activation endpoint; `can_activate` remains false. Do not store real passwords.

## Canonical manifest digest

On preparation the server computes `manifest_sha256` using domain-separated, length-prefixed fields with recipients ordered by device ID. It commits that digest along with the recipient list in the same transaction. Rotation validation recalculates it and reports `manifest_valid`; any mismatch blocks `envelopes_complete`.

**This is an integrity checksum, not a cryptographic signature or tamper-evident audit.** An attacker with database write privileges can replace the manifest and its digest. Authenticating the digest with a trusted device signature, enforcing concurrency guarantees and preserving previous key material remain prerequisites for activation.
