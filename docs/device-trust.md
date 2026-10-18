# Device trust state machine (incomplete)

Devices have separate timestamps: `verified_at` means that the client demonstrated possession of its Ed25519 private key, while `trusted_at` means that device enrollment has been approved. `revoked_at` prevents further use.

A verified device is NOT automatically trusted. Until an authenticated approval flow and a secure first-device bootstrap exist, normal API registration and proof routes do not populate `trusted_at`. Device-bound sessions and Vault Device Key Envelopes now require both `verified_at` and `trusted_at`, in addition to not being revoked. Rotation readiness lists only trusted devices.

This change intentionally makes fresh devices ineligible for secure key distribution until approval is implemented. The legacy development-only account tokens still work without any device binding; therefore these controls alone do not constitute production-ready device security. Direct server/database modifications of `trusted_at` are not a safe approval flow. Do not store real passwords.
