# Signed trusted-device sessions (development v1)

The following two endpoints do not require an existing account Bearer token:

1. `POST /api/v1/auth/device/challenge` with JSON `{"device_id":"..."}`. Only active devices with both `verified_at` and `trusted_at` can obtain a challenge. Response: `challenge_id`, `nonce` (base64, 32 bytes).
2. The device signs exactly `UTF8("zzz-device-session-v1:" + user_id + ":" + device_id + ":" + challenge_id + ":") || nonce_bytes` with its Ed25519 private key.
3. `POST /api/v1/auth/device/session` with `device_id`, `challenge_id` and base64 `signature`. On success the server atomically consumes the challenge and issues a random bearer token bound to that device, expiring in 3600 seconds.

Challenges expire after five minutes, cannot be reused, and are bound to the specific trusted device. Revoking the device makes its sessions invalid immediately, even when tokens have not expired. Never include token values in logs.

**Caveats:** challenge issuance is unauthenticated; add rate limiting and abuse defenses before public deployment. This is not complete authenticated account enrollment, secure recovery or production E2EE. The CLI-issued development bearer tokens remain active and unbound. Use HTTPS and do not store real passwords at this stage.
