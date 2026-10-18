> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Device challenge protocol (development v1)

All routes require the existing user Bearer token.

1. `POST /api/v1/devices/:device/challenge` returns `challenge_id` and base64 `nonce` (32 random bytes).
2. The client signs this exact byte sequence using the Ed25519 device private key:
   `UTF8("zzz-device-proof-v1:" + user_id + ":" + device_id + ":" + challenge_id + ":") || nonce_bytes`.
3. `POST /api/v1/devices/:device/verify` accepts `{"challenge_id":"...","signature":"base64..."}`.
4. The server checks account/device ownership, challenge lifetime (5 minutes), signature and one-time consumption before setting `verified_at`.

The device private key must never leave the client. The server stores only public keys and challenge state. This protocol proves possession of a signing key, **not** that the account owner trusts the device. A stolen account token could register an attacker device and complete this challenge. No real passwords should be used until trusted-device enrollment, device-bound sessions, proper recovery and key-distribution verification are implemented.

## Developer checks

Run `go mod tidy && go test ./...`. Tests include unauthenticated challenge rejection, valid Ed25519 signature and replay rejection.
