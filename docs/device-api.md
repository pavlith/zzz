> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Device registry API (development only)

The Echo API supports:

- `GET /api/v1/devices` — list the authenticated user's devices.
- `POST /api/v1/devices` — register a device name and 32-byte X25519/Ed25519 public keys, encoded as base64 JSON strings.
- `DELETE /api/v1/devices/:device` — revoke an owned device.

All routes require an existing developer Bearer token. Users cannot read or revoke another user's devices through these routes.

**Critical:** Device registration does not prove control of private keys or verify public-key authenticity. Device revocation does not revoke bearer tokens and cannot remove secrets already copied by the device. The server does not distribute vault decryption keys yet. No production E2EE or trusted-device enrollment is implemented.

Next: signed enrollment challenges, trusted-device approval, device-bound sessions, key transparency, vault key-envelope distribution, key-epoch rotation, and audited revocation.
