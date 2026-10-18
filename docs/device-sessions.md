> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Device-bound development sessions

The `auth.Token` table now has an optional `device_id`. `auth.IssueForDevice` issues a random 24-hour-or-less token only when a device belongs to that user, is verified and is not revoked. Every request using that token checks the same device state. Revoking a device marks it revoked, revokes its linked sessions and deletes server-stored key envelopes in one transaction.

Legacy tokens produced by `zzz user create` remain **unbound** and are accepted for developer bootstrap. They are not production authentication. Device-bound token issuance is an internal Go API only; no public sign-in flow or verified trusted-device approval is exposed.

Next steps: replace CLI bootstrap with proper account authentication, register the first device securely, add signed approval from an existing trusted device, bind every normal session to a device, implement token rotation and revocation, and audit all device events.

Tests: `go mod tidy && go test -race ./...`.
