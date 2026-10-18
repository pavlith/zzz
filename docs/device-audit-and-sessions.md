> **Status (2026-10-18): development/prototype subsystem note.** Not a production-ready guarantee. Track outstanding work and acceptance criteria in [the canonical backend + web roadmap](roadmap-backend-web.md). In particular, web is not implemented, production authentication and E2EE integration remain open, and Vault key rotation activation is disabled.

# Device audit and session management — development

Authenticated routes:

- `GET /api/v1/devices/audit`: latest 100 account-scoped device lifecycle events, ordered newest-first.
- `GET /api/v1/sessions`: latest 100 sessions for the authenticated user. Returns session ID, optional device ID and timestamps, **never raw bearer tokens or token hashes**.
- `DELETE /api/v1/sessions/:session`: revoke one of the caller's sessions; other users' sessions are inaccessible.

Device registration, device revocation, signed trusted approval and operator-run first-device bootstrap now record an audit event in the same transaction as their state change. Session revocation immediately invalidates the selected bearer token. Device revocation additionally invalidates all its device-bound tokens.

**Known gaps:** legacy development bearer tokens are still not device-bound, and session inventory/revocation are accessible using those tokens. Audit events are mutable database records, not tamper-evident and not an independent security log. Session issuance over HTTP, signed session binding, account recovery, rate limits and production authentication remain unfinished. Do not store real passwords.
