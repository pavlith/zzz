# Documentation map — 2026-10-18

**Canonical source for implementation tasks:** [Backend + Web roadmap](roadmap-backend-web.md). Individual files are subsystem design notes and historical milestone records, not independent roadmaps. Most APIs are development-only; web is not yet implemented.

## Start here
- [Roadmap, status and task IDs](roadmap-backend-web.md)
- [Implementation approach](implementation-plan.md)
- [Web app specification](web-app-spec.md)
- [API route summary](api.md)
- [Security release blockers](security-roadmap.md)
- [Cryptography overview](crypto-protocol.md)
- [Git workflow](git-workflow.md)

## Device identity, authentication and permissions
`auth-rate-limits.md`, `device-api.md`, `device-approval.md`, `device-audit-and-sessions.md`, `device-proof.md`, `device-sessions.md`, `device-trust.md`, `signed-device-sessions.md`, `first-device-bootstrap.md`. **Most flows are prototypes; production auth remains a blocker.**

## Data, sync and encrypted items
`consistent-snapshot.md`, `item-revisions.md`, `item-write-epoch.md`, `key-envelopes-api.md`, `sync-concurrency.md`, `sync-protocol.md`, `sync-push.md`, `sync-snapshot.md`. **Backend contracts require production invariants and browser E2E tests.**

## E2EE, device keys and rotation
`e2ee-client-envelope-v1.md`, `e2ee-verified-envelope.md`, `e2ee-commitment-consensus.md`, `e2ee-rotation-activation-contract.md`, `historical-key-envelopes.md`, `vault-key-rotation.md`, `rotation-activation-preflight.md`, `rotation-commitment-peer-comparison.md`, `rotation-readiness-and-cancellation.md`, `rotation-recipient-manifest.md`, `rotation-staging.md`, `rotation-transparency-chain.md`, `signed-rotation-manifest.md`. **Rotation activation intentionally blocked; hash chain is not independently witnessed transparency.**

## Architecture history
`echo-migration.md` documents a completed framework transition; retain as historical context rather than outstanding work.

## Maintenance rules
When shipping any change: update the relevant subsystem spec + OpenAPI when available + relevant roadmap checkbox, link tests and reflect current security limitations. A past milestone spec must never imply deployment readiness merely because a prototype was merged.
