# Roadmap: production backend + web password manager

**Status:** canonical delivery plan, 2026-10-18. **Current release: development prototype only; NEVER store real passwords.**
**Scope:** Go/Echo/SQLite API + Svelte 5/TypeScript web client, responsive/PWA after browser security review; Android is explicitly out of this release. **Branch policy:** all development directly in `dev`; `main` untouched until reviewed release.

## Legend and acceptance

- **DONE (prototype)** means code exists and prior CI passed; **not** production approved.
- **IN PROGRESS** means partially implemented or not security-reviewed.
- **TODO** means missing; passing server unit tests does not imply E2EE safety.
- Each task is complete only with implementation, automated tests, docs, threat review, API contract and passing CI.
- Critical release gates: authentication + recovery, reviewed cryptography and key identity, rotation, durable sync, web integration, accessibility, security tests, deployment/backups, independent security review.

## Actual baseline

**Backend prototype:** Go/Echo, GORM/SQLite; CLI/bootstrap, development bearer sessions, trust/device proofs and approvals, workspaces/groups/vault ACL, opaque items and immutable revisions, sync push/pull and consistent snapshots, per-device current/historical Key Envelopes, signed staged rotation with preflight/quorum/history coverage, commitment comparisons and initial hash-chain export. Tests exist; see CI. **Rotation activation deliberately returns HTTP 409**; `can_activate=false`. **Web client: NOT STARTED**. **E2EE library:** experimental Go `pkgs/e2ee` X25519/HKDF/AES-GCM, signed envelope and commitment; not wired to server or a browser.

## Dependency-ordered milestones and tasks

### M0 — architecture and contracts (BLOCKER; TODO)
- [x] M0-01 Draft and record scoped threat model (independent review/tests pending) — Freeze product scope, threat model (server compromise, malicious device/admin, offline clients, lost devices, browser/XSS, rollback, metadata leakage), acceptable risks and threat-to-test matrix.
- [ ] M0-02 Freeze API OpenAPI 3.1, error taxonomy, pagination, sync cursor semantics, optimistic concurrency, device/session binding and feature negotiation.
- [ ] M0-03 Freeze E2EE protocol, canonical serialization, domain separation, recipient identity verification/key transparency, manifest and key commitment wire format; review cross-language behavior.
- [ ] M0-04 Write ADRs for login/recovery, key hierarchy, trusted device bootstrap, key revocation and removal, archived keys, offline sync, conflict resolution, security constraints of browser/PWA.
- [ ] M0-05 Define production readiness gates, minimum browser support, UX flows, RBAC matrix and data retention.

### M1 — backend foundations (IN PROGRESS)
- [x] M1-01 Go service, healthcheck, basic CLI and SQLite schema — prototype.
- [x] M1-02 Vault/workspace/group/ACL/item/revision/sync core — prototype.
- [x] M1-03 Development CI Go test/race — available, but must verify latest runs.
- [ ] M1-04 Replace AutoMigrate with numbered forward/rollback migrations, schema constraints/FK integrity and migration upgrade tests. **Partial:** numbered v1 compatibility baseline/v2 prepared-rotation unique index, idempotence, legacy schema upgrade/data preservation, duplicate-rotation failure/retry and SQLite integrity/FK checks. **Still open:** full SQL baseline, tested backup restore, downgrade policy, concurrency/foreign-key schema audit. See [migration runbook](sqlite-migrations-and-recovery.md).
- [ ] M1-05 Extract routes into domain services/DTOs, stable validation and structured typed errors; OpenAPI generation, contract tests.
- [ ] M1-06 Add database isolation/concurrency tests, transaction retry strategy, unique prepared-rotation constraint, immutable/audited history guarantees.
- [ ] M1-07 Request IDs, redacted structured logs, tracing/metrics, health/readiness, graceful shutdown, configuration/secrets and TLS reverse proxy guidance.

### M2 — production identity, sessions and devices (BLOCKER; TODO/IN PROGRESS)
- [x] M2-01 Device key verification, approval and signed device session prototype.
- [ ] M2-02 Production registration/login: ADR proposal written; concrete vetted implementation and interoperability still unverified. Choose standard audited OPAQUE/PAKE or a vetted alternative; account enumeration protection and KDF parameters; no homemade PAKE.
- [ ] M2-03 Device-bound short-lived sessions, secure refresh rotation, idle/absolute expiry, theft/replay controls, logout-all; web cookie strategy (HttpOnly/Secure/SameSite), CSRF and CORS.
- [ ] M2-04 First-device bootstrap, independent identity verification, new-device pairing UX and recovery with lost-all-devices policy.
- [ ] M2-05 Abuse/rate limits across auth and device flows, account/device notifications and audit UI; security penetration tests.
- [ ] M2-06 Harden multi-tenant ACL on all endpoints, IDOR/property and adversarial permission tests.

### M3 — E2EE protocol and interoperable crypto (BLOCKER; IN PROGRESS)
- [x] M3-01 Experimental Go X25519/AES-GCM envelope and signed commitments.
- [ ] M3-02 Versioned, reviewed canonical binary/JSON format with cross-language known-answer vectors and negative vectors (Go + WebCrypto/TypeScript). **In progress:** isolated Go candidate-v1 parser and negative fixtures; authenticated cryptography, cross-language vectors and review remain pending.
- [ ] M3-03 Authenticated device public-key directory and anti-substitution/key-transparency workflow with independent witnesses/gossip.
- [ ] M3-04 Browser crypto adapter: secure key generation, AEAD data encryption/decryption, envelope wrapping/unwrapping, domain separation, key derivation and zeroization limitations documented. **In progress:** experimental browser-side candidate-v1 envelope verification/decryption in `web/src/lib/crypto/candidate-v1.ts`; wrapping, key lifecycle, compatibility fixtures, tests and security review are missing.
- [ ] M3-05 Authenticated shared Vault Key commitment validation across recipients; sender equivocation detection, signed/witnessed checkpoints.
- [ ] M3-06 Client-side historical key rewrap, local proof of possession and decryptability checks; recovery/rotation policies with cryptographic review.
- [ ] M3-07 Security audit, fuzz/property tests and side-channel/error handling review; document browser device-key storage risks.

### M4 — sync and key lifecycle backend (BLOCKER; IN PROGRESS)
- [x] M4-01 Immutable revisions, optimistic write guards, atomic sync push/idempotency and consistent snapshot — prototype.
- [x] M4-02 Rotation preparation/cancellation, recipient manifest, envelope staging, approvals, preflight, history coverage and signed claims — prototype.
- [x] M4-03 Initial commitment hash chain — NOT a complete transparency log.
- [ ] M4-04 Stable sync contract with tombstone retention, replay, pagination/backpressure, ACL changes, access revocation and stale cursor recovery.
- [ ] M4-05 Real transparency service: append-only constraints, signed monotonic checkpoints, inclusion/consistency proofs or suitable reviewed construction, independent peer verification and fork detection.
- [ ] M4-06 Atomic rotation activation: serialized transaction revalidates manifest/ACL/trust/quorum/epochs/envelopes/commitments/history and conditional epoch/status updates, audit and idempotency.
- [ ] M4-07 Retired/offline devices and history preservation; rewrap coverage and safe rekey scheduling, rollback/disaster recovery and consistency test matrix.
- [ ] M4-08 Encryption/key-epoch consistency integration tests across API, snapshots, sync, revisions and concurrent writers; API must fail closed.

### M5 — Svelte 5 web application (NOT STARTED; TODO)
- [ ] M5-01 Create `web/` with SvelteKit, Svelte 5 runes, TypeScript strict, shadcn-svelte, pnpm, lint/typecheck/unit/e2e and environment configuration.
- [ ] M5-02 Responsive design system, routing, layouts, error/loading/empty states, i18n (ru/en), accessible keyboard navigation and forms.
- [ ] M5-03 Auth UI: setup/login/unlock/logout, trusted device enrollment, session management, recovery flows and user-safe error messages.
- [ ] M5-04 Client-only crypto/keyring: unlock state, browser storage threat model, tab coordination, lock timeout, clipboard clearing, memory hygiene best effort. Never send secret plaintext to API.
- [ ] M5-05 Vault and workspace navigation, group/member/ACL management, invitation review, device trust/revocation.
- [ ] M5-06 Password item CRUD (logins, notes, cards, identities by approved scope), secrets generator, copy/reveal, client-side search, folders/tags/favorites and revision history.
- [ ] M5-07 Offline-first sync queue, idempotent mutations, conflict resolution, tombstones, progress/errors and resync after permission or epoch changes.
- [ ] M5-08 Rotation & history UX: prepare, recipient inspection, signatures, client-side rewrap, commitment comparison, warnings and recovery.
- [ ] M5-09 Accessibility WCAG 2.2 AA targets, responsive mobile browser, localization, cross-browser checks, secure CSP/Trusted Types assessment and dependency auditing.
- [ ] M5-10 Playwright end-to-end tests using real backend + ephemeral database (account onboarding, two devices, offline/edit conflict, revocation, rotation, history recovery).

### M6 — hardening, delivery and launch (NOT STARTED; TODO)
- [ ] M6-01 Docker Compose production reference with TLS, strict origins/CORS/CSRF, headers/CSP, secure secrets and least-privilege runtime.
- [ ] M6-02 Encrypted DB backups, restore drills, migration/upgrade/rollback procedures, disaster recovery RPO/RTO and logs without secrets.
- [ ] M6-03 CI: Go race/fuzz, TS typecheck/lint/unit, browser E2E, OpenAPI contract, secret scanning, SCA/SBOM, build provenance.
- [ ] M6-04 Load/soak tests, sync concurrency and abuse tests, observability, alerts and actionable operations runbook.
- [ ] M6-05 Independent security review of backend/browser crypto and auth; fix findings, re-test and publish known risks.
- [ ] M6-06 Release candidate checklist, manual acceptance, versioning, changelog and staged deployment. Only then consider `dev -> main`.

## Immediate execution order (next ten tickets)

1. **M0-01** threat model and adversarial matrix.
2. **M0-03** interoperable crypto protocol with signed canonical encoding.
3. **M2-02** production auth ADR and vetted library decision.
4. **M1-04** migration framework and invariants.
5. **M4-05** transparency checkpoints and fork detection design.
6. **M5-01** initialize Svelte 5 app + automated checks (UI scaffold only, no real secrets).
7. **M3-02** Go/browser cross-language vectors.
8. **M2-03** browser-safe device-bound session flow.
9. **M5-03** auth/device onboarding UI.
10. **M4-06** activation *after all cryptographic gates*; not earlier.

## Definition of done for backend + web

An authenticated user can safely onboard two independently verified devices; create and share vaults with enforceable ACL; encrypt/decrypt items only on the client; synchronize edits/deletions/history offline and online; safely revoke, recover and rotate keys while preserving authorized historical access; use a responsive accessible Svelte 5 web UI; perform backups/restore and upgrades; pass end-to-end/security tests and an independent audit. No prototype feature counts as complete solely because its endpoint returns 200.

## 2026-10-18 security + migrations checkpoint

- M0-01: initial threat matrix in [threat-model.md](threat-model.md) exists; independent review and adversarial test matrix execution remain open.
- M0-03, M0-04: candidate decisions captured in [ADR authentication](adr-authentication-and-recovery.md) and [ADR E2EE](adr-e2ee-contract.md); they are **not frozen or production approved**.
- M1-04: schema migration ledger and numbered baseline/index steps introduced in `back/database/migrations.go`; remaining production gates above are explicitly open.
- Web: directory contains an experimental crypto candidate under `web/src/lib/crypto`, **not a complete SvelteKit web app**. Avoid treating M5 as fully absent or complete without checking the actual files.
