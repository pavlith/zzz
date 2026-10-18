# Threat model and adversarial test matrix (M0-01)

Status: draft for security review, 2026-10-18. This document is a design baseline, not security approval. Never store real passwords in this prototype.

## Scope and trust boundaries

Assets: vault plaintext and metadata, device private keys, vault keys and historical epochs, identity assertions, authentication sessions, ACL, encrypted revisions, sync cursors, rotation approvals, backups and audit evidence.

Boundaries:
1. Browser and its JavaScript supply chain vs user device and operating system.
2. Client vs untrusted network and API server.
3. API authorization vs multi-tenant SQLite storage.
4. Device key directory vs independent device verification.
5. Active key epoch vs archived keys and rotation staging.
6. Server-maintained transparency hash chain vs independently verified checkpoints.
7. Encrypted backup vs recovery credentials and restore operator.

Assume an attacker may control the network, a normal account, a revoked device, or the server database; consider a compromised application server and malicious workspace administrator. A compromised browser origin or OS may read plaintext while unlocked: this cannot be prevented by browser E2EE alone.

## Threats, required controls and acceptance tests

| ID | Threat | Required control | Adversarial acceptance |
| --- | --- | --- | --- |
| T01 | Server reads secret contents | Client-side AEAD, authenticated key envelopes, no plaintext API payloads | Inspect API traces and DB for secret canaries; no plaintext found |
| T02 | Server substitutes device public key | Out-of-band identity verification and witnessed directory consistency | Malicious substituted key rejected by independently verified clients |
| T03 | Server forks or rolls back key history | Monotonic signed checkpoints, independent gossip/witnesses and fork detection | Two divergent histories produce explicit security failure |
| T04 | Stolen bearer or refresh token | Device-bound sessions, refresh rotation, short expiry and replay detection | Replay/old refresh invalid; session revocation enforced |
| T05 | Cross-tenant IDOR or ACL escalation | Deny-by-default authorization at every read/write/sync boundary | Property tests for foreign IDs, revoked membership and stale ACL |
| T06 | Sync replay, reorder, duplicate, cursor truncation | Atomic revision ordering, idempotency, stable cursors, retention contract | Offline clients recover without silent data loss |
| T07 | Rotation activated with missing historical keys | Serialized preflight and cryptographic proof of coverage | Concurrent revoke/rotate and incomplete history fail closed |
| T08 | Malicious member or admin changes recipient set | Signed manifest, verified identity, independent comparison | Unapproved recipient addition causes rejection |
| T09 | XSS or compromised JS dependency exfiltrates unlocked keys | CSP, trusted rendering, dependency pinning, minimized exposure, audits | XSS tests; explicitly document residual origin-compromise risk |
| T10 | Offline browser cache leaks plaintext | Encrypted IndexedDB only, no plaintext service worker or SSR state | Browser storage and cache inspection after lock/reload |
| T11 | Account enumeration and brute force | Audited authentication protocol, uniform errors, abuse limits | Timing/error enumeration and throttling tests |
| T12 | Backup leak or destructive restore | Encrypted backups, scoped recovery, restore verification, rollback policy | Restore drill with key epochs, ACL and sync invariants |
| T13 | Metadata leakage | Minimize metadata, redacted logs, defined retention | Review API/log/schema metadata inventory |
| T14 | Compromised or lost device | Revocation, epoch rekey, recovery policy and explicit residual exposure | Revoked device cannot access new epochs; past copied data cannot be recalled |
| T15 | Malicious or compromised deployment pipeline | Reproducible/pinned builds, secret scanning, signed provenance | Tampered dependency/build fails release gates |

## Severity and release policy

Critical blockers: T01–T09, T11, T14; T10, T12, T13 and T15 must also pass their release criteria. A server-only green test is insufficient: independent two-device browser integration, negative vectors and an external security review are mandatory. Do not enable rotation activation merely because a server-side preflight returns success.

## Residual risks and non-goals

- Browser XSS, malicious extensions and compromised operating systems can expose unlocked plaintext.
- E2EE does not hide all metadata, traffic timing or membership relationships.
- Revocation cannot erase ciphertext or plaintext previously copied by an authorized device.
- A self-reported server hash chain does not provide independent transparency.
- Account recovery must not promise recovery of lost cryptographic keys without an explicitly designed recovery mechanism.
- Android, native secure-enclave guarantees and production PWA offline mode are outside the current release.

## Implementation and review workflow

Map each threat to an executable test in M1–M6. Review every API change for cross-tenant access, auth/session binding, rollback, replay and key-epoch invariants. Track unresolved risks in the security roadmap. Before production, require a separately recorded reviewer, date, evidence links and accepted residual risks. This document intentionally does not claim that those reviews have occurred.
