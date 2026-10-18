# Pre-v1 legacy retirement audit

Status: **in progress** (crypto legacy removed; SQLite baseline consolidated). The project has not shipped v1. This document tracks deliberate removals; it is not a production migration plan.

## Removed in dev

- `pkgs/e2ee/envelope.go` and its tests: unauthenticated legacy X25519/HKDF/AES-GCM envelope, hex recipient fingerprint, noncanonical JSON/byte fields.
- `pkgs/e2ee/verified_envelope.go` and its tests: separate legacy signed wrapper and commitment, incompatible with candidate-v1 canonical signed envelope.
- Neither removed implementation was production-approved. The experimental replacement is `pkgs/e2ee/candidatev1` with `web/src/lib/crypto/candidate-v1.ts`.

**Compatibility policy:** no automatic legacy decryption or silent conversion. All development fixtures must be regenerated. No real passwords should be present. Never migrate secrets using the experimental protocol.

## Audit inventory: not yet removed

| Area | Findings | Decision / blocker |
| --- | --- | --- |
| SQLite schema | `back/database/baseline_sql.go` freezes original DDL; `migrations.go` applies versions 1 and 2. Tests cover legacy upgrades and backup/parity. | Consolidated to one version-1 baseline, including the prepared-rotation uniqueness index. Old two-version development ledgers are rejected, not silently converted. Legacy upgrade/parity tests removed; backup/restore and integrity tests retained. CI verification pending. |
| API envelopes | `back/api/envelopes.go`, `historical_envelopes.go`, `historical_envelope_rewrap.go` and their tests handle persisted opaque envelopes and rotation history. | Audit wire format, storage constraints, clients and rotation guards before replacing endpoints. Do not equate server opaque blobs with the removed Go client crypto library. |
| Rotation | Numerous preflight, manifest, commitment, acknowledgement and log handlers. | Keep activation blocked (409); no removal without identifying dependencies and preserving security invariants. |
| Docs | `docs/e2ee-client-envelope-v1.md`, `docs/e2ee-verified-envelope.md`, `docs/crypto-protocol.md`, `docs/key-envelopes-api.md` may describe older contracts. | Mark superseded where appropriate and reconcile canonical API contract before deletion. |
| Browser | Candidate-v1 TS code currently has no full application, trust bootstrap or independently reviewed parser. | Keep experimental; test cross-language interoperability and negative cases. |

## Acceptance before calling legacy removal complete

1. Search imports and API usages; CI for Go and WebCrypto green.
2. Freeze one canonical pre-v1 wire contract and reject old wire versions at boundaries.
3. Rebuild clean SQLite schema from authoritative models; test fresh DB and explicitly reject old development DB files or provide a one-time destructive reset command.
4. Remove superseded endpoints, docs and fixtures only after updating tests and roadmap.
5. Security review signer identity, recipient key authentication, manifest trust and rotation activation; do not enable production secrets.

Only `dev` is modified; `main` remains release-gated.

## Local development database reset (destructive)

After backing up any data needed for debugging, stop the server and remove the **development-only** SQLite DB and its `-wal` and `-shm` companions, then restart. The server will initialize the single pre-v1 baseline. Do not run this against a database containing real credentials; none should be used with the prototype. The application must not automatically delete a database on version mismatch.
