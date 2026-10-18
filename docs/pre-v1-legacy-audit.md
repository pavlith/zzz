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

## Opaque API contract finding (2026-10-18)

The server's `back/api/envelopes.go` and `historical_envelope_rewrap.go` currently accept `crypto_version:1` plus an opaque base64 JSON `ciphertext` byte array (32–65536 bytes), without parsing the candidate-v1 signed JSON envelope. `back/models/device_envelope.go` persists this as a BLOB. Candidate-v1 has a separate `protocol` and `suite` with mandatory signature, commitment, recipient fingerprint and manifest. These **are not equivalent**. The server must not label opaque v1 blobs as verified candidate-v1.

The historical endpoints additionally enforce device trust, epoch bounds, source signatures and existing-epoch possession; these checks are not interchangeable with candidate-v1 cryptographic verification. Keep the endpoints until a single replacement storage and API contract is implemented with tests. Before first release, choose whether to replace `crypto_version` with an explicit protocol identifier and validate the exact candidate envelope shape, while leaving independent signer trust to clients. Do not remove ACL or epoch checks.

Old client crypto documentation is now marked retired; it no longer advertises deleted functions.

## CI regression after strict API cutover

Go CI fails on older rotation tests because they submit legacy `crypto_version/ciphertext` requests and use non-UUID fixture identifiers. Do not weaken `candidatev1.Parse` or re-enable legacy payloads just to make those tests pass. Update the shared rotation test fixtures to real canonical UUIDs, construct valid signed candidate-v1 envelopes and hash their canonical stored JSON for acknowledgement tests. Historical rewrap tests need the same migration. This remains an **open CI blocker**; do not claim backend readiness.

The new-envelope write path additionally checks that `recipient_key_sha256` equals SHA-256 of the trusted device's registered X25519 public key. Signature verification and manifest authorization still require independent client-side trust checks.
