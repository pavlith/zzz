# zzz — encrypted password manager (development)

**Status: pre-production prototype. Do not store real passwords.** Go/Echo/SQLite backend exists; Svelte 5 web application has **not yet been implemented**.

## Development scope
Backend: authentication/device-proofs prototypes, account/workspace/vault ACL, encrypted item/revision storage, sync and snapshots, key-envelope staging/history, signed rotation and preflight, commitments and experimental SHA-256 transparency hash chain. Client crypto: experimental Go `pkgs/e2ee` (X25519, HKDF, AES-GCM, Ed25519). **No production-grade E2EE end-to-end integration or account authentication. Rotation activation explicitly returns HTTP 409 and never changes the active key epoch.**

## Start backend
```bash
go mod tidy
cp config.example.yaml config.yaml
go run ./cmd/zzz migrate
go run ./cmd/zzz user create --email dev@example.test
go run ./cmd/zzz serve
curl http://127.0.0.1:8080/healthz
go test -race ./...
```
Use loopback-only development environment and non-secret test data. Configure via `ZZZ_SERVER_ADDRESS`, `ZZZ_DATABASE_DSN` or `--config`.

## Documentation
- [**Canonical backend + web roadmap**](docs/roadmap-backend-web.md) — full task checklist, priorities and release gates.
- [Documentation index](docs/README.md) — actual status of each spec.
- [API v1 development surface](docs/api.md).
- [Security roadmap](docs/security-roadmap.md).
- [Web implementation specification](docs/web-app-spec.md).
- [E2EE protocol](docs/crypto-protocol.md).
- [Rotation and activation safeguards](docs/e2ee-rotation-activation-contract.md).

The release must pass independent security review, production auth, browser crypto integration, migration/backup/recovery and E2E acceptance tests before real credentials are permitted.
