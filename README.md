# zzz — Go Vault Backend

Initial **non-production** foundation for a multi-workspace encrypted password manager.

## Stack
Go, Cobra, Viper (YAML + ZZZ_* env overrides), GORM and SQLite.

## Layout
- `cmd/zzz` — entrypoint
- `back/config` — configuration
- `back/database` — SQLite and initial GORM schema
- `back/models` — User → Workspace → Group/Permission → Vault → encrypted Item
- `back/acl` — workspace-scoped permission checks
- `back/service` — transactional domain operations
- `back/cli` — Cobra commands
- `pkgs` — reserved for future shared client libraries (currently no code)

## Run
```bash
go mod tidy
cp config.example.yaml config.yaml
go run ./cmd/zzz migrate
go run ./cmd/zzz user create --email dev@example.test\ngo run ./cmd/zzz serve
curl http://127.0.0.1:8080/healthz
go test ./...
```

Config variables: `ZZZ_SERVER_ADDRESS`, `ZZZ_DATABASE_DSN`, or `--config path`.

## Security / limitations
- No user authentication, crypto protocol, or public CRUD API yet. Authenticated development API is available (see docs/api.md); do not expose it publicly.
- Items store opaque ciphertext and nonces; **this server does not encrypt them**.
- Group/Workspace management is available only as internal Go domain methods.
- Database AutoMigrate is for bootstrap; replace with versioned migrations before production.
- Server-visible Vault names are metadata, not E2EE-protected.
- Vault key envelopes are schema only. Key distribution, revocation, replay protection, and recovery remain to be designed.
- A stored ACL grant does not itself provide decryption ability: the client still needs a valid key envelope.
