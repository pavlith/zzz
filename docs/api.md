# Backend API v1 — development contract index

**This is a prototype API, not a stable public contract.** Current auth includes development bearer tokens and device-session flows. Production authentication, device-bound browser sessions, recovery and OpenAPI 3.1 remain **TODO** (M0-02, M2).

All paths except `/healthz` and selected device-auth bootstrap endpoints are under `/api/v1` and require applicable auth. JSON byte slices are base64; sensitive responses use `Cache-Control: no-store`. Most writes cap bodies at 1 MiB. Use `back/api/api.go` as the source of registered routes until OpenAPI is generated.

| Group | Available prototype routes |
| --- | --- |
| Identity | `GET /me`, `GET /sessions`, `DELETE /sessions/:session`, device challenge/session endpoints |
| Devices | `GET/POST /devices`, `GET /devices/audit`, `DELETE /devices/:device`, challenge/verify/approval endpoints |
| Workspaces | `GET/POST /workspaces`, group/member creation, Vault creation, Vault ACL grants |
| Items | `GET/POST /vaults/:vault/items`, `GET/PUT /vaults/:vault/items/:item`, `GET /vaults/:vault/items/:item/revisions` |
| Sync | `GET /vaults/:vault/sync`, `POST /vaults/:vault/sync/push`, `GET /vaults/:vault/snapshot`, `GET /vaults/:vault/snapshot-consistent` |
| Envelopes | `GET/POST /vaults/:vault/key-envelopes`, `GET /vaults/:vault/key-envelopes/history?epoch=N`, `POST /vaults/:vault/key-envelopes/history/rewrap` |
| Rotation | `GET /vaults/:vault/rotation-readiness`, `POST /rotation/prepare`, `GET /rotation`, `POST /rotation/sign`, `POST /rotation/envelope-ack`, `POST /rotation/history-ack`, `POST /rotation/commitment`, `GET /rotation/commitments`, `GET /rotation/transparency`, `GET /rotation/preflight`, `POST /rotation/cancel`, `POST /rotation/activate` (under each Vault) |

**Critical:** `POST /vaults/:vault/rotation/activate` always returns HTTP 409 `rotation_activation_not_implemented` for authorized callers. `can_activate` remains false. Signatures and hash-chain entries are metadata assertions, not proof of end-to-end decryptability.

For full endpoint semantics, see specific files in [docs index](README.md). **TODO:** OpenAPI schema, accurate authz matrix, generated TypeScript client, standardized pagination/errors and interop tests (M0-02, M1-05).
