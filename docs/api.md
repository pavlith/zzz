# API v1 (development)

Authentication: `Authorization: Bearer zzz_...` (random CLI-provisioned token), stored as SHA-256 hash. **Not** master-password authentication and **not** E2EE.

| Method | Path | Requirement |
|---|---|---|
| GET | /healthz | public |
| GET | /api/v1/me | authenticated |
| GET / POST | /api/v1/workspaces | membership / authenticated |
| POST | /api/v1/workspaces/{workspace}/groups | workspace admin |
| POST | /api/v1/groups/{group}/members | workspace admin |
| POST | /api/v1/workspaces/{workspace}/vaults | workspace admin |
| POST | /api/v1/vaults/{vault}/permissions | workspace admin |
| GET / POST | /api/v1/vaults/{vault}/items | explicit vault read/write |
| GET / PUT | /api/v1/vaults/{vault}/items/{item} | explicit vault read/write |

Use `zzz user create --email ...` to bootstrap development identity. Store the returned bearer token securely. Requests are JSON with 1 MiB max body. Item `nonce` and `ciphertext` are base64 JSON fields (Go `[]byte`). Update requires `expected_revision`, conflicting edits return HTTP 409.

**Security limitations:** No self-service signup, device auth, PAKE, E2EE key distribution, audit trail, rate limiting, token rotation API, TLS termination, encryption verification, revision history, or revocation workflows. Keep server bound to loopback for development. Do not use real credentials.
