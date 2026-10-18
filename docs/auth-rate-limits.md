# Anonymous device-auth rate limits (development)

The two public endpoints `POST /api/v1/auth/device/challenge` and `POST /api/v1/auth/device/session` share an in-process, per-remote-IP budget of ten attempts per rolling fixed 60-second window. When exhausted, they return HTTP 429 `rate_limited` with `Retry-After: 60`. Only the direct TCP peer address is used: request-supplied proxy headers such as X-Forwarded-For are intentionally not trusted.

This is a defensive prototype bound, **not production anti-abuse infrastructure**. The memory limiter resets on restart and is not shared between replicas. Users behind NAT share a budget; traffic arriving through one reverse proxy shares its address. The number of tracked addresses is capped. Production should enforce distributed, identity-aware limits at a trusted reverse proxy, with configured trusted-proxy boundaries, request-body budgets, observability and abuse monitoring. Do not expose this prototype publicly to store real passwords.
