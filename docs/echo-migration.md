# Echo API migration

Router: `github.com/labstack/echo/v4` v4.16.0.

Endpoints are registered with Echo, `/api/v1` is a route group, and `Recover`, `BodyLimit(1M)`, `Secure` middleware are enabled. Existing HTTP handlers are temporarily adapted to Echo contexts; domain services and ACL remain unchanged. No CORS is enabled by default. The API continues to use development Bearer tokens, not production account authentication.

Next: convert handlers to native `echo.Context`, introduce DTOs and typed errors, apply per-route security policies and add full migration tests.
