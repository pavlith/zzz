# ADR-001: Production authentication and account recovery

**Decision state: PROPOSED — architecture choice pending validation, not implemented.**

Reject continued CLI-issued account bearer tokens as production login. Evaluate vetted **OPAQUE** as first choice for password-authenticated login, contingent on maintained interoperable, independently reviewed Go and browser implementations; never ship homemade PAKE. If not viable, prefer well-established OIDC identity provider for authentication *separate from* end-to-end encrypted Vault unlocking, and document privacy/dependency tradeoffs.

Account authentication and local vault unlocking are different security boundaries. Server gets no Vault/master key. Password change, account recovery and stolen-credential protection must not silently expose old E2EE keys. Use short-lived device-bound sessions, refresh rotation and replay protection; browser should use Secure HttpOnly SameSite cookies with CSRF origin/token checks, not account tokens in localStorage. Verify device keys by independent pairing. Lost-all-devices recovery requires explicit tested user policy; access without recovery material may be irrecoverable.

**Completion gate:** decision of audited concrete auth dependency, implementation, threat tests for enumeration/replay/CSRF, cross-language client test, multi-device enrollment and recovery E2E. Current development bearer tokens remain unsafe.
