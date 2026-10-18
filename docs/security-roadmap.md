# Security roadmap — release blockers

**Status: NOT safe for real passwords.** Track task-level completion in [roadmap-backend-web.md](roadmap-backend-web.md).

## Implemented as prototypes
- Server stores ciphertext and revision metadata; ACL and conflict checks exist, but need comprehensive multi-tenant audit.
- Device signature verification, trust approval and session flows exist; production identity/authentication is incomplete.
- Signed rotation approvals and acknowledgements, staged key envelopes, dynamic ACL/trust validation and historical coverage are implemented; **activation is blocked**.
- Client Go library for X25519/AES-GCM with signed commitments is experimental; **web crypto not integrated**.
- Commitment comparison and a basic SHA-256 hash chain exist; neither provides an externally witnessed transparency guarantee.

## Mandatory security gates
1. Audited production authentication, recovery, device-bound sessions; rate limits, cookie/CSRF strategy, anti-enumeration controls.
2. Independently reviewed protocol and verified key directory, interoperable WebCrypto/Go vectors, secret-free server, protection against sender equivocation and rollback.
3. Real append-only/witnessed transparency consistency checks, robust device trust/revocation, safe offline/history key retention, fail-closed activation.
4. Multi-tenant ACL and IDOR audit, concurrency/invariants, versioned migrations, backup restoration and auditability.
5. Svelte/browser XSS/CSP and storage threat model, accessible UX, clipboard/keyring lock lifecycle and integration/E2E security tests.
6. TLS/CORS/CSRF policies, safe configuration, logs with redaction, SBOM/dependency scanning, external security assessment.

**Not proven:** signatures over ciphertext do not prove decryption; same signed key commitment does not guarantee honest or independent devices; a server-only hash chain cannot prevent rewrite/forks. Production rollout requires evidence for each release gate and documented residual risks.
