# Implementation plan

## Next milestone: security architecture

1. Record a threat model for compromised server, compromised client, lost device and malicious workspace administrator.
2. Specify registration and device-enrollment flows before implementing public endpoints.
3. Define key hierarchy and versioned envelope wire format with reference test vectors.
4. Build authorization tests for member, group, vault, recipient, and revocation scenarios.
5. Introduce versioned database migrations and continuous integration.
6. Implement append-only sync events and conflict resolution, with tombstones.

Do not deploy the current development authentication mechanism to production or store real passwords. Current endpoints prove authorization structure, not end-to-end cryptographic security.
