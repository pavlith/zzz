# ADR-002: Canonical E2EE wire protocol and trust

**State: CANDIDATE (NOT FROZEN; independent review pending).**

Client key primitive candidates: 256-bit CSPRNG Vault keys, X25519 ephemeral ECDH, HKDF-SHA256, AES-256-GCM for envelopes, Ed25519 signatures. Current Go `pkgs/e2ee` is experimental and `web/src/lib/crypto/candidate-v1.ts` is incomplete; do not claim interoperability until shared positive/negative vectors pass.

Wire contract candidate: protocol version, Vault ID, Device ID, Rotation ID, epoch, recipient key fingerprint, ephemeral public key, 96-bit nonce, ciphertext, pinned manifest digest and signer identity. Canonical domain-separated length-prefixed binary transcript for signatures and AEAD AAD, strict UTF-8 and integer representation; unknown versions and malformed lengths fail closed. Public keys must be verified independently; a key self-declared inside ciphertext isn't identity. Signed key commitment comparison needs externally witnessed checkpoints against server equivocation.

Item revisions retain historical key epochs. Never enable rotation activation until complete historical preservation, client key verification, authenticated recipients, serialized transactional state transition, and independent review.

**Completion gate:** frozen encoding, Go+browser fixtures, authenticated directory/pairing, tamper/negative tests, crypto review and recovery policy. Existing server Key Envelope API does not parse/enforce experimental client JSON envelope format.
