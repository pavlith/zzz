# E2EE cryptographic protocol — experimental, NOT frozen

Server stores opaque encrypted item ciphertext and device Key Envelopes. Go client-side prototype `pkgs/e2ee` implements X25519 ephemeral agreement, HKDF-SHA256, AES-256-GCM (32-byte keys), contextual AAD with Vault/device/epoch/rotation, and signed Ed25519 envelopes/key commitments. This **has not been integrated** with server envelope formats or a Svelte/WebCrypto client and **is not independently audited**.

## Client trust requirements
- Client CSPRNG generates all Vault and device private keys locally. Never send plaintext private keys, passwords or Vault Keys to backend.
- Independently verify device public keys and the signing authority for rotation manifests. A public key provided inside a signed envelope is **not its own identity proof**.
- Prevent cross-context key substitution and signer equivocation; compare authenticated device commitments through independently witnessed checkpoints.
- Preserve old keys for immutable item revisions and define retention/recovery/offline behavior; device revocation cannot erase previously exported secrets.
- Treat server-signed claims and SHA-256 hash chains as insufficient for proof of actual decryption or server non-equivocation.

## Release blockers
Freeze canonical interoperable wire encoding, KDF/key hierarchy, authentication/recovery decisions, browser key-storage threat model, cryptographic commitment proof/identity binding, test vectors shared by Go and TypeScript, external audit and complete E2E tests.

See [E2EE envelope v1](e2ee-client-envelope-v1.md), [verified envelopes](e2ee-verified-envelope.md), [commitment consensus](e2ee-commitment-consensus.md), [activation contract](e2ee-rotation-activation-contract.md) and [canonical roadmap](roadmap-backend-web.md). **Never use real credentials yet.**
