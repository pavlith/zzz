# E2EE protocol — design draft

Status: NOT IMPLEMENTED. Do not store real passwords.

## Trust boundaries

The client generates vault keys and encrypts item contents; server stores only opaque ciphertext. Device keys are generated locally. No private keys are sent to Go backend.

## Planned device keys

Each client generates an X25519 key pair for encryption and Ed25519 key pair for signatures. The server stores public keys; the client must verify the key directory independently before distributing any vault key. Proof of possession and trusted-device enrollment must be implemented before production.

## Planned vault key envelopes

Every vault has a fresh random encryption key. A distinct envelope wraps this key for each authorized device using authenticated hybrid encryption. Include vault ID, device ID, key epoch, and format version in authenticated context; enforce unique nonces. The server checks workspace membership, explicit vault permissions, and current key epoch before delivering envelopes. The service must support rotation, revocation, and rollback detection.

## Required before implementing cryptography

Finalize versioned canonical encoding, threat model, reproducible test vectors, verified recipient identities, trusted device enrollment and account recovery. Do not implement homemade PAKE or claim E2EE while these are missing.
