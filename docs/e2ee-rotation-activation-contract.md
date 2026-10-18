# E2EE Vault Rotation — activation security contract (design; NOT implemented)

## Security boundary

The server stores opaque encrypted item revisions, device key envelopes, recipient manifests, and signed client declarations. **No server-side claim of successful key decryption is possible from a signed acknowledgement alone.** A malicious or faulty device can sign a false acknowledgement.

The current prototype MUST NOT switch Vault.key_epoch. POST /api/v1/vaults/:vault/rotation/activate intentionally returns HTTP 409 `rotation_activation_not_implemented` for authorized managers; unauthorized callers remain denied.

## Client cryptographic requirements

1. Generate the next Vault encryption key using a CSPRNG on a trusted client; never transmit plaintext keys to the server.
2. Define an independently reviewed versioned envelope format. Authenticate all important context via AEAD associated data: protocol/version, vault ID, target key epoch, recipient device ID, recipient encryption public-key fingerprint, and rotation ID. Prevent cross-vault, cross-device, and cross-epoch substitution.
3. Authenticate the sender and recipient public-key identities, including key replacement and device revocation. Bind the full canonical manifest digest to the signed approval, and verify it on clients **before** wrapping or accepting a new key.
4. Each intended recipient must perform local unwrap and a cryptographic consistency check over the intended new Vault key. A signature over ciphertext hashes is merely a device assertion, not a zero-knowledge decryption proof.
5. Historical encrypted revisions are immutable and retain their original key_epoch. Preserve each required old key through encrypted historical envelopes for every entitled device. Client verification must test the correct key against an authenticated test vector or real item ciphertext; never send the plaintext key to the server.
6. Use device-bound, short-lived authentication for approval/acknowledgement and a user-verifiable confirmation UX. Account bearer authentication alone is insufficient.
7. Handle disaster recovery, offline devices, device revocations, role changes, and interrupted rotations with explicit policies. No arbitrary weakening of quorum from caller input.

## Atomic activation requirements (future)

Within one serialized write transaction, re-read the active epoch, prepared rotation status, the pinned manifest digest, current eligible recipient set, public-key fingerprints, ACLs, quorum and all required current/historical envelopes plus their acknowledgements. Reject stale or missing records. Enforce only one pending/activating rotation per vault using a database constraint, not just an application-level count. Change rotation status and Vault.key_epoch with conditional updates and verify affected rows; commit atomically. Never delete current or historical envelopes as part of activation. Keep an append-only audit event and idempotency key for retries.

When a prerequisite is absent, the transaction must fail without changing any key epoch. Preflight is only an advisory snapshot, not authorization to activate.

## Prioritized blocking issues

- Protocol-level independent key-consistency verification is undefined.
- Signed acknowledgements are not sufficient evidence that an honest recipient can decrypt.
- Historical-key retention, archived revisions, and offline device recovery require reviewed policies.
- Authenticated key distribution and session-device binding are incomplete.
- Concurrency constraints and atomic epoch-change protocol are unimplemented.

Until these conditions are implemented and reviewed, **production use and storing real passwords are unsafe**.
