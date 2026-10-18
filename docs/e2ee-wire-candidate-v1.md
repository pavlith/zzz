# M0-03 — interoperable E2EE wire contract (candidate v1)

**Status: proposed, NOT frozen or audited (2026-10-18).** This specification is a target for Go ↔ TypeScript interoperability. It does not claim that the current `pkgs/e2ee` implementation follows these bytes. Production use and rotation activation remain blocked.

## Design principles

- All key generation, key wrapping and plaintext handling happen on clients. The server sees ciphertext, public identity records and authenticated metadata.
- Separate Ed25519 device signing keys from X25519 recipient agreement keys. Neither a key embedded in an envelope nor a server-issued signature alone establishes device identity.
- Canonicalization is mandatory for every signed/hashable object; do not sign arbitrary JSON serialized by a language runtime.
- A protocol version or algorithm identifier is authenticated and cannot be silently downgraded.
- Unknown mandatory fields, invalid lengths, duplicate JSON object members, noncanonical encodings, unsupported versions and malformed points must fail closed.

## Candidate canonical representation

For signed protocol objects, use RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 encoded, with a strict schema:

1. ASCII snake_case member names, no unknown members in v1.
2. Integers only in the exact safe JSON integer range and within each field's schema; no floating-point numbers.
3. Cryptographic byte strings encoded as unpadded base64url (RFC 4648 section 5). Decoders reject padding, whitespace, alternate alphabets and noncanonical final bits.
4. Identifiers are lowercase canonical UUID strings (8-4-4-4-12) or a separately specified opaque identifier; never normalize identifiers during verification.
5. Timestamps, if used, are integer Unix milliseconds; no locale-dependent strings.
6. Serialize with a conforming JCS implementation, never ordinary Go `encoding/json` or JavaScript `JSON.stringify` as a substitute. Reject duplicate members before canonicalization.

**Compatibility warning:** existing experimental Go envelopes use standard padded base64 and their own length-prefixed AAD. They are NOT candidate-v1 wire-compatible. Introduce a new explicit version; do not silently reinterpret existing `version:1` envelopes.

## Domain separation

Define `D(label, bytes) = UTF8("zzz/e2ee/candidate-v1/" + label) || 0x00 || uint32be(len(bytes)) || bytes`. Each label is fixed ASCII and registered per purpose. Hashes use SHA-256 of `D(label, canonical_bytes)`. Signatures use Ed25519 over `D("signed-envelope", canonical_bytes_without_signature)`; no signing of an object containing its own signature.

Proposed labels: `recipient-envelope-aad`, `signed-envelope`, `rotation-manifest`, `vault-key-commitment`, `transparency-checkpoint`. Labels must never be reused for a different semantic object.

## Candidate recipient envelope

Required fields (no extras):
- `protocol`: exact string `zzz-e2ee-candidate-v1`
- `suite`: exact string `X25519-HKDF-SHA256-AES256GCM-Ed25519`
- `vault_id`, `device_id`, `rotation_id`: canonical UUID strings; rotation-less initial provisioning needs a separately specified object type rather than a fake UUID
- `key_epoch`: integer >= 1
- `recipient_key_sha256`: 32 bytes encoded as base64url
- `ephemeral_public_key`: 32 bytes encoded as base64url
- `nonce`: 12 bytes encoded as base64url
- `ciphertext`: AEAD output (32-byte vault key plus 16-byte tag) encoded as base64url
- `manifest_sha256`: 32 bytes encoded as base64url
- `vault_key_commitment`: 32 bytes encoded as base64url
- `signer_device_id`: canonical UUID string
- `signature`: 64 bytes encoded as base64url

AAD is `D("recipient-envelope-aad", JCS({protocol,suite,vault_id,device_id,rotation_id,key_epoch,recipient_key_sha256,ephemeral_public_key,manifest_sha256,vault_key_commitment,signer_device_id}))`. All fields are mandatory.

HKDF-SHA256 inputs: IKM = 32-byte X25519 shared secret; salt = 32 zero bytes; info = `D("envelope-kek", JCS({protocol,suite,vault_id,device_id,rotation_id,key_epoch,recipient_key_sha256,ephemeral_public_key,manifest_sha256,signer_device_id}))`; output = 32 bytes. Register `envelope-kek` as a distinct domain label.

Vault key commitment: `SHA256(D("vault-key-commitment", JCS({protocol,vault_id,key_epoch,manifest_sha256,key:base64url(raw_32_byte_vault_key)})))`. This commitment is only appropriate for uniformly random high-entropy keys. Sign the complete envelope object excluding `signature`; independently authenticate the expected signing key and verify the authorized manifest before decryption.

Reject X25519 all-zero shared secrets, invalid signature, altered context, mismatched key commitment and wrong expected signer. Never trust a signer key supplied only by the untrusted envelope.

## Rotation manifest and identity

The rotation manifest MUST identify vault, previous/new epochs, exact recipient device IDs and authenticated public-key fingerprints, initiator, nonce and authorization context. Canonical schema, sorted recipient order, independent identity proof and authorization snapshot are **not yet finalized**. Consequently, this candidate envelope cannot be promoted to frozen wire v1.

A recipient verifies the signing key against an independently trusted device identity record, the signed manifest and an independently witnessed checkpoint. Cross-device commitment comparisons are required to detect equivocation; the server's own SHA-256 chain alone is insufficient.

## Cross-language conformance gate (M3-02)

Build fixtures from fixed test-only keys, ephemeral X25519 secret and nonce, including exact JCS bytes, AAD, HKDF info, KEK, ciphertext, commitment and Ed25519 signature. Run the same fixtures in Go and TypeScript/WebCrypto; assert byte-for-byte equality. Negative fixtures must cover duplicate JSON keys, noncanonical base64url, unknown members, changed UUID/epoch/recipient/manifest/signer, wrong key, tampered ciphertext/tag/signature, all-zero X25519 shared secret and stale checkpoint. Randomized roundtrip tests do not replace known-answer vectors.

## Open decisions before M0-03 completion

1. Finalize rotation and initial-provisioning manifest schemas and their binding to ACL/trust snapshots.
2. Choose and review authenticated identity-directory and independent checkpoint/witness transport.
3. Define archival key wrapping, multi-epoch compatibility, recovery and algorithm agility.
4. Implement candidate separately from the existing Go v1, with Go/TS deterministic vectors.
5. Obtain independent protocol review; only then freeze a numbered production protocol and update OpenAPI.

**Safety gate:** rotation activation must continue to return HTTP 409 until all required cryptographic and authorization gates pass. No real passwords.


## Experimental browser adapter status (2026-10-18)

`web/src/lib/crypto/candidate-v1.ts` contains a preliminary TypeScript/WebCrypto **decrypt-and-verify** adapter. It is not a complete Svelte application, has no browser build/test harness, does not implement wrapping, does not independently authenticate signer identity, and does not establish trusted manifest authorization or key transparency. Its caller must supply a previously authenticated Ed25519 signer key and recipient public key associated with the private key. X25519/Ed25519 WebCrypto support must be checked in target browsers. Browser memory zeroization cannot be guaranteed.

**Interoperability gate still open:** no checked-in cross-language fixed expected ciphertext/signature bytes or negative fixtures have been verified against this adapter. Go deterministic tests are not proof of browser interoperability. Current candidate canonicalization relies on a narrowly constrained ASCII-key/primitive-value JSON subset; a general RFC 8785 implementation and parser-level duplicate-member rejection must be independently assessed before freezing the wire protocol. The browser adapter currently accepts parsed objects and does not reject extra object members itself. Never parse untrusted raw JSON using plain JSON.parse and assume duplicate-field detection.

Do not use real secrets or enable rotation activation.
