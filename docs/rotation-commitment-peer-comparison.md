# Rotation commitment view for peer comparison (development)

`GET /api/v1/vaults/:vault/rotation/commitments` requires Vault Read and returns the pending `rotation_id`, `manifest_sha256`, all stored per-device signed claims ordered by `device_id`, and `view_sha256`.

The view digest is SHA-256 of domain-separated, length-prefixed UTF-8 fields `zzz-rotation-commitment-view-v1`, Vault ID, rotation ID, manifest SHA-256, followed by each ordered row's device ID, manifest digest, key commitment, and raw Ed25519 signature bytes. A client should recompute the digest independently and verify every device signature against authenticated, pinned identity keys rather than trusting the server's digest or list.

Clients can exchange independently obtained view digests and signed claims over an authenticated peer-to-peer channel. Differing view digests for the same rotation identify different *views*, including omissions or alterations. A digest alone does not identify the dishonest party.

**This is not a transparency log.** There are no authenticated append-only tree heads, consistency/inclusion proofs, witnesses, client gossip implementation, or protection against a server serving two internally consistent snapshots. This response includes signatures and device IDs and therefore must remain access-controlled; account Bearer authentication still needs replacement with device-bound sessions. Preflight never activates `key_epoch`. Do not use real passwords.
