# Rotation commitment transparency chain — development v1

`GET /api/v1/vaults/:vault/rotation/transparency` (Vault Read) returns the pending rotation's ordered commitment log `entries`, `size`, and `head_sha256`.

Each successful `POST /api/v1/vaults/:vault/rotation/commitment` creates a device-signed commitment and a new log entry **inside the same database transaction**. The entry stores `rotation_id`, `device_id`, `manifest_sha256`, `key_commitment`, the original Ed25519 `signature`, `prev_hash`, and `entry_hash`. Each entry hash is SHA-256 over domain-separated, length-prefixed UTF-8 fields `zzz-rotation-log-v1`, rotation ID, device ID, manifest digest, commitment, previous entry hash, followed by the signature bytes. The genesis previous hash is empty. A read verifies the complete chain and fails closed if any stored entry fails hash or previous-link verification.

A client SHOULD independently verify the chain and every device's Ed25519 signature against trusted public keys, save previously witnessed `size` and `head_sha256`, and compare them with other devices using an authenticated external channel. Never treat an unverified server-provided head as a trusted anchor.

**Not yet a cryptographic transparency service:** This is a simple hash chain, not a Merkle tree. It has no inclusion proofs, efficient consistency proofs, externally signed checkpoints, trusted independent witnesses, gossip transport, or append-only constraints against a privileged database administrator. The server can rewrite an entire chain or present forked histories unless clients retain and exchange witnessed heads. Concurrent SQLite writers require additional review and database-level append-only enforcement. The current endpoint only exposes a prepared rotation's chain. No rotation activation occurs.

Do not store real passwords in this prototype.
