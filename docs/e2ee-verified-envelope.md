# Verified client envelope and Vault Key commitment (experimental)

The client package `pkgs/e2ee` now supports `SignWrappedKey` and `OpenVerifiedKey`.

`SignWrappedKey` wraps a 32-byte Vault Key to an X25519 recipient, creates a domain-separated SHA-256 commitment over the **raw key bytes** and manifest SHA-256, and signs the commitment plus the exact envelope context, ephemeral public key, nonce and ciphertext using Ed25519.

`OpenVerifiedKey` requires **out-of-band authenticated** expected Ed25519 public key, expected manifest SHA-256 and exact Vault/rotation/device/epoch context. It verifies Ed25519, decrypts the AES-GCM envelope, then compares the SHA-256 key commitment in constant time. The same manifest and intended Vault Key produce the same commitment across recipients. This can help honest clients detect different keys being distributed for the same manifest.

**Threat model and limitations**: A compromised or malicious signer can sign two different commitments for the same rotation (equivocation). Clients must exchange and compare independently authenticated commitments, or use a transparency/audit protocol; one signed envelope does not establish consensus across devices. SHA-256 commitment to random 256-bit keys is suitable only for unpredictable keys, not human passwords or low-entropy secrets. The signature must be tied to a trusted device identity and authorized rotation manifest, NOT to an untrusted key from the envelope itself. No server integration, cross-platform test vectors, recovery protocols or independent cryptographic review are complete. The activation API remains disabled.

This format is experimental and may change before production. Do not store real passwords.
