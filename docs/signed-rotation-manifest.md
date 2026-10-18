# Signed vault rotation manifest — development v1

After preparing a rotation, an account device that is verified, trusted and active can sign the prepared recipient digest.

`POST /api/v1/vaults/:vault/rotation/sign` (Vault Manage required):

```json
{"device_id":"TRUSTED_DEVICE_UUID","manifest_sha256":"64 lowercase hexadecimal digits","signature":"base64 Ed25519 signature"}
```

The signed message is UTF-8 bytes of `zzz-vault-rotation-approval-v1:<vault_id>:<rotation_id>:<manifest_sha256>`. The trusted device signs with its Ed25519 private key; the server checks the signature against its registered signing public key and revalidates the manifest checksum within the same SQLite transaction that records the approval. A device may sign only once per rotation. Rotation status reports `signature_count`.

**Security limitations:** An approved digest attests only the manifest bytes, not the decryptability, authenticity or completeness of future-epoch Key Envelopes. The HTTP request is authorized using the existing development Bearer authentication; the signature itself is checked separately. There is no threshold/quorum policy, cryptographically verified key wrapping, immutable signing-key history, attested signing UX, or protected activation transaction. A database administrator can still replace signatures and public keys. This route does not activate the rotation; `can_activate` remains false. Do not use real passwords.

## Revalidation of existing signatures

Rotation status now reports `valid_signature_count` and `invalid_signer_device_ids` in addition to the total `signature_count`. Stored approvals are verified again against current trusted, verified, nonrevoked device signing keys and the signer's current Vault Manage ACL. A revoked signer, removed Manage permission, changed key, corrupted signature or digest mismatch does not count as a valid approval.

This is diagnostic only, not a quorum policy. The status never enables activation, and multi-query validation is not a substitute for atomic checks at commit time.

## Quorum policy v1

Each new rotation records `required_approvals = 1`, pinned at preparation time. Rotation status returns `required_approvals` and `quorum_met`; the latter is calculated from **currently valid** Ed25519 signatures, not the number of stored approvals. Revocation, lost Manage ACL or signing-key change can make the quorum false again.

This is a conservative single-approver **development policy**, not a reviewed team-vault multi-party approval policy. Changing approval thresholds via caller input is not supported. There is still no activation endpoint. Production needs explicit workspace/group-specific quorum rules and safeguards against one account's devices impersonating multiple independent approvers.
