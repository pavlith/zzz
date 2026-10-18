# Rotation recipient manifest (development)

Preparing a Vault key rotation now captures a database-backed list of verified, trusted, active devices that have Vault read access at preparation time. The list is represented by `RotationRecipient` records and is not automatically expanded when new devices join. Staging next-epoch envelopes requires that the device was included in the prepared manifest. Rotation status includes `required_recipients` and `staged_envelopes`.

This makes preparation reproducible but **does not make activation safe**. Revoked devices, changed ACL or group membership, a changed device key, or an altered recipient set require revalidation and likely cancellation/restart of the rotation. The manifest currently lacks signatures and an audited recipient digest. Staged envelopes are opaque and their actual ability to decrypt a new vault key cannot be verified by the server. Concurrent prepare requests require further hardening through database constraints.

There is deliberately no activation endpoint; `can_activate` remains false. Do not store real passwords.
