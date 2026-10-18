# Vault key rotation: readiness v0

`GET /api/v1/vaults/:vault/rotation-readiness` requires an authenticated user with explicit Vault manage access. It reports `current_key_epoch`, `proposed_key_epoch`, and devices whose users have Vault read access and whose devices have completed possession proof and are not revoked.

**This endpoint is read-only.** The response always sets `can_activate=false` with reason `trusted_device_approval_not_implemented`. It neither generates keys nor changes Vault epochs. The device `verified_at` property proves possession of a device signing key; it does **not** establish device trust or account-owner approval.

Before implementing key rotation, introduce authenticated trusted-device approval and a secure first-device bootstrap, bind production sessions to trusted devices, distribute authenticated new key envelopes to all recipients, define how retired and offline devices regain access, and ensure historical encrypted Items remain decryptable. Rotation requires a commit protocol that prevents partial activation. Do not treat this readiness endpoint as proof that rotation is safe.
