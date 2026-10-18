# Vault key rotation staging — development

This implements **preparation only**, not activation.

- `POST /api/v1/vaults/:vault/rotation/prepare` requires explicit Vault manage permission. It records a pending rotation from current `key_epoch` to current + 1 without changing the active epoch. A second concurrent/pending rotation is rejected.
- `POST /api/v1/vaults/:vault/key-envelopes` accepts the current epoch, or the next epoch only when an appropriate prepared rotation exists. Recipients must be verified, trusted, nonrevoked devices with Vault read permission. Envelopes remain opaque and encrypted on the client.
- `GET /api/v1/vaults/:vault/rotation` reports the pending epoch and number of staged envelopes, and always returns `can_activate: false` until a correct atomic commit protocol is implemented.

Pending envelopes are *not* returned through the ordinary current-epoch envelope listing.

## Mandatory next steps

Build an immutable recipient manifest for each rotation, track authenticated approval of every included device, recheck ACL and revocations at activation, and prevent concurrent permission, membership or device changes from racing activation. Define safe cancellation, crash recovery and retirement of old key epochs and ensure previously encrypted item history remains decryptable. The current staging flow uses unsigned operator/client-submitted envelopes and a development bearer token; it must not be used for production password data.
