# Vault key rotation — actual prototype state

Earlier readiness-only documentation is superseded by the implementation: prepare, manifest-pinned recipients, signed approval, next-epoch envelope staging, history coverage and acknowledgements, commitment comparison, preflight, cancellation, initial transparency chain export.

**Activation is explicitly disabled**: authorized `POST /api/v1/vaults/:vault/rotation/activate` returns HTTP 409 `rotation_activation_not_implemented`; `GET /rotation/preflight` always reports `can_activate:false`. No active Vault `key_epoch` switch is implemented. Preflight metadata checks and device signatures cannot prove a recipient can decrypt the intended Vault Key or historical ciphertext.

Detailed contracts: [rotation preflight](rotation-activation-preflight.md), [readiness/cancellation](rotation-readiness-and-cancellation.md), [signed manifest](signed-rotation-manifest.md), [historical envelopes](historical-key-envelopes.md), [transparency chain](rotation-transparency-chain.md), [activation contract](e2ee-rotation-activation-contract.md). Production activation and operational rollout are M3/M4 in [roadmap](roadmap-backend-web.md).
