# First trusted device bootstrap (development only)

There is deliberately no HTTP endpoint that trusts the first device using a bearer account token. During local development the machine operator can bootstrap an initial verified device using the CLI.

1. Register a device through `POST /api/v1/devices` and complete Ed25519 proof via the challenge/verify endpoints.
2. On the physical device, independently compute SHA-256 of each **raw 32-byte public key** (signing and encryption) and compare with those intended for the account.
3. On the server machine, using local administrative access to the SQLite database, execute:

```sh
zzz bootstrap-device --user USER_UUID --device DEVICE_UUID \
  --signing-sha256 SIGNING_PUBLIC_KEY_SHA256_HEX \
  --encryption-sha256 ENCRYPTION_PUBLIC_KEY_SHA256_HEX
```

The command checks the supplied fingerprints, requires the device to belong to the account, be verified and nonrevoked, and rejects bootstrapping when *any* trusted device already exists for that account. It sets `trusted_at` in a database transaction.

This procedure trusts the machine operator and database integrity; it does not provide production-grade account identity verification, a safe remote bootstrap, or account recovery. Fingerprints should be obtained from the device through an independent channel, not copied from the untrusted API response. Production first-device enrollment must be integrated into a reviewed account-registration and recovery ceremony. Do not use real passwords with the current development backend.
