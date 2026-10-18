import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validate } from './candidate-v1.ts';

const b64 = (n) => Buffer.alloc(n).toString('base64url');
const uuid = '12345678-1234-1234-1234-123456789abc';
function fixture() {
  return {
    protocol: 'zzz-e2ee-candidate-v1',
    suite: 'X25519-HKDF-SHA256-AES256GCM-Ed25519',
    vault_id: uuid, device_id: uuid, rotation_id: uuid, signer_device_id: uuid,
    key_epoch: 1, recipient_key_sha256: b64(32), ephemeral_public_key: b64(32),
    nonce: b64(12), ciphertext: b64(48), manifest_sha256: b64(32),
    vault_key_commitment: b64(32), signature: b64(64),
  };
}
test('candidate-v1 structural validation accepts canonical fixture', () => {
  assert.doesNotThrow(() => validate(fixture()));
});
for (const [name, change] of [
  ['unknown member', (e) => { e.unknown = true; }],
  ['missing member', (e) => { delete e.signature; }],
  ['wrong epoch', (e) => { e.key_epoch = 0; }],
  ['unsafe epoch', (e) => { e.key_epoch = Number.MAX_SAFE_INTEGER + 1; }],
  ['wrong suite', (e) => { e.suite = 'downgrade'; }],
  ['wrong UUID', (e) => { e.vault_id = 'not-a-uuid'; }],
  ['padded base64', (e) => { e.nonce += '='; }],
  ['invalid base64', (e) => { e.nonce = '!'; }],
  ['wrong nonce size', (e) => { e.nonce = b64(11); }],
  ['wrong signature size', (e) => { e.signature = b64(63); }],
  ['wrong member type', (e) => { e.device_id = 42; }],
]) {
  test('candidate-v1 rejects ' + name, () => {
    const e = fixture();
    change(e);
    assert.throws(() => validate(e));
  });
}
