import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { unwrap } from './candidate-v1.ts';

const raw = (value) => Buffer.from(value, 'base64url');

test('Go candidate-v1 vector decrypts and authenticates with WebCrypto', async () => {
  const output = execFileSync('go', [
    'test', './pkgs/e2ee/candidatev1', '-run', '^TestDeterministicEnvelope$',
    '-count=1', '-v',
  ], { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  const line = output.split('\n').find((s) => s.includes('CANDIDATE_V1_VECTOR='));
  assert.ok(line, 'Go test did not emit vector');
  const vector = JSON.parse(line.slice(line.indexOf('CANDIDATE_V1_VECTOR=') + 'CANDIDATE_V1_VECTOR='.length));
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'),
    raw(vector.recipient_private_key),
  ]);
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    raw(vector.signer_public_key),
  ]);
  const privateKey = await webcrypto.subtle.importKey('pkcs8', pkcs8,
    'X25519', false, ['deriveBits']);
  const signer = await webcrypto.subtle.importKey('spki', spki,
    'Ed25519', false, ['verify']);
  const e = vector.envelope;
  const context = {
    vault_id: e.vault_id, device_id: e.device_id, rotation_id: e.rotation_id,
    signer_device_id: e.signer_device_id, key_epoch: e.key_epoch,
    manifest_sha256: e.manifest_sha256,
  };
  const actual = await unwrap(e, privateKey, signer, context, raw(vector.recipient_public_key));
  assert.deepEqual(Buffer.from(actual), raw(vector.vault_key));
  const tampered = { ...e, key_epoch: e.key_epoch + 1 };
  await assert.rejects(unwrap(tampered, privateKey, signer, context,
    raw(vector.recipient_public_key)));
  const altered = { ...e, ciphertext: 'A' + e.ciphertext.slice(1) };
  await assert.rejects(unwrap(altered, privateKey, signer, context,
    raw(vector.recipient_public_key)));
});
