import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { wrap, unwrap } from './candidate-v1.ts';

const uuid = (lead) => lead + '2345678-1234-1234-1234-123456789abc';
const raw = (bytes) => Buffer.from(bytes).toString('base64url');

test('WebCrypto Wrap -> Go Unwrap, including authenticated roundtrip', async () => {
  const recipient = await webcrypto.subtle.generateKey('X25519', true, ['deriveBits']);
  const signer = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const recipientPublic = new Uint8Array(
    await webcrypto.subtle.exportKey('raw', recipient.publicKey));
  const recipientPKCS8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', recipient.privateKey));
  const recipientPrivate = recipientPKCS8.subarray(-32);
  const signerPublic = new Uint8Array(await webcrypto.subtle.exportKey('raw', signer.publicKey));
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const manifest = webcrypto.getRandomValues(new Uint8Array(32));
  const context = {
    vault_id: uuid('1'), device_id: uuid('2'), rotation_id: uuid('3'),
    signer_device_id: uuid('4'), key_epoch: 3, manifest_sha256: raw(manifest),
  };
  const envelope = await wrap(key, recipientPublic, signer.privateKey, context);
  const browserPlain = await unwrap(envelope, recipient.privateKey,
    signer.publicKey, context, recipientPublic);
  assert.deepEqual(Buffer.from(browserPlain), Buffer.from(key));
  const payload = JSON.stringify({
    envelope, recipient_private_key: raw(recipientPrivate),
    signer_public_key: raw(signerPublic), vault_key: raw(key),
  });
  const result = spawnSync('go', ['run', './pkgs/e2ee/candidatev1/testdata/interop'],
    { input: payload, encoding: 'utf8', maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Go verified browser envelope/);
});
