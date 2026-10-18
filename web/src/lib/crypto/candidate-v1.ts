/**
 * Experimental candidate-v1 browser verification/decryption adapter.
 * No identity directory, persistence, recovery or production trust bootstrap.
 * Caller MUST independently authenticate expectedSigner and manifest.
 */
export type Envelope = {
  protocol: string; suite: string; vault_id: string; device_id: string;
  rotation_id: string; signer_device_id: string; key_epoch: number;
  recipient_key_sha256: string; ephemeral_public_key: string;
  nonce: string; ciphertext: string; manifest_sha256: string;
  vault_key_commitment: string; signature: string;
};
export type ExpectedContext = Pick<Envelope,
  'vault_id' | 'device_id' | 'rotation_id' | 'signer_device_id' | 'key_epoch' | 'manifest_sha256'>;
const PROTOCOL = 'zzz-e2ee-candidate-v1';
const SUITE = 'X25519-HKDF-SHA256-AES256GCM-Ed25519';
const UUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();
const fail = (): never => { throw new Error('Invalid candidate E2EE envelope'); };
const equal = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.reduce((v, x, i) => v | (x ^ b[i]), 0) === 0;

function decode(value: string, length: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return fail();
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  // Browser-native atob is used only for strict, canonical base64url.
  const raw = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (bytes.length !== length || encode(bytes) !== value) return fail();
  return bytes;
}
function encode(bytes: Uint8Array): string {
  let s = '';
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function canonical(value: Record<string, string | number>): Uint8Array {
  return encoder.encode(JSON.stringify(Object.fromEntries(
    Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0),
  )));
}
function domain(label: string, data: Uint8Array): Uint8Array {
  const prefix = encoder.encode('zzz/e2ee/candidate-v1/' + label);
  const out = new Uint8Array(prefix.length + 5 + data.length);
  out.set(prefix);
  new DataView(out.buffer).setUint32(prefix.length + 1, data.length, false);
  out.set(data, prefix.length + 5);
  return out;
}
function metadata(e: Envelope, includeCommitment: boolean): Record<string, string | number> {
  const m: Record<string, string | number> = {
    protocol: e.protocol, suite: e.suite, vault_id: e.vault_id,
    device_id: e.device_id, rotation_id: e.rotation_id,
    key_epoch: e.key_epoch, recipient_key_sha256: e.recipient_key_sha256,
    ephemeral_public_key: e.ephemeral_public_key,
    manifest_sha256: e.manifest_sha256, signer_device_id: e.signer_device_id,
  };
  if (includeCommitment) m.vault_key_commitment = e.vault_key_commitment;
  return m;
}
export function validate(e: Envelope): void {
  if (e.protocol !== PROTOCOL || e.suite !== SUITE ||
    ![e.vault_id, e.device_id, e.rotation_id, e.signer_device_id].every((v) => UUID.test(v)) ||
    !Number.isSafeInteger(e.key_epoch) || e.key_epoch < 1) fail();
  for (const [field, length] of [
    ['recipient_key_sha256', 32], ['ephemeral_public_key', 32],
    ['nonce', 12], ['ciphertext', 48], ['manifest_sha256', 32],
    ['vault_key_commitment', 32], ['signature', 64],
  ] as const) decode(e[field], length);
}
export async function unwrap(
  envelope: Envelope, recipientPrivate: CryptoKey, expectedSigner: CryptoKey,
  expected: ExpectedContext, recipientPublicRaw: Uint8Array,
): Promise<Uint8Array> {
  validate(envelope);
  for (const field of ['vault_id', 'device_id', 'rotation_id',
    'signer_device_id', 'key_epoch', 'manifest_sha256'] as const) {
    if (envelope[field] !== expected[field]) fail();
  }
  if (recipientPrivate.algorithm.name !== 'X25519' ||
    expectedSigner.algorithm.name !== 'Ed25519' ||
    recipientPublicRaw.length !== 32) fail();
  const fingerprint = new Uint8Array(await crypto.subtle.digest('SHA-256', recipientPublicRaw));
  if (!equal(fingerprint, decode(envelope.recipient_key_sha256, 32))) fail();
  const signed = { ...metadata(envelope, true), nonce: envelope.nonce, ciphertext: envelope.ciphertext };
  const ok = await crypto.subtle.verify('Ed25519', expectedSigner,
    decode(envelope.signature, 64), domain('signed-envelope', canonical(signed)));
  if (!ok) fail();
  const ephemeral = await crypto.subtle.importKey('raw', decode(envelope.ephemeral_public_key, 32),
    'X25519', false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'X25519', public: ephemeral }, recipientPrivate, 256));
  if (shared.every((x) => x === 0)) fail();
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32),
    info: domain('envelope-kek', canonical(metadata(envelope, false))),
  }, ikm, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: decode(envelope.nonce, 12),
    additionalData: domain('recipient-envelope-aad', canonical(metadata(envelope, true))),
    tagLength: 128,
  }, kek, decode(envelope.ciphertext, 48)));
  if (plaintext.length !== 32) fail();
  const commit = canonical({
    protocol: envelope.protocol, vault_id: envelope.vault_id,
    key_epoch: envelope.key_epoch, manifest_sha256: envelope.manifest_sha256,
    key: encode(plaintext),
  });
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', domain('vault-key-commitment', commit)));
  if (!equal(digest, decode(envelope.vault_key_commitment, 32))) fail();
  return plaintext;
}
