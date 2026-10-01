import test from 'node:test';
import assert from 'node:assert/strict';
globalThis.btoa = globalThis.btoa || ((s) => Buffer.from(s, 'binary').toString('base64'));
globalThis.atob = globalThis.atob || ((s) => Buffer.from(s, 'base64').toString('binary'));

const mod = await import('../public/js/crypto.js');

test('random access code is formatted and non-empty', () => {
  const code = mod.generateAccessCode();
  assert.match(code, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
});

test('AES-GCM detects tampering', async () => {
  const key = mod.randomBytes(32);
  const record = await mod.aesEncrypt(key, new TextEncoder().encode('secret'), 'aad');
  const tampered = { ...record, ciphertext: record.ciphertext.slice(0, -2) + (record.ciphertext.endsWith('AA') ? 'BB' : 'AA') };
  await assert.rejects(() => mod.aesDecrypt(key, tampered));
});

test('capsule package round-trips plaintext locally', async () => {
  const pack = await mod.createCapsulePackage('Hello from CIPHER', { mode: 'standard', capsuleId: 'TEST01' });
  assert.match(pack.clientSecret, /^[a-f0-9]{64}$/);
  assert.match(pack.accessHash, /^[a-f0-9]{64}$/);
  const opened = await mod.openCapsulePackage(pack.clientSecret, 'TEST01', { envelope: pack.envelope, metadataCiphertext: pack.metadataRecord, messageRecord: pack.messageRecord });
  assert.equal(opened.message, 'Hello from CIPHER');
  assert.equal(opened.metadata.mode, 'standard');
  assert.equal(opened.integrity, true);
});

test('wrong secret key cannot open capsule', async () => {
  const pack = await mod.createCapsulePackage('Nope', { mode: 'standard', capsuleId: 'TEST03' });
  const wrong = '00'.repeat(32);
  await assert.rejects(() => mod.openCapsulePackage(wrong, 'TEST03', { envelope: pack.envelope, metadataCiphertext: pack.metadataRecord, messageRecord: pack.messageRecord }));
});

test('metadata tampering is detected', async () => {
  const pack = await mod.createCapsulePackage('Hi', { mode: 'one-time', capsuleId: 'TEST02' });
  const meta = JSON.parse(JSON.stringify(pack.metadataRecord));
  meta.ciphertext = meta.ciphertext.slice(0, -2) + 'AA';
  await assert.rejects(() => mod.openCapsulePackage(pack.clientSecret, 'TEST02', { envelope: pack.envelope, metadataCiphertext: meta, messageRecord: pack.messageRecord }));
});
