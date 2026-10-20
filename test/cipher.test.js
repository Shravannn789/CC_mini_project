import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { blockAAD, decryptBlock, deriveKey, encryptBlock, newSalt } from '../src/cipher.js';

test('encrypt + decrypt round trip', async () => {
  const salt = newSalt();
  const key = await deriveKey('correct horse battery staple', salt);
  const aad = blockAAD('vault-1', 0);
  const plaintext = randomBytes(4096);
  const blob = encryptBlock(plaintext, key, aad);
  assert.equal(blob.length, 12 + 16 + plaintext.length);
  assert.deepEqual(decryptBlock(blob, key, aad), plaintext);
});

test('same passphrase + salt yields the same key; different salt does not', async () => {
  const salt = newSalt();
  const k1 = await deriveKey('pass', salt);
  const k2 = await deriveKey('pass', salt);
  const k3 = await deriveKey('pass', newSalt());
  assert.deepEqual(k1, k2);
  assert.notDeepEqual(k1, k3);
  assert.equal(k1.length, 32);
});

test('wrong passphrase fails to decrypt', async () => {
  const salt = newSalt();
  const goodKey = await deriveKey('right', salt);
  const badKey = await deriveKey('wrong', salt);
  const aad = blockAAD('vault-1', 3);
  const blob = encryptBlock(randomBytes(256), goodKey, aad);
  assert.throws(() => decryptBlock(blob, badKey, aad));
});

test('tampered ciphertext, tag or nonce is rejected by GCM', async () => {
  const salt = newSalt();
  const key = await deriveKey('pass', salt);
  const aad = blockAAD('vault-1', 0);
  const blob = encryptBlock(randomBytes(256), key, aad);

  for (const pos of [0, 12, 30, blob.length - 1]) {
    const tampered = Buffer.from(blob);
    tampered[pos] ^= 0x01;
    assert.throws(() => decryptBlock(tampered, key, aad), undefined, `tamper at ${pos} must fail`);
  }
});

test('blocks cannot be reordered or replayed across vaults (AAD binding)', async () => {
  const salt = newSalt();
  const key = await deriveKey('pass', salt);
  const blob = encryptBlock(randomBytes(128), key, blockAAD('vault-a', 0));
  // Same block index, different vault id
  assert.throws(() => decryptBlock(blob, key, blockAAD('vault-b', 0)));
  // Same vault, different index (reorder)
  assert.throws(() => decryptBlock(blob, key, blockAAD('vault-a', 1)));
});

test('truncated block is rejected before any crypto happens', async () => {
  const salt = newSalt();
  const key = await deriveKey('pass', salt);
  assert.throws(() => decryptBlock(Buffer.alloc(20), key, blockAAD('v', 0)), /too short/);
});
