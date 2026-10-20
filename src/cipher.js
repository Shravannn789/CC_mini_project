import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

export const CIPHER = 'aes-256-gcm';
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const SALT_BYTES = 16;

// Cost parameters for turning a passphrase into a 256-bit key.
export const KDF = { name: 'scrypt', N: 16384, r: 8, p: 1 };
const SCRYPT_MAXMEM = 128 * KDF.N * KDF.r * 4; // headroom above the 128*N*r bytes scrypt needs

/**
 * Derive an AES-256 key from a passphrase using scrypt.
 * @param {string} passphrase
 * @param {Buffer} salt 16 random bytes (store it in the manifest, it is not secret)
 * @param {object} [params]
 */
export async function deriveKey(passphrase, salt, params = KDF) {
  if (!passphrase) throw new Error('A passphrase is required to derive a key');
  return scryptAsync(Buffer.from(passphrase, 'utf8'), salt, 32, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  });
}

export function newSalt() {
  return randomBytes(SALT_BYTES);
}

/**
 * Encrypt one block: output layout is nonce(12) || tag(16) || ciphertext.
 * The AAD binds the block to its vault id + index so blocks cannot be
 * reordered or replayed from a different upload.
 *
 * @param {Buffer} plaintext
 * @param {Buffer} key 32 bytes
 * @param {Buffer} aad additional authenticated data
 */
export function encryptBlock(plaintext, key, aad) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, tag, ciphertext]);
}

/**
 * Decrypt one block written by {@link encryptBlock}. Any tampering with the
 * ciphertext, tag, nonce or AAD raises an authentication error.
 *
 * @param {Buffer} blob nonce || tag || ciphertext
 * @param {Buffer} key
 * @param {Buffer} aad
 */
export function decryptBlock(blob, key, aad) {
  if (blob.length < NONCE_BYTES + TAG_BYTES) throw new Error('Block too short to be a valid encrypted block');
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
  const ciphertext = blob.subarray(NONCE_BYTES + TAG_BYTES);
  const decipher = createDecipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Build the AAD that ties a block to its position in the vault.
 * @param {string} vaultId
 * @param {number} index
 */
export function blockAAD(vaultId, index) {
  return Buffer.from(`cbv1:${vaultId}:${index}`, 'utf8');
}
