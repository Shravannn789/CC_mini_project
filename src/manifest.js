import { createHash } from 'node:crypto';

export const MANIFEST_VERSION = 1;

/**
 * Build the manifest that describes one encrypted upload.
 * The manifest is stored alongside the blocks (one JSON object in the bucket).
 *
 * @param {object} input
 * @param {string} input.id vault id (object prefix)
 * @param {string} input.filename original file name
 * @param {number} input.size plaintext size in bytes
 * @param {number} input.blockSize
 * @param {string} input.sha256 hex digest of the plaintext file
 * @param {Buffer} input.salt KDF salt
 * @param {Array<{index:number,name:string,size:number,sha256:string}>} input.blocks
 */
export function buildManifest({ id, filename, size, blockSize, sha256, salt, blocks }) {
  return {
    version: MANIFEST_VERSION,
    id,
    filename,
    size,
    blockSize,
    blockCount: blocks.length,
    sha256,
    encrypted: true,
    cipher: 'aes-256-gcm',
    kdf: { name: 'scrypt', salt: salt.toString('hex'), N: 16384, r: 8, p: 1 },
    createdAt: new Date().toISOString(),
    blocks,
  };
}

export function serializeManifest(manifest) {
  return Buffer.from(JSON.stringify(manifest, null, 2), 'utf8');
}

export function parseManifest(buffer) {
  let manifest;
  try {
    manifest = JSON.parse(Buffer.isBuffer(buffer) ? buffer.toString('utf8') : buffer);
  } catch (err) {
    throw new Error(`Manifest is not valid JSON: ${err.message}`);
  }
  if (manifest.version !== MANIFEST_VERSION) {
    throw new Error(`Unsupported manifest version: ${manifest.version}`);
  }
  for (const key of ['id', 'sha256', 'blockSize', 'blocks', 'kdf']) {
    if (manifest[key] === undefined) throw new Error(`Manifest is missing required field: ${key}`);
  }
  if (!Buffer.from(manifest.kdf.salt, 'hex').length) throw new Error('Manifest has no KDF salt');
  return manifest;
}

export function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}
