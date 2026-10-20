import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { open } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { DEFAULT_BLOCK_SIZE } from './blockify.js';
import { blockAAD, decryptBlock, deriveKey, encryptBlock, newSalt } from './cipher.js';
import { buildManifest, parseManifest, serializeManifest, sha256Hex, MANIFEST_VERSION } from './manifest.js';

/**
 * High-level operations on the vault:
 *   upload   — split → encrypt → store every block + the manifest
 *   download — fetch blocks (still encrypted) → authenticate → decrypt → reassemble
 */

function makeId(filename, id) {
  if (id) return id.replace(/^\/+|\/+$/g, '');
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  return `${basename(filename).replace(/[^\w.-]/g, '_')}-${stamp}`;
}

/**
 * Encrypt and upload a file, block by block.
 * @returns {Promise<object>} the manifest
 */
export async function uploadFile(store, filePath, { id, passphrase, blockSize = DEFAULT_BLOCK_SIZE, onProgress } = {}) {
  const salt = newSalt();
  const key = await deriveKey(passphrase, salt);
  const vaultId = makeId(filePath, id);
  const handle = await open(filePath, 'r');
  try {
    const info = await handle.stat();
    const fileHash = createHash('sha256');
    const blocks = [];
    const buffer = Buffer.allocUnsafe(Math.min(blockSize, 1024 * 1024));
    let position = 0;
    let index = 0;

    while (position < info.size) {
      const plain = [];
      let written = 0;
      while (written < blockSize && position < info.size) {
        const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, blockSize - written), position);
        if (bytesRead === 0) break;
        const chunk = Buffer.from(buffer.subarray(0, bytesRead));
        plain.push(chunk);
        fileHash.update(chunk);
        position += bytesRead;
        written += bytesRead;
      }
      const plaintext = Buffer.concat(plain);
      const blob = encryptBlock(plaintext, key, blockAAD(vaultId, index));
      const name = `blocks/${String(index).padStart(6, '0')}.blk`;
      await store.putObject(`${vaultId}/${name}`, blob, 'application/octet-stream');
      blocks.push({ index, name, size: blob.length, sha256: sha256Hex(blob) });
      onProgress?.({ phase: 'upload', index, total: undefined, bytes: written });
      index += 1;
    }

    const manifest = buildManifest({
      id: vaultId,
      filename: basename(filePath),
      size: info.size,
      blockSize,
      sha256: fileHash.digest('hex'),
      salt,
      blocks,
    });
    // Manifest goes last: its presence marks the upload as complete.
    await store.putObject(`${vaultId}/manifest.json`, serializeManifest(manifest), 'application/json');
    return manifest;
  } finally {
    await handle.close();
  }
}

/** Fetch and validate the manifest for a vault id. */
export async function getManifest(store, id) {
  const manifest = parseManifest(await store.getObject(`${id}/manifest.json`));
  if (manifest.version !== MANIFEST_VERSION) throw new Error(`Unsupported manifest version ${manifest.version}`);
  return manifest;
}

/**
 * Download a vault.
 *
 * options.keepEncrypted — write the ciphertext exactly as stored in the cloud
 * (blocks + manifest) without decrypting; demonstrates "download in encrypted form".
 *
 * @returns {Promise<{id, filename, size, blockCount, decrypted: boolean, outFile: string}>}
 */
export async function downloadVault(store, id, { outFile, passphrase, keepEncrypted = false, onProgress } = {}) {
  const manifest = await getManifest(store, id);
  const target = outFile || (keepEncrypted ? `${id}.enc` : manifest.filename);
  const key = keepEncrypted ? undefined : await deriveKey(passphrase, Buffer.from(manifest.kdf.salt, 'hex'), manifest.kdf);

  const encDir = join(target, 'blocks');
  if (keepEncrypted) await mkdir(encDir, { recursive: true });

  const fileHash = createHash('sha256');
  let plaintextBytes = 0;
  const out = keepEncrypted ? null : createWriteStream(target);

  try {
    for (const block of manifest.blocks) {
      const blob = await store.getObject(`${id}/${block.name}`);
      const digest = sha256Hex(blob);
      if (digest !== block.sha256) {
        throw new Error(`Block ${block.index} checksum mismatch (stored ${block.sha256}, got ${digest})`);
      }
      if (keepEncrypted) {
        await writeFile(join(target, block.name), blob);
      } else {
        const plaintext = decryptBlock(blob, key, blockAAD(id, block.index));
        fileHash.update(plaintext);
        plaintextBytes += plaintext.length;
        onProgress?.({ phase: 'download', index: block.index });
        if (!out.write(plaintext)) {
          await new Promise((resolve, reject) => {
            out.once('drain', resolve);
            out.once('error', reject);
          });
        }
      }
    }
  } finally {
    if (out) await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
  }

  if (keepEncrypted) {
    await writeFile(join(target, 'manifest.json'), serializeManifest(manifest));
    return { id, filename: manifest.filename, size: manifest.size, blockCount: manifest.blockCount, decrypted: false, outFile: target };
  }

  const digest = fileHash.digest('hex');
  if (plaintextBytes !== manifest.size) throw new Error(`Size mismatch: expected ${manifest.size}, got ${plaintextBytes}`);
  if (digest !== manifest.sha256) throw new Error(`File checksum mismatch: expected ${manifest.sha256}, got ${digest}`);
  return { id, filename: manifest.filename, size: plaintextBytes, blockCount: manifest.blockCount, decrypted: true, outFile: target };
}

/**
 * Decrypt a vault that was downloaded in encrypted form (see downloadVault
 * with keepEncrypted): reads manifest + ciphertext blocks from a local
 * directory, authenticates them with GCM and writes the original file.
 */
export async function restoreEncryptedDir(encDir, { outFile, passphrase } = {}) {
  const manifest = parseManifest(await open(join(encDir, 'manifest.json')).then((h) => h.readFile()));
  const key = await deriveKey(passphrase, Buffer.from(manifest.kdf.salt, 'hex'), manifest.kdf);
  const target = outFile || manifest.filename;
  const fileHash = createHash('sha256');
  let bytes = 0;
  const out = createWriteStream(target);
  try {
    for (const block of manifest.blocks) {
      const blob = await open(join(encDir, block.name)).then((h) => h.readFile());
      if (sha256Hex(blob) !== block.sha256) throw new Error(`Block ${block.index}: checksum mismatch on disk`);
      const plaintext = decryptBlock(blob, key, blockAAD(manifest.id, block.index));
      fileHash.update(plaintext);
      bytes += plaintext.length;
      if (!out.write(plaintext)) {
        await new Promise((resolve, reject) => {
          out.once('drain', resolve);
          out.once('error', reject);
        });
      }
    }
  } finally {
    await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
  }
  if (bytes !== manifest.size) throw new Error(`Size mismatch: expected ${manifest.size}, got ${bytes}`);
  if (fileHash.digest('hex') !== manifest.sha256) throw new Error('File checksum mismatch after decrypting');
  return { id: manifest.id, filename: manifest.filename, size: bytes, outFile: target };
}

/** List vault ids present in the store. */
export async function listVaults(store) {
  const objects = await store.listObjects('');
  const ids = new Set();
  for (const { key } of objects) {
    if (key.endsWith('/manifest.json')) ids.add(key.slice(0, -'/manifest.json'.length));
  }
  const vaults = [];
  for (const id of [...ids].sort()) {
    const manifest = await getManifest(store, id);
    vaults.push({
      id,
      filename: manifest.filename,
      size: manifest.size,
      blockCount: manifest.blockCount,
      createdAt: manifest.createdAt,
    });
  }
  return vaults;
}

/**
 * Verify a vault end-to-end: every stored block matches the manifest hash and
 * (if a passphrase is given) decrypts and authenticates via GCM.
 */
export async function verifyVault(store, id, { passphrase } = {}) {
  const manifest = await getManifest(store, id);
  const key = passphrase ? await deriveKey(passphrase, Buffer.from(manifest.kdf.salt, 'hex'), manifest.kdf) : undefined;
  const fileHash = createHash('sha256');
  let bytes = 0;
  for (const block of manifest.blocks) {
    const blob = await store.getObject(`${id}/${block.name}`);
    if (sha256Hex(blob) !== block.sha256) throw new Error(`Block ${block.index}: stored checksum mismatch`);
    if (key) {
      const plaintext = decryptBlock(blob, key, blockAAD(id, block.index));
      fileHash.update(plaintext);
      bytes += plaintext.length;
    }
  }
  if (key) {
    if (bytes !== manifest.size) throw new Error(`Size mismatch: expected ${manifest.size}, got ${bytes}`);
    if (fileHash.digest('hex') !== manifest.sha256) throw new Error('Reassembled file checksum mismatch');
  }
  return { id, blockCount: manifest.blockCount, checksumsOk: true, decrypted: Boolean(key), size: manifest.size };
}
