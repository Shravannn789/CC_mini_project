import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { LocalStore } from '../src/storage/local.js';
import { downloadVault, listVaults, restoreEncryptedDir, uploadFile, verifyVault } from '../src/vault.js';

const execFileAsync = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

async function withTmp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'cbv-roundtrip-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('upload -> list -> download -> decrypt round trip on the local store', async () => {
  await withTmp(async (dir) => {
    const data = randomBytes(1.2 * 1024 * 1024);
    const src = join(dir, 'archive.bin');
    await writeFile(src, data);

    const store = new LocalStore({ root: join(dir, 'store') });
    const manifest = await uploadFile(store, src, { id: 'demo', passphrase: 's3cret', blockSize: 256 * 1024 });
    assert.equal(manifest.blockCount, 5);
    assert.equal(manifest.sha256, sha(data));
    assert.equal(manifest.encrypted, true);

    // Stored objects are manifest + one blob per block
    const objects = await store.listObjects('demo/');
    assert.equal(objects.length, manifest.blockCount + 1);

    const vaults = await listVaults(store);
    assert.equal(vaults.length, 1);
    assert.equal(vaults[0].id, 'demo');

    const result = await downloadVault(store, 'demo', { outFile: join(dir, 'restored.bin'), passphrase: 's3cret' });
    assert.equal(result.decrypted, true);
    assert.deepEqual(await readFile(join(dir, 'restored.bin')), data);

    const verified = await verifyVault(store, 'demo', { passphrase: 's3cret' });
    assert.deepEqual(verified, { id: 'demo', blockCount: 5, checksumsOk: true, decrypted: true, size: data.length });
  });
});

test('download in encrypted form keeps ciphertext, restore decrypts it', async () => {
  await withTmp(async (dir) => {
    const data = randomBytes(700 * 1024);
    const src = join(dir, 'notes.txt');
    await writeFile(src, data);
    const store = new LocalStore({ root: join(dir, 'store') });
    await uploadFile(store, src, { id: 'notes', passphrase: 'pw', blockSize: 128 * 1024 });

    const encDir = join(dir, 'notes.enc');
    const dl = await downloadVault(store, 'notes', { outFile: encDir, keepEncrypted: true });
    assert.equal(dl.decrypted, false);

    // The downloaded bytes must be ciphertext, not the original file
    const rawBlock = await readFile(join(encDir, 'blocks', '000000.blk'));
    assert.notDeepEqual(rawBlock, data.subarray(0, rawBlock.length));
    assert.equal(rawBlock.length, 12 + 16 + 128 * 1024);

    const restored = await restoreEncryptedDir(encDir, { outFile: join(dir, 'from-enc.bin'), passphrase: 'pw' });
    assert.equal(restored.size, data.length);
    assert.deepEqual(await readFile(join(dir, 'from-enc.bin')), data);

    await assert.rejects(() => restoreEncryptedDir(encDir, { outFile: join(dir, 'bad.bin'), passphrase: 'nope' }));
  });
});

test('wrong passphrase cannot download-decrypt', async () => {
  await withTmp(async (dir) => {
    const src = join(dir, 'f.bin');
    await writeFile(src, randomBytes(10_000));
    const store = new LocalStore({ root: join(dir, 'store') });
    await uploadFile(store, src, { id: 'f', passphrase: 'right', blockSize: 4096 });
    await assert.rejects(() => downloadVault(store, 'f', { outFile: join(dir, 'x.bin'), passphrase: 'wrong' }));
  });
});

test('CLI end-to-end: upload, list, verify, download, keep-encrypted + restore', async () => {
  await withTmp(async (dir) => {
    const data = randomBytes(900 * 1024);
    const src = join(dir, 'movie.mkv');
    await writeFile(src, data);
    const root = join(dir, 'store');
    const cli = (args, env = {}) =>
      execFileAsync(process.execPath, [join(ROOT, 'src', 'cli.js'), ...args], { env: { ...process.env, ...env } });

    const up = await cli(['upload', src, '--id', 'movie', '--block-size', '300k', '--root', root, '--passphrase', 'pw']);
    assert.match(up.stdout, /Uploaded vault "movie"/);

    const list = await cli(['list', '--root', root]);
    assert.match(list.stdout, /movie\t900 KiB\t3 blocks\tmovie\.mkv/);

    const verify = await cli(['verify', 'movie', '--root', root, '--passphrase', 'pw']);
    assert.match(verify.stdout, /checksums OK/);

    const dl = await cli(['download', 'movie', '-o', join(dir, 'got.mkv'), '--root', root, '--passphrase', 'pw']);
    assert.match(dl.stdout, /Downloaded and decrypted/);
    assert.deepEqual(await readFile(join(dir, 'got.mkv')), data);

    const enc = await cli(['download', 'movie', '--keep-encrypted', '-o', join(dir, 'movie.enc'), '--root', root]);
    assert.match(enc.stdout, /encrypted block\(s\)/);
    const restored = await cli(['restore', join(dir, 'movie.enc'), '-o', join(dir, 'got2.mkv'), '--passphrase', 'pw']);
    assert.match(restored.stdout, /Restored/);
    assert.deepEqual(await readFile(join(dir, 'got2.mkv')), data);

    // CLI exits non-zero on failure
    await assert.rejects(() => cli(['download', 'movie', '-o', join(dir, 'nope'), '--root', root, '--passphrase', 'bad']));
  });
});
