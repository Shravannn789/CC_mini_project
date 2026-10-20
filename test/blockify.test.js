import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { mergeSegments, parseSize, splitFile } from '../src/blockify.js';

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

async function withTmp(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'cbv-blockify-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('parseSize understands human units', () => {
  assert.equal(parseSize('4m'), 4 * 1024 * 1024);
  assert.equal(parseSize('512k'), 512 * 1024);
  assert.equal(parseSize('1048576'), 1048576);
  assert.equal(parseSize(42), 42);
  assert.throws(() => parseSize('banana'));
});

test('split + merge round trip (multiple full blocks + remainder)', async () => {
  await withTmp(async (dir) => {
    const data = randomBytes(2.5 * 1024 * 1024);
    const src = join(dir, 'video.mp4');
    const { writeFile } = await import('node:fs/promises');
    await writeFile(src, data);

    const segDir = join(dir, 'segments');
    const result = await splitFile(src, segDir, 1024 * 1024);
    assert.equal(result.blockCount, 3);
    assert.equal(result.size, data.length);
    assert.equal(result.sha256, sha(data));
    assert.deepEqual(
      result.blocks.map((b) => b.size),
      [1024 * 1024, 1024 * 1024, 512 * 1024],
    );

    const out = join(dir, 'out.mp4');
    const merged = await mergeSegments(segDir, out);
    assert.equal(merged.sha256, sha(data));
    const { readFile } = await import('node:fs/promises');
    assert.deepEqual(await readFile(out), data);
  });
});

test('split works for a file smaller than one block and for an empty file', async () => {
  await withTmp(async (dir) => {
    const { writeFile, readFile } = await import('node:fs/promises');
    const small = join(dir, 'small.txt');
    await writeFile(small, 'hello blocks');
    const r1 = await splitFile(small, join(dir, 'seg-small'), 1024);
    assert.equal(r1.blockCount, 1);
    const merged = await mergeSegments(join(dir, 'seg-small'), join(dir, 'small.out'));
    assert.equal(merged.size, 'hello blocks'.length);
    assert.equal((await readFile(join(dir, 'small.out'))).toString(), 'hello blocks');

    const empty = join(dir, 'empty.bin');
    await writeFile(empty, Buffer.alloc(0));
    const r2 = await splitFile(empty, join(dir, 'seg-empty'), 1024);
    assert.equal(r2.blockCount, 0);
    assert.equal(r2.size, 0);
    await mergeSegments(join(dir, 'seg-empty'), join(dir, 'empty.out'));
    assert.equal((await stat(join(dir, 'empty.out'))).size, 0);
  });
});

test('merge detects a tampered segment', async () => {
  await withTmp(async (dir) => {
    const { writeFile, readFile } = await import('node:fs/promises');
    const src = join(dir, 'doc.pdf');
    await writeFile(src, randomBytes(100 * 1024));
    const segDir = join(dir, 'segments');
    await splitFile(src, segDir, 32 * 1024);

    const blockPath = join(segDir, 'blocks', '000001.blk');
    const blob = await readFile(blockPath);
    blob[10] ^= 0xff;
    await writeFile(blockPath, blob);

    await assert.rejects(() => mergeSegments(segDir, join(dir, 'out.pdf')), /checksum mismatch|Checksum mismatch/i);
  });
});
