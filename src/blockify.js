import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, mkdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';

export const DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024; // 4 MiB

/**
 * Parse human-friendly sizes like "4m", "512k", "1048576".
 * @param {string|number} value
 * @returns {number} size in bytes
 */
export function parseSize(value) {
  if (typeof value === 'number') return value;
  const match = /^(\d+(?:\.\d+)?)\s*(k|m|g|kb|mb|gb)?$/i.exec(String(value).trim());
  if (!match) throw new Error(`Invalid size: ${value} (use e.g. 4m, 512k, 1048576)`);
  const n = Number(match[1]);
  const unit = (match[2] || '').toLowerCase();
  const factor = { '': 1, k: 1024, kb: 1024, m: 1024 ** 2, mb: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3 }[unit];
  return Math.round(n * factor);
}

/**
 * Split a file into fixed-size segments (the last one may be smaller).
 * Each segment is streamed to disk and hashed while being written.
 *
 * @param {string} filePath source file
 * @param {string} outDir directory that receives the segments
 * @param {number} [blockSize]
 * @returns {Promise<{blockSize: number, blockCount: number, size: number, sha256: string, blocks: Array<{index:number, name:string, size:number, sha256:string}>}>}
 */
export async function splitFile(filePath, outDir, blockSize = DEFAULT_BLOCK_SIZE) {
  if (blockSize <= 0) throw new Error('blockSize must be positive');
  const info = await stat(filePath);
  if (!info.isFile()) throw new Error(`Not a regular file: ${filePath}`);

  await mkdir(join(outDir, 'blocks'), { recursive: true });
  const fileHash = createHash('sha256');
  const blocks = [];
  let index = 0;

  const handle = await open(filePath, 'r');
  try {
    const buffer = Buffer.allocUnsafe(Math.min(blockSize, 1024 * 1024)); // 1 MiB streaming window
    let position = 0;
    while (position < info.size) {
      const blockHash = createHash('sha256');
      let written = 0;
      const blockName = `blocks/${String(index).padStart(6, '0')}.blk`;
      const out = createWriteStream(join(outDir, blockName));
      try {
        while (written < blockSize && position < info.size) {
          const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, blockSize - written), position);
          if (bytesRead === 0) break;
          const chunk = buffer.subarray(0, bytesRead);
          if (!out.write(chunk)) {
            await new Promise((resolve, reject) => {
              out.once('drain', resolve);
              out.once('error', reject);
            });
          }
          fileHash.update(chunk);
          blockHash.update(chunk);
          position += bytesRead;
          written += bytesRead;
        }
      } finally {
        await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
        if (out.errored) throw out.errored;
      }
      blocks.push({
        index,
        name: blockName,
        size: written,
        sha256: blockHash.digest('hex'),
      });
      index += 1;
    }
  } finally {
    await handle.close();
  }

  const result = {
    blockSize,
    blockCount: blocks.length,
    size: info.size,
    sha256: fileHash.digest('hex'),
    blocks,
  };
  await writeFile(join(outDir, 'segments.json'), JSON.stringify(result, null, 2));
  return result;
}

/**
 * Reassemble segments produced by {@link splitFile} back into a single file.
 * @param {string} segDir
 * @param {string} outFile
 * @returns {Promise<{size: number, sha256: string}>}
 */
export async function mergeSegments(segDir, outFile) {
  const metaPath = join(segDir, 'segments.json');
  const meta = JSON.parse(await (await open(metaPath)).readFile().catch((err) => {
    throw new Error(`Cannot read ${metaPath}: ${err.message}`);
  }));

  const hash = createHash('sha256');
  let total = 0;
  if (meta.blocks.length === 0) await writeFile(outFile, Buffer.alloc(0));
  for (const block of meta.blocks) {
    const src = join(segDir, block.name);
    const stream = createReadStream(src);
    stream.on('data', (chunk) => {
      hash.update(chunk);
      total += chunk.length;
    });
    await pipeline(stream, createWriteStream(outFile, { flags: total === 0 ? 'w' : 'a' }));
  }

  const digest = hash.digest('hex');
  if (meta.size !== undefined && total !== meta.size) {
    throw new Error(`Size mismatch: expected ${meta.size} bytes, reassembled ${total}`);
  }
  if (meta.sha256 !== undefined && digest !== meta.sha256) {
    throw new Error(`Checksum mismatch: expected ${meta.sha256}, got ${digest}`);
  }
  return { size: total, sha256: digest };
}
