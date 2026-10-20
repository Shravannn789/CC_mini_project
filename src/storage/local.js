import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, normalize, sep } from 'node:path';

export class StorageError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'StorageError';
    this.code = code; // 'NotFound' | 'IO'
  }
}

/**
 * Local object store: emulates the semantics of S3 (put/get/list by key)
 * on the filesystem. Used as the default backend so the whole workflow —
 * split → encrypt → upload → download — runs offline.
 */
export class LocalStore {
  constructor({ root }) {
    if (!root) throw new Error('LocalStore requires a root directory');
    this.root = root;
    this.name = 'local';
  }

  _path(key) {
    const clean = normalize(key).replace(/^([/\\])+/, '');
    if (clean.startsWith('..') || clean.includes(`..${sep}`) || clean.includes('\0')) {
      throw new StorageError(`Unsafe object key: ${key}`, 'IO');
    }
    return join(this.root, clean);
  }

  async putObject(key, body, _contentType = 'application/octet-stream') {
    const path = this._path(key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, body);
  }

  async getObject(key) {
    try {
      return await readFile(this._path(key));
    } catch (err) {
      if (err.code === 'ENOENT') throw new StorageError(`Object not found: ${key}`, 'NotFound');
      throw new StorageError(`Cannot read ${key}: ${err.message}`, 'IO');
    }
  }

  async listObjects(prefix = '') {
    const base = this.root;
    const keys = [];
    async function walk(dir) {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (err) {
        if (err.code === 'ENOENT') return;
        throw err;
      }
      for (const entry of entries) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) await walk(full);
        else keys.push(full.slice(base.length + 1).split(sep).join('/'));
      }
    }
    await walk(base);
    const filtered = keys.filter((k) => k.startsWith(prefix)).sort();
    const out = [];
    for (const key of filtered) {
      const st = await readFile(join(base, key));
      out.push({ key, size: st.length });
    }
    return out;
  }

  async deleteObject(key) {
    await rm(this._path(key), { force: true });
  }
}
