#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mergeSegments, parseSize, splitFile, DEFAULT_BLOCK_SIZE } from './blockify.js';
import { createStore } from './storage/index.js';
import { downloadVault, listVaults, restoreEncryptedDir, uploadFile, verifyVault } from './vault.js';
import { serveSite } from './site-server.js';

const USAGE = `cloud-block-vault — split, encrypt, upload and download files as blocks

Usage: node src/cli.js <command> [options]

Segmentation (local):
  split <file> [--block-size 4m] [--out dir]        split a file into segments
  merge <segDir> [-o file]                          reassemble segments

Cloud operations (backend: local store by default, or Amazon S3):
  upload <file> [--id name] [--block-size 4m]       encrypt block-by-block and upload
                 [--backend local|s3] [--root dir] [--bucket b] [--region r]
                 [--prefix p] [--endpoint url] [--passphrase secret]
  download <id> [-o file] [--keep-encrypted]        download and decrypt, or keep
                 [same backend flags as upload]     ciphertext as stored in the cloud
  restore <encDir> [-o file] [--passphrase secret]  decrypt a vault downloaded
                                                    with --keep-encrypted
  list [--backend ...]                              list vaults
  verify <id> [--passphrase secret] [backend flags] verify stored checksums (+ decrypt)

  serve-site [--port 4173]                          serve the docs site locally

Environment (S3): CBV_BACKEND, CBV_BUCKET, CBV_REGION, CBV_PREFIX, CBV_ENDPOINT,
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.
Passphrase: --passphrase or CBV_PASSPHRASE.
`;

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const name = token.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        args.flags[name] = next;
        i += 1;
      } else {
        args.flags[name] = true;
      }
    } else if (token.startsWith('-') && token.length === 2) {
      const name = { o: 'out', p: 'port' }[token[1]] || token[1];
      args.flags[name] = argv[++i];
    } else {
      args._.push(token);
    }
  }
  return args;
}

function storeFromFlags(flags) {
  return createStore({
    backend: flags.backend,
    root: flags.root,
    bucket: flags.bucket,
    region: flags.region,
    prefix: flags.prefix,
    endpoint: flags.endpoint,
  });
}

function passphraseFrom(flags) {
  return flags.passphrase || process.env.CBV_PASSPHRASE;
}

function human(bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);

  switch (command) {
    case 'split': {
      const file = args._[0];
      if (!file) throw new Error('Usage: split <file> [--block-size 4m] [--out dir]');
      const out = args.flags.out || `${file}.segments`;
      const blockSize = parseSize(args.flags['block-size'] || DEFAULT_BLOCK_SIZE);
      const result = await splitFile(resolve(file), out, blockSize);
      console.log(`Split ${file} (${human(result.size)}) into ${result.blockCount} segment(s) of ${human(blockSize)} in ${out}`);
      console.log(`sha256: ${result.sha256}`);
      break;
    }
    case 'merge': {
      const segDir = args._[0];
      if (!segDir) throw new Error('Usage: merge <segDir> [-o file]');
      const out = args.flags.out || 'reassembled.bin';
      const result = await mergeSegments(segDir, out);
      console.log(`Reassembled ${human(result.size)} into ${out}`);
      console.log(`sha256: ${result.sha256}`);
      break;
    }
    case 'upload': {
      const file = args._[0];
      if (!file) throw new Error('Usage: upload <file> [options]');
      const passphrase = passphraseFrom(args.flags);
      if (!passphrase) throw new Error('Provide a passphrase via --passphrase or CBV_PASSPHRASE');
      const store = storeFromFlags(args.flags);
      const manifest = await uploadFile(store, resolve(file), {
        id: args.flags.id,
        passphrase,
        blockSize: parseSize(args.flags['block-size'] || DEFAULT_BLOCK_SIZE),
      });
      console.log(`Uploaded vault "${manifest.id}" to ${store.name} (${manifest.blockCount} encrypted block(s), ${human(manifest.size)} plaintext)`);
      console.log(`file sha256: ${manifest.sha256}`);
      console.log(`download with: node src/cli.js download ${manifest.id} --backend ${store.name}${store.name === 's3' ? ` --bucket ${store.bucket} --region ${store.region}` : ''}`);
      break;
    }
    case 'download': {
      const id = args._[0];
      if (!id) throw new Error('Usage: download <id> [-o file] [--keep-encrypted]');
      const store = storeFromFlags(args.flags);
      const keepEncrypted = Boolean(args.flags['keep-encrypted']);
      if (!keepEncrypted && !passphraseFrom(args.flags)) {
        throw new Error('Provide a passphrase via --passphrase or CBV_PASSPHRASE (or use --keep-encrypted)');
      }
      const result = await downloadVault(store, id, {
        outFile: args.flags.out,
        passphrase: passphraseFrom(args.flags),
        keepEncrypted,
      });
      if (result.decrypted) {
        console.log(`Downloaded and decrypted "${result.filename}" (${human(result.size)}, ${result.blockCount} blocks) -> ${result.outFile}`);
        console.log(`sha256: verified against manifest`);
      } else {
        console.log(`Downloaded ${result.blockCount} encrypted block(s) + manifest -> ${result.outFile}/`);
        console.log(`Ciphertext left as stored in the cloud; decrypt later with the same command without --keep-encrypted`);
      }
      break;
    }
    case 'restore': {
      const encDir = args._[0];
      if (!encDir) throw new Error('Usage: restore <encDir> [-o file]');
      const passphrase = passphraseFrom(args.flags);
      if (!passphrase) throw new Error('Provide a passphrase via --passphrase or CBV_PASSPHRASE');
      const result = await restoreEncryptedDir(encDir, { outFile: args.flags.out, passphrase });
      console.log(`Restored "${result.filename}" (${human(result.size)}) -> ${result.outFile}`);
      break;
    }
    case 'list': {
      const store = storeFromFlags(args.flags);
      const vaults = await listVaults(store);
      if (!vaults.length) {
        console.log(`No vaults in ${store.name} store`);
        break;
      }
      for (const v of vaults) {
        console.log(`${v.id}\t${human(v.size)}\t${v.blockCount} blocks\t${v.filename}\t${v.createdAt}`);
      }
      break;
    }
    case 'verify': {
      const id = args._[0];
      if (!id) throw new Error('Usage: verify <id> [--passphrase secret]');
      const store = storeFromFlags(args.flags);
      const result = await verifyVault(store, id, { passphrase: passphraseFrom(args.flags) });
      console.log(`Vault "${result.id}": ${result.blockCount} block(s), stored checksums OK${result.decrypted ? ', GCM authentication + file checksum OK' : ' (checksums only; pass --passphrase to also decrypt)'}`);
      break;
    }
    case 'serve-site': {
      const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'site');
      const port = Number(args.flags.port || 4173);
      const server = await serveSite(root, { port });
      const addr = server.address();
      console.log(`Docs site: http://localhost:${addr.port}/ (serving ${root})`);
      break;
    }
    case 'help':
    case undefined:
      console.log(USAGE);
      break;
    default:
      throw new Error(`Unknown command "${command}"\n\n${USAGE}`);
  }
}

main().catch((err) => {
  console.error(`error: ${err.message}`);
  process.exitCode = 1;
});
