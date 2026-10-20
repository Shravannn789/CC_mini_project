# Cloud Block Vault

A **Cloud Computing mini project**: split any file into segments/blocks, encrypt every block,
upload them to object storage (Amazon S3 or a local S3-like store), and download the file back
from the cloud in encrypted form — then decrypt and reassemble it byte-for-byte.

It also ships with a static **portfolio / documentation site** (in [`site/`](site/)) and scripts to
host it on **Amazon S3 behind CloudFront** with HTTPS, so the project covers the full path:
*segmentation → encryption → object storage → CDN → HTTPS*.

**Zero runtime dependencies** — only the Node.js standard library (v20+). The S3 client signs
requests with an **AWS Signature Version 4** implementation written from the specification and
verified against AWS's own published worked example.

---

## Features

| Operation | Command | Description |
|---|---|---|
| Segmentation | `split` | Streams a file into fixed-size segments (default 4 MiB) + a `segments.json` with per-block SHA-256 checksums. |
| Reassembly | `merge` | Joins the segments back and verifies size + checksum. |
| Encrypted upload | `upload` | Split → AES-256-GCM encrypt each block → upload blocks + manifest to the store. |
| Download | `download` | Fetches the blocks, verifies checksums, decrypts and reassembles the original file. |
| Download in encrypted form | `download --keep-encrypted` | Pulls the ciphertext exactly as stored in the cloud, without decrypting. |
| Restore | `restore` | Decrypts a locally downloaded encrypted vault back into the original file. |
| Inventory | `list` | Lists vaults (id, size, block count, filename, date). |
| Integrity check | `verify` | Verifies stored checksums; with a passphrase also decrypts and authenticates every block. |

## Quickstart

Requires Node.js 20 or newer. No `npm install` needed — there are no dependencies.

```bash
# 1. Split a file into segments locally
node src/cli.js split bigfile.bin --block-size 4m

# 2. Encrypt + upload (local store by default — same semantics as S3, runs offline)
export CBV_PASSPHRASE="your-strong-passphrase"
node src/cli.js upload bigfile.bin --id demo

# 3. Download it back and verify the round trip
node src/cli.js download demo -o bigfile-restored.bin
sha256sum bigfile.bin bigfile-restored.bin   # identical

# 4. Or download the ciphertext only, and decrypt later
node src/cli.js download demo --keep-encrypted -o demo.enc
node src/cli.js restore demo.enc -o bigfile-restored.bin
```

### Using real Amazon S3

```bash
export CBV_BACKEND=s3
export CBV_BUCKET=my-vault-bucket        # must exist
export CBV_REGION=us-east-1
export CBV_PREFIX=optional/key/prefix
export AWS_ACCESS_KEY_ID=...             # IAM user with s3:GetObject/PutObject/ListBucket on the prefix
export AWS_SECRET_ACCESS_KEY=...
export CBV_PASSPHRASE=...

node src/cli.js upload bigfile.bin
node src/cli.js list
node src/cli.js download bigfile.bin-20261020T120000 -o restored.bin
```

S3-compatible endpoints (MinIO, Ceph RGW, Cloudflare R2, …) work with `--endpoint http://localhost:9000`
or `CBV_ENDPOINT` — requests switch to path-style and are still SigV4-signed.

Every flag also exists as a CLI option: `--backend s3 --bucket … --region … --prefix … --passphrase …`.

## How it works

```
file ──split──▶ blocks[0..n] ──encrypt──▶ ciphertext blocks ──upload──▶ object storage
                                                                          (manifest.json last)
download ◀── decrypt + authenticate ◀── fetch + checksum ◀──────────────┘
   │
   └──▶ original file, verified against the manifest SHA-256
```

* **Segmentation** — the file is streamed in fixed-size blocks (a 1 MiB window is reused, so
  memory stays flat regardless of file size). Each block gets its own SHA-256 checksum.
* **Encryption** — every block is encrypted with **AES-256-GCM** using a fresh random 12-byte
  nonce. The key comes from **scrypt** (N=16384, r=8, p=1) over your passphrase with a random
  16-byte salt stored in the manifest. The block layout on disk/in the bucket is
  `nonce(12) ‖ tag(16) ‖ ciphertext`.
* **Block binding** — the vault id and the block index are passed to GCM as *additional
  authenticated data* (AAD), so blocks cannot be reordered, duplicated, or replayed from another
  vault without failing authentication.
* **Manifest** — a small JSON object per vault (`<id>/manifest.json`) records the original
  filename, size, block size, whole-file SHA-256, KDF parameters + salt, and every block's name,
  size and checksum. It is written **last**, so its presence marks a completed upload.
* **Download** — each fetched block is checksummed, then decrypted and authenticated (GCM tag);
  the reassembled file is verified against the manifest's SHA-256 before you get it.

### Storage abstraction

`src/storage/` defines a tiny object-store interface (`putObject`, `getObject`, `listObjects`,
`deleteObject`) with two backends:

* **local** — the same semantics on the filesystem (default, offline, used by the tests).
* **s3** — the S3 REST API signed with Signature Version 4 implemented in `src/sigv4.js`
  (canonical request → string to sign → derived signing key → HMAC-SHA256 signature).
  `test/sigv4.test.js` asserts the signer reproduces the exact signature from the
  [AWS S3 SigV4 documentation example](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html).

## Hosting the docs site on S3 + CloudFront

The site in [`site/`](site/) is static HTML/CSS (portfolio + full documentation). To put it behind
a CDN with HTTPS:

```bash
export AWS_REGION=us-east-1
export SITE_BUCKET=my-portfolio-site-12345   # globally unique
./infra/deploy-site.sh
# → prints https://dxxxx.cloudfront.net (first deploy ~5 minutes)

./infra/invalidate.sh <distribution-id>      # after re-uploading content
```

The script (`infra/deploy-site.sh`) does the following, using only the AWS CLI:

1. creates the bucket (if missing) and **blocks all public access**;
2. syncs `site/` into it;
3. creates a **CloudFront Origin Access Control** (SigV4 between CloudFront and S3);
4. creates the distribution with `ViewerProtocolPolicy: redirect-to-https` (HTTP → HTTPS),
   the managed `CachingOptimized` cache policy, compression and HTTP/2+3;
5. attaches a bucket policy that allows **only that distribution** to `s3:GetObject`.

Why a CDN: CloudFront caches the site at edge locations close to visitors (lower latency),
terminates TLS and enforces HTTPS, hides the bucket behind OAC (the origin stays fully private),
and invalidations propagate fresh content globally in minutes.

Preview the site locally first with `npm run serve-site` → http://localhost:4173/

## Tests

```bash
npm test        # 19 tests, node:test, no dependencies
```

Covers: segmentation round trips (multi-block, sub-block, empty, tampered), GCM round trips and
failure modes (wrong passphrase, tampered ciphertext/tag/nonce, reordered/replayed blocks),
upload → list → download → decrypt round trips, the encrypted-download + restore path, a CLI
end-to-end run, and the SigV4 signer against the official AWS worked example.

## Project layout

```
src/
  cli.js            CLI: split, merge, upload, download, restore, list, verify, serve-site
  blockify.js       streamed segmentation + verified merge
  cipher.js         AES-256-GCM and scrypt key derivation
  manifest.js       manifest schema, parse/serialize
  vault.js          upload / download / restore / verify operations
  sigv4.js          AWS Signature Version 4 signer
  storage/          local (S3-like) and s3 (REST + SigV4) backends
  site-server.js    tiny static file server for local preview
test/               node:test suites
site/               static portfolio + documentation site
infra/              deploy-site.sh (S3 + CloudFront), invalidate.sh
```

## Security notes

* The passphrase never leaves your machine and is never stored; only the salt and public
  metadata go into the manifest.
* Use `CBV_PASSPHRASE` (env) rather than `--passphrase` on shared machines — flags are visible in
  process listings.
* Store the AWS credentials for the S3 backend with least privilege (`s3:GetObject`,
  `s3:PutObject`, `s3:ListBucket` on your prefix) — the bucket can hold ciphertext only, since
  decryption needs the passphrase.
* HTTPS in transit is provided by the transport: `https://` endpoints for S3 (SigV4-signed) and
  CloudFront's TLS for the website.

MIT License.
