import { LocalStore } from './local.js';
import { S3Store } from './s3.js';

/**
 * Build a storage backend from options + environment.
 * backend: 'local' (default) or 's3'
 */
export function createStore({ backend, root, bucket, region, prefix, endpoint, accessKeyId, secretAccessKey, sessionToken } = {}) {
  const chosen = backend || process.env.CBV_BACKEND || 'local';
  if (chosen === 'local') {
    return new LocalStore({ root: root || process.env.CBV_ROOT || '.store' });
  }
  if (chosen === 's3') {
    return new S3Store({
      bucket: bucket || process.env.CBV_BUCKET,
      region: region || process.env.CBV_REGION || 'us-east-1',
      prefix: prefix ?? process.env.CBV_PREFIX ?? '',
      endpoint: endpoint || process.env.CBV_ENDPOINT,
      credentials: {
        accessKeyId: accessKeyId || process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
        sessionToken: sessionToken || process.env.AWS_SESSION_TOKEN,
      },
    });
  }
  throw new Error(`Unknown backend "${chosen}" (expected "local" or "s3")`);
}
