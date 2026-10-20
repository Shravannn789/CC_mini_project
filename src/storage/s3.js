import { signRequest, uriEncode } from '../sigv4.js';
import { StorageError } from './local.js';

/**
 * Amazon S3 backend using the REST API directly with Signature Version 4 —
 * no SDK, no dependencies. Works against AWS S3 and against any S3-compatible
 * endpoint (MinIO, Ceph RGW, R2, ...) via the `endpoint` option (path-style).
 */
export class S3Store {
  constructor({ bucket, region = 'us-east-1', prefix = '', endpoint, credentials }) {
    if (!bucket) throw new Error('S3Store requires a bucket (set --bucket or CBV_BUCKET)');
    if (!credentials?.accessKeyId || !credentials?.secretAccessKey) {
      throw new Error('S3Store requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
    }
    this.bucket = bucket;
    this.region = region;
    this.prefix = prefix ? prefix.replace(/^\/+|\/+$/g, '') + '/' : '';
    this.credentials = credentials;
    this.name = 's3';

    if (endpoint) {
      // Path-style against a custom endpoint (MinIO etc.)
      const base = endpoint.replace(/\/+$/, '');
      this.baseUrl = `${base}/${bucket}`;
      this.virtualHost = false;
    } else {
      const host = region === 'us-east-1' ? `${bucket}.s3.amazonaws.com` : `${bucket}.s3.${region}.amazonaws.com`;
      this.baseUrl = `https://${host}`;
      this.virtualHost = true;
    }
  }

  _key(key) {
    return this.prefix + key;
  }

  _url(key, query = {}) {
    const encodedKey = this._key(key)
      .split('/')
      .map((part) => uriEncode(part))
      .join('/');
    const url = new URL(this.baseUrl + (key ? '/' + encodedKey : '/'));
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
    return url;
  }

  async _request(method, key, { body, query, headers = {} } = {}) {
    const url = this._url(key, query);
    const signed = signRequest({
      method,
      url,
      body,
      headers,
      credentials: this.credentials,
      region: this.region,
      service: 's3',
    });

    const response = await fetch(url, { method, headers: signed.headers, body: method === 'GET' ? undefined : body });
    if (response.status === 404) {
      throw new StorageError(`Object not found: s3://${this.bucket}/${this._key(key)}`, 'NotFound');
    }
    if (!response.ok) {
      const text = (await response.text()).slice(0, 500);
      throw new StorageError(`S3 ${method} ${this._key(key)} failed: HTTP ${response.status} ${text}`, 'IO');
    }
    return response;
  }

  async putObject(key, body, contentType = 'application/octet-stream') {
    await this._request('PUT', key, { body, headers: { 'content-type': contentType } });
  }

  async getObject(key) {
    const response = await this._request('GET', key);
    return Buffer.from(await response.arrayBuffer());
  }

  /** List object keys under a prefix (ListObjectsV2, XML parsed without deps). */
  async listObjects(prefix = '') {
    const keys = [];
    let token;
    do {
      const query = { 'list-type': '2', prefix: this._key(prefix) };
      if (token) query['continuation-token'] = token;
      const response = await this._request('GET', '', { query });
      const xml = await response.text();
      for (const match of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
        const chunk = match[1];
        const key = /<Key>([\s\S]*?)<\/Key>/.exec(chunk)?.[1];
        const size = Number(/<Size>(\d+)<\/Size>/.exec(chunk)?.[1] ?? 0);
        if (key) keys.push({ key, size });
      }
      token = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)?.[1];
      if (token) token = decodeXml(token);
    } while (token);
    return keys;
  }

  async deleteObject(key) {
    await this._request('DELETE', key);
  }
}

function decodeXml(value) {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}
