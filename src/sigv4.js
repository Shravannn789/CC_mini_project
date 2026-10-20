import { createHash, createHmac } from 'node:crypto';

/**
 * Minimal AWS Signature Version 4 implementation (no dependencies).
 * Spec: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-request.html
 */

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/** RFC 3986 percent-encoding, used by SigV4 canonical URIs/queries. */
export function uriEncode(value, encodeSlash = true) {
  return Buffer.from(String(value), 'utf8')
    .toString('binary')
    .replace(/[^A-Za-z0-9\-._~]/g, (ch) => {
      if (ch === '/' && !encodeSlash) return ch;
      return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
    });
}

function canonicalHeaders(headers) {
  const names = Object.keys(headers)
    .map((n) => n.toLowerCase())
    .sort();
  const lines = names.map((name) => {
    const raw = headers[name] ?? headers[Object.keys(headers).find((k) => k.toLowerCase() === name)];
    const value = String(raw).trim().replace(/\s+/g, ' ');
    return `${name}:${value}`;
  });
  return { signedHeaders: names.join(';'), canonicalHeaderString: lines.join('\n') + '\n' };
}

export function canonicalRequest({ method, path, query = {}, headers, payloadHash }) {
  const { signedHeaders, canonicalHeaderString } = canonicalHeaders(headers);
  const search = new URLSearchParams();
  for (const key of Object.keys(query).sort()) {
    if (query[key] === undefined || query[key] === null) continue;
    search.append(uriEncode(key), uriEncode(String(query[key])));
  }
  // URLSearchParams encodes space as '+', SigV4 requires %20
  const canonicalQueryString = search.toString().replace(/\+/g, '%20');

  return {
    value: [
      method.toUpperCase(),
      uriEncode(path, false),
      canonicalQueryString,
      canonicalHeaderString,
      signedHeaders,
      payloadHash,
    ].join('\n'),
    signedHeaders,
  };
}

export function stringToSign(amzDate, scope, canonicalRequestString) {
  return ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequestString)].join('\n');
}

export function signingKey(secret, dateStamp, region, service) {
  const kDate = createHmac('sha256', 'AWS4' + secret).update(dateStamp).digest();
  const kRegion = createHmac('sha256', kDate).update(region).digest();
  const kService = createHmac('sha256', kRegion).update(service).digest();
  return createHmac('sha256', kService).update('aws4_request').digest();
}

/**
 * Sign a request and return the headers to send.
 *
 * @param {object} input
 * @param {string} input.method
 * @param {URL} input.url
 * @param {Record<string,string>} [input.headers] extra headers (host is added)
 * @param {Buffer|string} [input.body]
 * @param {{accessKeyId:string, secretAccessKey:string, sessionToken?:string}} input.credentials
 * @param {string} input.region
 * @param {string} input.service default "s3"
 * @param {Date} [input.now] injectable clock (tests)
 */
export function signRequest({ method, url, headers = {}, body, credentials, region, service = 's3', now = new Date() }) {
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body ?? '');

  const allHeaders = {
    host: url.host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
  };
  if (credentials.sessionToken) allHeaders['x-amz-security-token'] = credentials.sessionToken;

  const { value: canonical, signedHeaders } = canonicalRequest({
    method,
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    headers: allHeaders,
    payloadHash,
  });
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const toSign = stringToSign(amzDate, scope, canonical);
  const signature = createHmac('sha256', signingKey(credentials.secretAccessKey, dateStamp, region, service))
    .update(toSign)
    .digest('hex');

  allHeaders.authorization =
    `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: allHeaders, canonicalRequest: canonical, stringToSign: toSign, signature };
}

export { EMPTY_SHA256 };
