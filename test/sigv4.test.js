import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalRequest, sha256Hex, signRequest, signingKey, stringToSign, uriEncode } from '../src/sigv4.js';

// Official worked example from the AWS S3 docs:
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
// GET /test.txt with a Range header, signed for 2013-05-24T00:00:00Z.
const AK = 'AKIAIOSFODNN7EXAMPLE';
const SK = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const EXPECTED_CANONICAL = [
  'GET',
  '/test.txt',
  '',
  'host:examplebucket.s3.amazonaws.com',
  'range:bytes=0-9',
  'x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'x-amz-date:20130524T000000Z',
  '', // CanonicalHeaders ends with a newline, then the spec adds another before SignedHeaders
  'host;range;x-amz-content-sha256;x-amz-date',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
].join('\n');

const EXPECTED_STRING_TO_SIGN = [
  'AWS4-HMAC-SHA256',
  '20130524T000000Z',
  '20130524/us-east-1/s3/aws4_request',
  '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972',
].join('\n');

const EXPECTED_SIGNATURE = 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41';

test('canonical request and string to sign match the AWS worked example', () => {
  const url = new URL('https://examplebucket.s3.amazonaws.com/test.txt');
  const { value, signedHeaders } = canonicalRequest({
    method: 'GET',
    path: url.pathname,
    headers: {
      host: url.host,
      range: 'bytes=0-9',
      'x-amz-content-sha256': sha256Hex(''),
      'x-amz-date': '20130524T000000Z',
    },
    payloadHash: sha256Hex(''),
  });
  assert.equal(value, EXPECTED_CANONICAL);
  assert.equal(signedHeaders, 'host;range;x-amz-content-sha256;x-amz-date');
  assert.equal(stringToSign('20130524T000000Z', '20130524/us-east-1/s3/aws4_request', value), EXPECTED_STRING_TO_SIGN);
});

test('final signature matches the AWS worked example', () => {
  const url = new URL('https://examplebucket.s3.amazonaws.com/test.txt');
  const { signature, headers } = signRequest({
    method: 'GET',
    url,
    headers: { range: 'bytes=0-9' },
    credentials: { accessKeyId: AK, secretAccessKey: SK },
    region: 'us-east-1',
    service: 's3',
    now: new Date('2013-05-24T00:00:00Z'),
  });
  assert.equal(signature, EXPECTED_SIGNATURE);
  assert.equal(
    headers.authorization,
    `AWS4-HMAC-SHA256 Credential=${AK}/20130524/us-east-1/s3/aws4_request, ` +
      'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, ' +
      `Signature=${EXPECTED_SIGNATURE}`,
  );
});

test('signing key derivation is deterministic and secret-dependent', () => {
  const key = signingKey(SK, '20130524', 'us-east-1', 's3');
  assert.equal(key.length, 32);
  assert.deepEqual(key, signingKey(SK, '20130524', 'us-east-1', 's3'));
  assert.notDeepEqual(key, signingKey(SK, '20130524', 'eu-west-1', 's3'));
  assert.notDeepEqual(key, signingKey('other', '20130524', 'us-east-1', 's3'));
});

test('uriEncode follows RFC 3986 and preserves slashes when asked', () => {
  assert.equal(uriEncode('a b/c~d'), 'a%20b%2Fc~d');
  assert.equal(uriEncode('a b/c~d', false), 'a%20b/c~d');
  assert.equal(uriEncode('é'), '%C3%A9');
});

test('session token is added as a signed header when present', () => {
  const url = new URL('https://bucket.s3.us-west-2.amazonaws.com/k');
  const { headers } = signRequest({
    method: 'PUT',
    url,
    body: Buffer.from('hello'),
    credentials: { accessKeyId: AK, secretAccessKey: SK, sessionToken: 'TOKEN' },
    region: 'us-west-2',
    now: new Date('2020-01-01T00:00:00Z'),
  });
  assert.equal(headers['x-amz-security-token'], 'TOKEN');
  assert.match(headers.authorization, /SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token/);
});
