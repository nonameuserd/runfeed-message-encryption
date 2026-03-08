/**
 * Metadata-reducing padding for E2EE payloads.
 * Pads ciphertext to fixed size buckets so the server cannot infer message length.
 * Format: 2-byte big-endian original length || UTF-8 payload || random bytes to bucket.
 */

const PADDED_PREFIX = 'e2ee-pad1:';

const BUCKETS = [256, 512, 1024, 2048, 4096, 8192] as const;
const MAX_BUCKET: number = BUCKETS[BUCKETS.length - 1] ?? 8192;

function nextBucket(size: number): number {
  for (const b of BUCKETS) {
    if (b >= size) return b;
  }
  return Math.max(MAX_BUCKET, size);
}

function b64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64Decode(s: string): Uint8Array {
  return new Uint8Array(
    atob(s)
      .split('')
      .map((c) => c.charCodeAt(0))
  );
}

/**
 * Pad an encrypted payload string to the next size bucket. Server sees only bucket-sized blobs.
 */
export function padForSend(encryptedPayload: string): string {
  const bytes = new TextEncoder().encode(encryptedPayload);
  const payloadLen = bytes.length;
  const totalWithPrefix = 2 + payloadLen;
  const bucket = nextBucket(totalWithPrefix);
  const padded = new Uint8Array(bucket);
  const view = new DataView(padded.buffer);
  view.setUint16(0, payloadLen, false);
  padded.set(bytes, 2);
  if (bucket > totalWithPrefix) {
    crypto.getRandomValues(padded.subarray(totalWithPrefix));
  }
  return `${PADDED_PREFIX}${b64Encode(padded)}`;
}

/**
 * Remove padding from a received payload. Returns inner payload or unchanged string if not padded.
 */
export function unpadFromReceive(paddedPayload: string): string {
  if (!paddedPayload.startsWith(PADDED_PREFIX)) return paddedPayload;
  const rest = paddedPayload.slice(PADDED_PREFIX.length);
  const decoded = b64Decode(rest);
  if (decoded.length < 2) return paddedPayload;
  const view = new DataView(decoded.buffer, decoded.byteOffset, decoded.byteLength);
  const payloadLen = view.getUint16(0, false);
  if (payloadLen > decoded.length - 2) return paddedPayload;
  return new TextDecoder().decode(decoded.subarray(2, 2 + payloadLen));
}
