/**
 * Sender Keys for group E2EE: one symmetric chain per sender in a conversation.
 * Same KDF chain pattern as Double Ratchet sending chain; no DH.
 * Includes skipped-key cache for out-of-order delivery.
 * Sender key distribution and group messages carry a per-sender ECDSA P-256
 * signing key; every group message is signed over (conversationId, senderDeviceId, iteration, ciphertext) and verified on decrypt to fix group forgery.
 * When signingPublicKey is present, verification fails with "E2EE: group message signature verification failed". Legacy (unsigned) messages still decrypt when the stored sender key has no signingPublicKey.
 */

const ECDSA_P256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

function toArrayBuffer(buf: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (buf instanceof ArrayBuffer) return buf.slice(0, buf.byteLength);
  const u = buf as Uint8Array;
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as unknown as ArrayBuffer;
}

async function kdf(
  key: ArrayBuffer,
  info: string
): Promise<{ chainKey: ArrayBuffer; messageKey: ArrayBuffer }> {
  const keyCrypto = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode(info),
    },
    keyCrypto,
    512
  );
  const ab = (
    derived instanceof ArrayBuffer ? derived : new Uint8Array(derived).buffer
  ) as ArrayBuffer;
  return {
    chainKey: ab.slice(0, 32) as ArrayBuffer,
    messageKey: ab.slice(32, 64) as ArrayBuffer,
  };
}

async function aesGcmEncrypt(
  key: ArrayBuffer,
  plaintext: ArrayBuffer,
  iv: Uint8Array,
  additionalData?: ArrayBuffer
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 };
  if (additionalData) params.additionalData = additionalData;
  return crypto.subtle.encrypt(params, cryptoKey, plaintext);
}

async function aesGcmDecrypt(
  key: ArrayBuffer,
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
  additionalData?: ArrayBuffer
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 };
  if (additionalData) params.additionalData = additionalData;
  return crypto.subtle.decrypt(params, cryptoKey, ciphertext);
}

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

const MAX_SKIP = 2000;
const MAX_SKIPPED_KEYS = 2000;
const ECDSA_SIG_MAX_DER = 72;
const ITERATION_BYTES = 4;
const IV_BYTES = 12;
const SIGLEN_BYTES = 2;
const PAYLOAD_HEADER_BYTES = ITERATION_BYTES + IV_BYTES;
const GROUP_PAYLOAD_MIN = PAYLOAD_HEADER_BYTES + SIGLEN_BYTES; // iteration + iv + sigLen

function concat(...bufs: ArrayBuffer[]): ArrayBuffer {
  const total = bufs.reduce((a, b) => a + b.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    out.set(new Uint8Array(b), off);
    off += b.byteLength;
  }
  return toArrayBuffer(out);
}

function writeUint16Be(value: number): ArrayBuffer {
  const buf = new ArrayBuffer(2);
  new DataView(buf).setUint16(0, value, false);
  return buf;
}

function buildMessageToSign(
  conversationId: string,
  senderDeviceId: string,
  iteration: number,
  ciphertext: ArrayBuffer
): ArrayBuffer {
  const enc = new TextEncoder();
  const conv = enc.encode(conversationId);
  const dev = enc.encode(senderDeviceId);
  const convLen = new ArrayBuffer(4);
  new DataView(convLen).setUint32(0, conv.byteLength, false);
  const devLen = new ArrayBuffer(4);
  new DataView(devLen).setUint32(0, dev.byteLength, false);
  const iterBuf = new ArrayBuffer(ITERATION_BYTES);
  new DataView(iterBuf).setUint32(0, iteration, false);
  return concat(
    convLen,
    toArrayBuffer(conv),
    devLen,
    toArrayBuffer(dev),
    iterBuf,
    ciphertext
  );
}

export async function generateSenderSigningKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyRaw: ArrayBuffer;
}> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicKeyRaw: raw,
  };
}

export async function signSenderPayload(
  conversationId: string,
  senderDeviceId: string,
  iteration: number,
  ciphertext: ArrayBuffer,
  privateKey: CryptoKey
): Promise<ArrayBuffer> {
  const message = buildMessageToSign(conversationId, senderDeviceId, iteration, ciphertext);
  const sig = await crypto.subtle.sign(ECDSA_P256, privateKey, message);
  const sigLen = writeUint16Be(sig.byteLength);
  return concat(sig, sigLen);
}

export async function verifySenderSignature(
  conversationId: string,
  senderDeviceId: string,
  iteration: number,
  ciphertext: ArrayBuffer,
  signature: ArrayBuffer,
  publicKey: CryptoKey
): Promise<boolean> {
  const message = buildMessageToSign(conversationId, senderDeviceId, iteration, ciphertext);
  return crypto.subtle.verify(ECDSA_P256, publicKey, signature, message);
}

export interface SenderKeyState {
  chainKey: ArrayBuffer;
  iteration: number;
  skippedKeys: Record<number, string>;
  signingPublicKey?: ArrayBuffer;
  signingPrivateKey?: CryptoKey;
}

/**
 * Create a new sender key state (e.g. when we first send in a group). Generates a per-sender ECDSA P-256 signing key.
 */
export async function createSenderKeyState(): Promise<SenderKeyState> {
  const seed = randomBytes(32);
  const { publicKeyRaw, privateKey } = await generateSenderSigningKeyPair();
  return {
    chainKey: toArrayBuffer(seed),
    iteration: 0,
    skippedKeys: {},
    signingPublicKey: publicKeyRaw,
    signingPrivateKey: privateKey,
  };
}

export interface SenderKeySigningContext {
  conversationId: string;
  senderDeviceId: string;
}

/**
 * Encrypt plaintext with sender key; advances chain. Payload: 4-byte iteration (big-endian) || iv(12) || ciphertext [|| signature || sigLen(2)].
 * When state has a signing key and context is provided, appends signature over (conversationId, senderDeviceId, iteration, ciphertext).
 * additionalData binds ciphertext to conversationId to prevent replay or cross-conversation use.
 */
export async function senderKeyEncrypt(
  state: SenderKeyState,
  plaintext: string,
  additionalData?: ArrayBuffer,
  signingContext?: SenderKeySigningContext
): Promise<{ payload: ArrayBuffer; state: SenderKeyState }> {
  const { chainKey, messageKey } = await kdf(state.chainKey, `msg-${state.iteration}`);
  const iv = randomBytes(IV_BYTES);
  const plainBytes = new TextEncoder().encode(plaintext);
  const ciphertext = await aesGcmEncrypt(messageKey, plainBytes.buffer, iv, additionalData);
  const ciphertextAb = ciphertext as ArrayBuffer;

  const nBuf = new ArrayBuffer(ITERATION_BYTES);
  new DataView(nBuf).setUint32(0, state.iteration, false);
  let payload = concat(nBuf, toArrayBuffer(iv), ciphertextAb);

  if (state.signingPrivateKey && signingContext) {
    const sig = await signSenderPayload(
      signingContext.conversationId,
      signingContext.senderDeviceId,
      state.iteration,
      ciphertextAb,
      state.signingPrivateKey
    );
    payload = concat(payload, sig);
  }

  return {
    payload,
    state: { ...state, chainKey, iteration: state.iteration + 1 },
  };
}

export interface SenderKeyVerificationContext {
  conversationId: string;
  senderDeviceId: string;
}

/**
 * Decrypt payload; advances receiving chain to this iteration.
 * Payload format: 4-byte n || iv(12) || ciphertext [|| signature || sigLen(2)].
 *
 * When state has signingPublicKey and payload has signature+sigLen, signature is verified before
 * decrypting; on failure throws "E2EE: group message signature verification failed". No legacy path
 * when the key is present.
 *
 * Legacy: when the stored sender key has no signingPublicKey, legacy (unsigned) messages still
 * decrypt.
 *
 * additionalData must match the value used when encrypting (e.g. conversationId) or decryption fails.
 */
export async function senderKeyDecrypt(
  state: SenderKeyState,
  payload: ArrayBuffer,
  additionalData?: ArrayBuffer,
  verificationContext?: SenderKeyVerificationContext
): Promise<{ plaintext: string; state: SenderKeyState }> {
  let body = payload;
  if (state.signingPublicKey && verificationContext) {
    if (payload.byteLength < GROUP_PAYLOAD_MIN) {
      throw new Error('E2EE: group message signature missing');
    }
    const view = new DataView(payload);
    const sigLen = view.getUint16(payload.byteLength - SIGLEN_BYTES, false);
    if (sigLen <= 0 || sigLen > ECDSA_SIG_MAX_DER) {
      throw new Error('E2EE: group message signature missing');
    }
    if (payload.byteLength < GROUP_PAYLOAD_MIN + sigLen) {
      throw new Error('E2EE: group message signature missing');
    }
    body = payload.slice(0, payload.byteLength - SIGLEN_BYTES - sigLen);
    const signature = payload.slice(
      payload.byteLength - SIGLEN_BYTES - sigLen,
      payload.byteLength - SIGLEN_BYTES
    );
    const n = view.getUint32(0, false);
    const ciphertext = toArrayBuffer(
      new Uint8Array(body, PAYLOAD_HEADER_BYTES, body.byteLength - PAYLOAD_HEADER_BYTES)
    );
    const publicKey = await crypto.subtle.importKey(
      'raw',
      state.signingPublicKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    let ok: boolean;
    try {
      ok = await verifySenderSignature(
        verificationContext.conversationId,
        verificationContext.senderDeviceId,
        n,
        ciphertext,
        signature,
        publicKey
      );
    } catch {
      ok = false;
    }
    if (!ok) throw new Error('E2EE: group message signature verification failed');
  }

  const view = new DataView(body);
  const n = view.getUint32(0, false);
  const iv = new Uint8Array(body, ITERATION_BYTES, IV_BYTES);
  const ciphertext = toArrayBuffer(
    new Uint8Array(body, PAYLOAD_HEADER_BYTES, body.byteLength - PAYLOAD_HEADER_BYTES)
  );

  let chainKey = state.chainKey;
  let curN = state.iteration;
  const skipped = { ...state.skippedKeys };
  if (n < curN) {
    const cached = skipped[n];
    if (!cached) throw new Error('E2EE: group message out-of-order or duplicate');
    const messageKey = toArrayBuffer(b64Decode(cached));
    const plainBytes = await aesGcmDecrypt(messageKey, ciphertext, iv, additionalData);
    const plaintext = new TextDecoder().decode(plainBytes);
    return {
      plaintext,
      state: { ...state, skippedKeys: skipped },
    };
  }
  if (n - curN > MAX_SKIP) throw new Error('E2EE: too many skipped group messages');
  while (curN < n) {
    const out = await kdf(chainKey, `msg-${curN}`);
    chainKey = out.chainKey;
    skipped[curN] = b64Encode(out.messageKey);
    curN += 1;
  }
  const { chainKey: nextChainKey, messageKey } = await kdf(chainKey, `msg-${n}`);
  const plainBytes = await aesGcmDecrypt(messageKey, ciphertext, iv, additionalData);
  const plaintext = new TextDecoder().decode(plainBytes);
  skipped[n] = b64Encode(messageKey);

  return {
    plaintext,
    state: {
      chainKey: nextChainKey,
      iteration: n + 1,
      skippedKeys: pruneSkippedKeys(skipped),
      signingPublicKey: state.signingPublicKey,
      signingPrivateKey: state.signingPrivateKey,
    },
  };
}

function b64Encode(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function b64Decode(s: string): Uint8Array {
  return new Uint8Array(
    atob(s)
      .split('')
      .map((c) => c.charCodeAt(0))
  );
}

interface SenderKeyStateJson {
  chainKey: string;
  iteration: number;
  skippedKeys: Record<number, string>;
  signingPublicKeyB64?: string;
  signingPrivateKeyPkcs8B64?: string;
}

/**
 * Serialize sender key state for persistence (chain key, iteration, optional signing keys).
 */
export function senderKeyStateToJson(state: SenderKeyState): string {
  const out: SenderKeyStateJson = {
    chainKey: b64Encode(toArrayBuffer(state.chainKey)),
    iteration: state.iteration,
    skippedKeys: state.skippedKeys,
  };
  if (state.signingPublicKey) {
    out.signingPublicKeyB64 = b64Encode(state.signingPublicKey);
  }
  return JSON.stringify(out);
}

/**
 * Serialize sender key state for persistence including private signing key (async).
 */
export async function senderKeyStateToJsonAsync(state: SenderKeyState): Promise<string> {
  const out: SenderKeyStateJson = {
    chainKey: b64Encode(toArrayBuffer(state.chainKey)),
    iteration: state.iteration,
    skippedKeys: state.skippedKeys,
  };
  if (state.signingPublicKey) {
    out.signingPublicKeyB64 = b64Encode(state.signingPublicKey);
  }
  if (state.signingPrivateKey) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', state.signingPrivateKey);
    out.signingPrivateKeyPkcs8B64 = b64Encode(pkcs8);
  }
  return JSON.stringify(out);
}

/**
 * Deserialize sender key state from JSON. Call senderKeyStateFromJsonAsync when the blob may contain a private key.
 */
export function senderKeyStateFromJson(json: string): SenderKeyState {
  const o = JSON.parse(json) as SenderKeyStateJson;
  const chainKey = b64Decode(o.chainKey);
  const state: SenderKeyState = {
    chainKey: toArrayBuffer(chainKey),
    iteration: o.iteration,
    skippedKeys: o.skippedKeys ?? {},
  };
  if (o.signingPublicKeyB64) {
    state.signingPublicKey = toArrayBuffer(b64Decode(o.signingPublicKeyB64));
  }
  return state;
}

/**
 * Deserialize sender key state from JSON, importing private signing key if present.
 */
export async function senderKeyStateFromJsonAsync(json: string): Promise<SenderKeyState> {
  const o = JSON.parse(json) as SenderKeyStateJson;
  const chainKey = b64Decode(o.chainKey);
  const state: SenderKeyState = {
    chainKey: toArrayBuffer(chainKey),
    iteration: o.iteration,
    skippedKeys: o.skippedKeys ?? {},
  };
  if (o.signingPublicKeyB64) {
    state.signingPublicKey = toArrayBuffer(b64Decode(o.signingPublicKeyB64));
  }
  if (o.signingPrivateKeyPkcs8B64) {
    const pkcs8 = b64Decode(o.signingPrivateKeyPkcs8B64);
    state.signingPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      toArrayBuffer(pkcs8),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign']
    );
  }
  return state;
}

function pruneSkippedKeys(skippedKeys: Record<number, string>): Record<number, string> {
  const entries = Object.entries(skippedKeys);
  if (entries.length <= MAX_SKIPPED_KEYS) return skippedKeys;
  const trimmed = entries.slice(entries.length - MAX_SKIPPED_KEYS);
  return Object.fromEntries(trimmed);
}
