/**
 * Double Ratchet (DH + symmetric chains) with skipped-key cache.
 * Session state includes DH ratchet keys, root key, chain keys, and counters.
 */

const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const HEADER_MAGIC = new Uint8Array([0x44, 0x52, 0x01]); // "DR" v1
const MAX_SKIP = 2000;
const MAX_SKIPPED_KEYS = 2000;

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

function toArrayBuffer(buf: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (buf instanceof ArrayBuffer) return buf.slice(0, buf.byteLength);
  const u = buf;
  const slice = u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
  return slice as unknown as ArrayBuffer;
}

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

async function kdfRk(
  rootKey: ArrayBuffer,
  dhOut: ArrayBuffer
): Promise<{ rootKey: ArrayBuffer; chainKey: ArrayBuffer }> {
  const keyCrypto = await crypto.subtle.importKey(
    'raw',
    dhOut,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(rootKey),
      info: new TextEncoder().encode('dr-root'),
    },
    keyCrypto,
    512
  );
  const ab = (derived instanceof ArrayBuffer ? derived : new Uint8Array(derived).buffer) as ArrayBuffer;
  return {
    rootKey: ab.slice(0, 32) as ArrayBuffer,
    chainKey: ab.slice(32, 64) as ArrayBuffer,
  };
}

async function kdfCk(
  chainKey: ArrayBuffer
): Promise<{ chainKey: ArrayBuffer; messageKey: ArrayBuffer }> {
  const keyCrypto = await crypto.subtle.importKey(
    'raw',
    chainKey,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new ArrayBuffer(0),
      info: new TextEncoder().encode('dr-chain'),
    },
    keyCrypto,
    512
  );
  const ab = (derived instanceof ArrayBuffer ? derived : new Uint8Array(derived).buffer) as ArrayBuffer;
  return {
    chainKey: ab.slice(0, 32) as ArrayBuffer,
    messageKey: ab.slice(32, 64) as ArrayBuffer,
  };
}

async function ecdh(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
}

async function generateDhKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']);
}

async function exportDhPublicKeyBase64(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return b64Encode(raw);
}

async function exportDhPrivateKeyBase64(key: CryptoKey): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
  return b64Encode(pkcs8);
}

async function importDhPublicKeyBase64(rawBase64: string): Promise<CryptoKey> {
  const raw = b64Decode(rawBase64);
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('raw', buf, P256, false, []);
}

async function importDhPrivateKeyBase64(pkcs8Base64: string): Promise<CryptoKey> {
  const raw = b64Decode(pkcs8Base64);
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('pkcs8', buf, P256, true, ['deriveKey', 'deriveBits']);
}

async function aesGcmEncrypt(
  key: ArrayBuffer,
  plaintext: ArrayBuffer,
  iv: Uint8Array,
  additionalData?: ArrayBuffer
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
  ]);
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
  const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(key), { name: 'AES-GCM', length: 256 }, false, [
    'decrypt',
  ]);
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 };
  if (additionalData) params.additionalData = additionalData;
  return crypto.subtle.decrypt(params, cryptoKey, ciphertext);
}

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

type SkippedKeyMap = Record<string, string>;

export interface RatchetState {
  version: 'dh';
  rootKey: ArrayBuffer;
  dhs: CryptoKeyPair;
  dhsPublicKeyB64: string;
  dhsPrivateKeyB64: string;
  dhrPublicKeyB64?: string;
  dhr?: CryptoKey;
  ckS?: ArrayBuffer;
  ckR?: ArrayBuffer;
  ns: number;
  nr: number;
  pn: number;
  skippedKeys: SkippedKeyMap;
}

function skippedKeyId(dhPubB64: string, n: number): string {
  return `${dhPubB64}:${n}`;
}

function pruneSkippedKeys(skippedKeys: SkippedKeyMap): SkippedKeyMap {
  const entries = Object.entries(skippedKeys);
  if (entries.length <= MAX_SKIPPED_KEYS) return skippedKeys;
  const trimmed = entries.slice(entries.length - MAX_SKIPPED_KEYS);
  return Object.fromEntries(trimmed);
}

async function skipMessageKeys(
  state: RatchetState,
  until: number
): Promise<RatchetState> {
  if (!state.ckR || !state.dhrPublicKeyB64) return state;
  if (until - state.nr > MAX_SKIP) throw new Error('E2EE: too many skipped messages');
  let ckR = state.ckR;
  let nr = state.nr;
  const skippedKeys = { ...state.skippedKeys };
  while (nr < until) {
    const out = await kdfCk(ckR);
    ckR = out.chainKey;
    skippedKeys[skippedKeyId(state.dhrPublicKeyB64, nr)] = b64Encode(out.messageKey);
    nr += 1;
  }
  return {
    ...state,
    ckR,
    nr,
    skippedKeys: pruneSkippedKeys(skippedKeys),
  };
}

async function dhRatchet(state: RatchetState, newDhrB64: string): Promise<RatchetState> {
  const newDhr = await importDhPublicKeyBase64(newDhrB64);
  const dhOut = await ecdh(state.dhs.privateKey!, newDhr);
  const { rootKey: rk1, chainKey: ckR } = await kdfRk(state.rootKey, dhOut);
  const nextDhs = await generateDhKeyPair();
  const dhOut2 = await ecdh(nextDhs.privateKey!, newDhr);
  const { rootKey: rk2, chainKey: ckS } = await kdfRk(rk1, dhOut2);
  const nextDhsPublicB64 = await exportDhPublicKeyBase64(nextDhs.publicKey!);
  const nextDhsPrivateB64 = await exportDhPrivateKeyBase64(nextDhs.privateKey!);
  return {
    ...state,
    rootKey: rk2,
    dhrPublicKeyB64: newDhrB64,
    dhr: newDhr,
    dhs: nextDhs,
    dhsPublicKeyB64: nextDhsPublicB64,
    dhsPrivateKeyB64: nextDhsPrivateB64,
    ckR,
    ckS,
    pn: state.ns,
    ns: 0,
    nr: 0,
  };
}

function encodeHeader(dhPub: ArrayBuffer, pn: number, n: number): Uint8Array {
  const dhLen = dhPub.byteLength;
  const header = new Uint8Array(3 + 2 + dhLen + 4 + 4);
  header.set(HEADER_MAGIC, 0);
  const view = new DataView(header.buffer);
  view.setUint16(3, dhLen, false);
  header.set(new Uint8Array(dhPub), 5);
  view.setUint32(5 + dhLen, pn, false);
  view.setUint32(9 + dhLen, n, false);
  return header;
}

function parseHeader(payload: ArrayBuffer): {
  header: Uint8Array;
  dhPub: Uint8Array;
  pn: number;
  n: number;
  iv: Uint8Array;
  ciphertext: ArrayBuffer;
} | null {
  const u8 = new Uint8Array(payload);
  if (u8.byteLength < 3 + 2 + 4 + 4 + 12 + 1) return null;
  if (
    u8[0] !== HEADER_MAGIC[0] ||
    u8[1] !== HEADER_MAGIC[1] ||
    u8[2] !== HEADER_MAGIC[2]
  ) {
    return null;
  }
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const dhLen = view.getUint16(3, false);
  const headerLen = 3 + 2 + dhLen + 4 + 4;
  if (u8.byteLength < headerLen + 12 + 1) return null;
  const dhPub = u8.slice(5, 5 + dhLen);
  const pn = view.getUint32(5 + dhLen, false);
  const n = view.getUint32(9 + dhLen, false);
  const header = u8.slice(0, headerLen);
  const iv = u8.slice(headerLen, headerLen + 12);
  const ciphertext = toArrayBuffer(u8.slice(headerLen + 12));
  return { header, dhPub, pn, n, iv, ciphertext };
}

/**
 * Create initial ratchet state from X3DH root key.
 * Initiator: DHs = initiator ephemeral; DHr = responder signed prekey; CKs derived.
 * Responder: DHs = responder signed prekey; DHr = initiator ephemeral; CKr derived.
 */
export async function ratchetStateFromRoot(
  rootKey: ArrayBuffer,
  options: { isInitiator: boolean; ourDhKeyPair: CryptoKeyPair; theirDhPublicKeyBase64: string }
): Promise<RatchetState> {
  const dhsPublicKeyB64 = await exportDhPublicKeyBase64(options.ourDhKeyPair.publicKey!);
  const dhsPrivateKeyB64 = await exportDhPrivateKeyBase64(options.ourDhKeyPair.privateKey!);
  const dhrPublicKeyB64 = options.theirDhPublicKeyBase64;
  const dhr = await importDhPublicKeyBase64(dhrPublicKeyB64);
  const dhOut = await ecdh(options.ourDhKeyPair.privateKey!, dhr);
  const { rootKey: nextRoot, chainKey } = await kdfRk(rootKey, dhOut);
  if (options.isInitiator) {
    return {
      version: 'dh',
      rootKey: nextRoot,
      dhs: options.ourDhKeyPair,
      dhsPublicKeyB64,
      dhsPrivateKeyB64,
      dhrPublicKeyB64,
      dhr,
      ckS: chainKey,
      ckR: undefined,
      ns: 0,
      nr: 0,
      pn: 0,
      skippedKeys: {},
    };
  }
  return {
    version: 'dh',
    rootKey: nextRoot,
    dhs: options.ourDhKeyPair,
    dhsPublicKeyB64,
    dhsPrivateKeyB64,
    dhrPublicKeyB64,
    dhr,
    ckS: undefined,
    ckR: chainKey,
    ns: 0,
    nr: 0,
    pn: 0,
    skippedKeys: {},
  };
}

/**
 * Encrypt plaintext; advances sending chain. Payload includes header with DH, PN, N.
 * AAD binds ciphertext to conversationId (and optionally messageId) to prevent replay or cross-conversation use.
 */
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: string,
  additionalData?: ArrayBuffer
): Promise<{ payload: ArrayBuffer; state: RatchetState }> {
  let nextState = { ...state, skippedKeys: { ...state.skippedKeys } };
  if (!nextState.ckS) {
    if (!nextState.dhrPublicKeyB64) {
      throw new Error('E2EE: missing remote DH public key');
    }
    const nextDhs = await generateDhKeyPair();
    const nextDhsPublicB64 = await exportDhPublicKeyBase64(nextDhs.publicKey!);
    const nextDhsPrivateB64 = await exportDhPrivateKeyBase64(nextDhs.privateKey!);
    const dhr = await importDhPublicKeyBase64(nextState.dhrPublicKeyB64);
    const dhOut = await ecdh(nextDhs.privateKey!, dhr);
    const { rootKey: rk, chainKey: ckS } = await kdfRk(nextState.rootKey, dhOut);
    nextState = {
      ...nextState,
      rootKey: rk,
      dhs: nextDhs,
      dhsPublicKeyB64: nextDhsPublicB64,
      dhsPrivateKeyB64: nextDhsPrivateB64,
      ckS,
      pn: nextState.ns,
      ns: 0,
    };
  }

  const ckS = nextState.ckS;
  if (!ckS) throw new Error('E2EE: missing sending chain key');
  const { chainKey, messageKey } = await kdfCk(ckS);
  const iv = randomBytes(12);
  const plainBytes = new TextEncoder().encode(plaintext);
  const dhPubRaw = b64Decode(nextState.dhsPublicKeyB64);
  const header = encodeHeader(toArrayBuffer(dhPubRaw), nextState.pn, nextState.ns);
  const aad = additionalData ? concat(toArrayBuffer(header), additionalData) : toArrayBuffer(header);
  const ciphertext = await aesGcmEncrypt(messageKey, plainBytes.buffer, iv, aad);

  const payload = concat(toArrayBuffer(header), toArrayBuffer(iv), ciphertext as ArrayBuffer);
  return {
    payload,
    state: {
      ...nextState,
      ckS: chainKey,
      ns: nextState.ns + 1,
    },
  };
}

/**
 * Decrypt payload; advances receiving chain.
 * additionalData must match the value used when encrypting (e.g. conversationId) or decryption fails.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  payload: ArrayBuffer,
  additionalData?: ArrayBuffer
): Promise<{ plaintext: string; state: RatchetState }> {
  const parsed = parseHeader(payload);
  if (!parsed) throw new Error('E2EE: invalid ratchet payload');

  const dhPubB64 = b64Encode(toArrayBuffer(parsed.dhPub));
  const currentMessageKeyId = skippedKeyId(dhPubB64, parsed.n);
  const cached = state.skippedKeys[currentMessageKeyId];
  if (cached) {
    const messageKey = toArrayBuffer(b64Decode(cached));
    const aad = additionalData ? concat(toArrayBuffer(parsed.header), additionalData) : toArrayBuffer(parsed.header);
    const plainBytes = await aesGcmDecrypt(messageKey, parsed.ciphertext, parsed.iv, aad);
    const plaintext = new TextDecoder().decode(plainBytes);
    return {
      plaintext,
      state,
    };
  }

  let nextState = { ...state, skippedKeys: { ...state.skippedKeys } };
  if (nextState.dhrPublicKeyB64 !== dhPubB64) {
    nextState = await skipMessageKeys(nextState, parsed.pn);
    nextState = await dhRatchet(nextState, dhPubB64);
  }

  nextState = await skipMessageKeys(nextState, parsed.n);
  if (!nextState.ckR) throw new Error('E2EE: missing receiving chain key');
  const { chainKey: nextCkR, messageKey } = await kdfCk(nextState.ckR);
  const aad = additionalData ? concat(toArrayBuffer(parsed.header), additionalData) : toArrayBuffer(parsed.header);
  const plainBytes = await aesGcmDecrypt(messageKey, parsed.ciphertext, parsed.iv, aad);
  const plaintext = new TextDecoder().decode(plainBytes);
  const nextSkippedKeys = pruneSkippedKeys({
    ...nextState.skippedKeys,
    [currentMessageKeyId]: b64Encode(messageKey),
  });

  return {
    plaintext,
    state: {
      ...nextState,
      ckR: nextCkR,
      nr: nextState.nr + 1,
      skippedKeys: nextSkippedKeys,
    },
  };
}

/**
 * Serialize state for persistence (base64 keys + counters).
 */
export function ratchetStateToJson(state: RatchetState): string {
  return JSON.stringify({
    version: 'dh',
    rootKey: b64Encode(toArrayBuffer(state.rootKey)),
    dhsPublicKeyB64: state.dhsPublicKeyB64,
    dhsPrivateKeyB64: state.dhsPrivateKeyB64,
    dhrPublicKeyB64: state.dhrPublicKeyB64,
    ckS: state.ckS ? b64Encode(toArrayBuffer(state.ckS)) : undefined,
    ckR: state.ckR ? b64Encode(toArrayBuffer(state.ckR)) : undefined,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    skippedKeys: state.skippedKeys,
  });
}

/**
 * Deserialize state from JSON.
 */
export async function ratchetStateFromJson(json: string): Promise<RatchetState> {
  const o = JSON.parse(json) as Record<string, unknown>;
  if (o.version !== 'dh') {
    throw new Error('E2EE: unsupported ratchet state');
  }

  const rootKey = b64Decode(String(o.rootKey ?? ''));
  const dhsPublicKeyB64 = String(o.dhsPublicKeyB64 ?? '');
  const dhsPrivateKeyB64 = String(o.dhsPrivateKeyB64 ?? '');
  const dhs = await Promise.all([
    importDhPublicKeyBase64(dhsPublicKeyB64),
    importDhPrivateKeyBase64(dhsPrivateKeyB64),
  ]).then(([pub, priv]) => ({ publicKey: pub, privateKey: priv }));

  const dhrPublicKeyB64 = o.dhrPublicKeyB64 ? String(o.dhrPublicKeyB64) : undefined;
  const dhr = dhrPublicKeyB64 ? await importDhPublicKeyBase64(dhrPublicKeyB64) : undefined;
  const ckS = o.ckS ? toArrayBuffer(b64Decode(String(o.ckS))) : undefined;
  const ckR = o.ckR ? toArrayBuffer(b64Decode(String(o.ckR))) : undefined;
  return {
    version: 'dh',
    rootKey: toArrayBuffer(rootKey),
    dhs,
    dhsPublicKeyB64,
    dhsPrivateKeyB64,
    dhrPublicKeyB64,
    dhr,
    ckS,
    ckR,
    ns: Number(o.ns ?? 0),
    nr: Number(o.nr ?? 0),
    pn: Number(o.pn ?? 0),
    skippedKeys: (o.skippedKeys as SkippedKeyMap) ?? {},
  };
}

export function payloadToBase64(payload: ArrayBuffer): string {
  return b64Encode(payload);
}

export function base64ToPayload(s: string): ArrayBuffer {
  return toArrayBuffer(b64Decode(s));
}
