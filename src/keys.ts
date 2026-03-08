/**
 * E2EE key generation and storage (X3DH-style with P-256).
 * Identity: ECDH key for agreement + ECDSA key for signing the signed prekey.
 * Private keys stored as non-extractable CryptoKeys in IndexedDB.
 */

import {
  openDb,
  STORE_KEYS,
  getFromStore,
  putInStore,
  deleteFromStore,
  deriveStorageEncryptionKey,
} from './idb';
import { getStoragePrefix } from './storage-prefix';

const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const P256_SIGN = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const KEYS_RECORD_KEY = 'default';

function keysStoreKey(): string {
  const p = getStoragePrefix();
  return p ? `${p}_${KEYS_RECORD_KEY}` : KEYS_RECORD_KEY;
}
function legacyKeysStoreKey(): string {
  return KEYS_RECORD_KEY;
}
const LEGACY_STORAGE_KEY = 'e2ee_keys_v1';
/** Keep this many previous signed prekeys for decryption of in-flight initial messages. */
export const SIGNED_PREKEY_RETENTION = 4;

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

export interface IdentityKeys {
  identityDhKeyPair: CryptoKeyPair;
  identitySignKeyPair: CryptoKeyPair;
}

export interface SignedPreKey {
  keyPair: CryptoKeyPair;
  keyId: number;
  signature: ArrayBuffer;
}

export interface OneTimePreKey {
  keyPair: CryptoKeyPair;
  keyId: string;
}

function randomId(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface StoredSignedPreKeyEntry {
  keyPair: CryptoKeyPair;
  keyId: number;
  signature: ArrayBuffer;
}

interface StoredKeysRecord {
  identityDhKeyPair: CryptoKeyPair;
  identitySignKeyPair: CryptoKeyPair;
  signedPreKey: StoredSignedPreKeyEntry;
  signedPreKeysRetained?: StoredSignedPreKeyEntry[];
  oneTimePreKeys: Array<{ keyPair: CryptoKeyPair; keyId: string }>;
  consumedOneTimePreKeys?: Array<{ keyPair: CryptoKeyPair; keyId: string }>;
}

interface LegacyStoredKeyPair {
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

interface LegacyStoredKeys {
  version: 1;
  identityDh: LegacyStoredKeyPair;
  identitySign: LegacyStoredKeyPair;
  signedPreKey: LegacyStoredKeyPair & { keyId: number; signatureB64: string };
  oneTimePreKeys?: Array<LegacyStoredKeyPair & { keyId: string }>;
}

function legacyRead(): LegacyStoredKeys | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(LEGACY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as LegacyStoredKeys;
    if (!parsed || parsed.version !== 1) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function importLegacyKeyPair(
  pair: LegacyStoredKeyPair,
  algorithm: EcKeyImportParams,
  publicUsages: KeyUsage[],
  privateUsages: KeyUsage[]
): Promise<CryptoKeyPair> {
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.importKey('jwk', pair.publicJwk, algorithm, true, publicUsages),
    crypto.subtle.importKey('jwk', pair.privateJwk, algorithm, true, privateUsages),
  ]);
  return { publicKey, privateKey };
}

async function migrateFromLocalStorage(): Promise<StoredKeysRecord | null> {
  const stored = legacyRead();
  if (!stored) return null;
  try {
    const [identityDhKeyPair, identitySignKeyPair, signedPreKeyPair, oneTimePreKeys] =
      await Promise.all([
        importLegacyKeyPair(stored.identityDh, P256, [], ['deriveKey', 'deriveBits']),
        importLegacyKeyPair(stored.identitySign, P256_SIGN, ['verify'], ['sign']),
        importLegacyKeyPair(stored.signedPreKey, P256, [], ['deriveKey', 'deriveBits']),
        (async () => {
          if (!stored.oneTimePreKeys?.length) return [];
          return Promise.all(
            stored.oneTimePreKeys.map(async (entry) => {
              const keyPair = await importLegacyKeyPair(entry, P256, [], ['deriveKey', 'deriveBits']);
              return { keyPair, keyId: entry.keyId };
            })
          );
        })(),
      ]);
    const sigRaw = b64Decode(stored.signedPreKey.signatureB64);
    const record: StoredKeysRecord = {
      identityDhKeyPair,
      identitySignKeyPair,
      signedPreKey: {
        keyPair: signedPreKeyPair,
        keyId: stored.signedPreKey.keyId,
        signature: sigRaw.buffer.slice(sigRaw.byteOffset, sigRaw.byteOffset + sigRaw.byteLength) as ArrayBuffer,
      },
      oneTimePreKeys,
    };
    const db = await openDb();
    await putInStore(db, STORE_KEYS, keysStoreKey(), record);
    db.close();
    try {
      window.localStorage.removeItem(LEGACY_STORAGE_KEY);
    } catch {
      // ignore
    }
    return record;
  } catch {
    return null;
  }
}

let cachedStorageKey: CryptoKey | null = null;

/**
 * Derives the key used to encrypt ratchet/sender-key state at rest. Cached after first derivation.
 * Returns null if no identity keys are stored.
 */
export async function getStorageEncryptionKey(): Promise<CryptoKey | null> {
  if (cachedStorageKey) return cachedStorageKey;
  const db = await openDb();
  const key = keysStoreKey();
  let record = await getFromStore<StoredKeysRecord>(db, STORE_KEYS, key);
  if (!record && getStoragePrefix()) {
    const legacy = await getFromStore<StoredKeysRecord>(db, STORE_KEYS, legacyKeysStoreKey());
    if (legacy) {
      await putInStore(db, STORE_KEYS, key, legacy);
      await deleteFromStore(db, STORE_KEYS, legacyKeysStoreKey());
      record = legacy;
    }
  }
  db.close();
  if (!record?.identityDhKeyPair?.privateKey) return null;
  cachedStorageKey = await deriveStorageEncryptionKey(record.identityDhKeyPair.privateKey);
  return cachedStorageKey;
}

export function clearStorageEncryptionKeyCache(): void {
  cachedStorageKey = null;
}

function recordToLoaded(record: StoredKeysRecord): {
  identity: IdentityKeys;
  signedPreKey: SignedPreKey;
  signedPreKeys: SignedPreKey[];
  oneTimePreKeys: OneTimePreKey[];
  consumedOneTimePreKeys: OneTimePreKey[];
} {
  const current: SignedPreKey = {
    keyPair: record.signedPreKey.keyPair,
    keyId: record.signedPreKey.keyId,
    signature: record.signedPreKey.signature,
  };
  const retained: SignedPreKey[] = (record.signedPreKeysRetained ?? []).map((e) => ({
    keyPair: e.keyPair,
    keyId: e.keyId,
    signature: e.signature,
  }));
  return {
    identity: {
      identityDhKeyPair: record.identityDhKeyPair,
      identitySignKeyPair: record.identitySignKeyPair,
    },
    signedPreKey: current,
    signedPreKeys: [current, ...retained],
    oneTimePreKeys: record.oneTimePreKeys,
    consumedOneTimePreKeys: record.consumedOneTimePreKeys ?? [],
  };
}

export type LoadedKeys = {
  identity: IdentityKeys;
  signedPreKey: SignedPreKey;
  signedPreKeys: SignedPreKey[];
  oneTimePreKeys: OneTimePreKey[];
  consumedOneTimePreKeys: OneTimePreKey[];
};

export async function loadKeysFromStorage(): Promise<LoadedKeys | null> {
  if (typeof indexedDB === 'undefined') return null;
  const db = await openDb();
  const key = keysStoreKey();
  let record: StoredKeysRecord | null | undefined = await getFromStore<StoredKeysRecord>(
    db,
    STORE_KEYS,
    key
  );
  if (!record && getStoragePrefix()) {
    const legacy = await getFromStore<StoredKeysRecord>(db, STORE_KEYS, legacyKeysStoreKey());
    if (legacy) {
      await putInStore(db, STORE_KEYS, key, legacy);
      await deleteFromStore(db, STORE_KEYS, legacyKeysStoreKey());
      record = legacy;
    }
  }
  db.close();
  if (!record) record = await migrateFromLocalStorage();
  if (!record) return null;
  return recordToLoaded(record);
}

export async function persistKeysToStorage(
  identity: IdentityKeys,
  signedPreKey: SignedPreKey,
  oneTimePreKeys: OneTimePreKey[] = [],
  retainedSignedPreKeys: SignedPreKey[] = [],
  consumedOneTimePreKeys: OneTimePreKey[] = []
): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const record: StoredKeysRecord = {
    identityDhKeyPair: identity.identityDhKeyPair,
    identitySignKeyPair: identity.identitySignKeyPair,
    signedPreKey: {
      keyPair: signedPreKey.keyPair,
      keyId: signedPreKey.keyId,
      signature: signedPreKey.signature,
    },
    oneTimePreKeys,
    ...(consumedOneTimePreKeys.length > 0 ? { consumedOneTimePreKeys } : {}),
    ...(retainedSignedPreKeys.length > 0
      ? {
          signedPreKeysRetained: retainedSignedPreKeys.map((e) => ({
            keyPair: e.keyPair,
            keyId: e.keyId,
            signature: e.signature,
          })),
        }
      : {}),
  };
  const db = await openDb();
  await putInStore(db, STORE_KEYS, keysStoreKey(), record);
  db.close();
  clearStorageEncryptionKeyCache();
}

export async function clearStoredKeys(): Promise<void> {
  clearStorageEncryptionKeyCache();
  if (typeof indexedDB === 'undefined') return;
  const db = await openDb();
  await deleteFromStore(db, STORE_KEYS, keysStoreKey());
  if (getStoragePrefix()) {
    await deleteFromStore(db, STORE_KEYS, legacyKeysStoreKey());
  }
  db.close();
  try {
    if (typeof window !== 'undefined') window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // ignore
  }
}

/**
 * Generate long-term identity: one ECDH key (agreement) and one ECDSA key (signing prekeys).
 * Keys are generated non-extractable.
 */
export async function generateIdentityKeys(): Promise<IdentityKeys> {
  const [identityDhKeyPair, identitySignKeyPair] = await Promise.all([
    crypto.subtle.generateKey(P256, false, ['deriveKey', 'deriveBits']),
    crypto.subtle.generateKey(P256_SIGN, false, ['sign', 'verify']),
  ]);
  return { identityDhKeyPair, identitySignKeyPair };
}

/**
 * Generate a signed prekey and sign it with the identity signing key.
 */
export async function generateSignedPreKey(
  identitySignPrivate: CryptoKey,
  keyId: number
): Promise<SignedPreKey> {
  // Must be extractable because ratchet state persists DH private key material (pkcs8/base64).
  const keyPair = await crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']);
  const pubRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey!);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identitySignPrivate,
    pubRaw
  );
  return { keyPair, keyId, signature };
}

/**
 * Generate a one-time prekey (ECDH). Caller supplies keyId (string).
 */
export async function generateOneTimePreKey(keyId: string): Promise<OneTimePreKey> {
  const keyPair = await crypto.subtle.generateKey(P256, false, ['deriveKey', 'deriveBits']);
  return { keyPair, keyId };
}

/**
 * Generate a batch of one-time prekeys with random keyIds.
 */
export async function generateOneTimePreKeys(count: number): Promise<OneTimePreKey[]> {
  const out: OneTimePreKey[] = [];
  const total = Math.max(0, Math.floor(count));
  for (let i = 0; i < total; i += 1) {
    out.push(await generateOneTimePreKey(randomId()));
  }
  return out;
}

/**
 * Export any ECDH public key to base64.
 */
export async function exportEcdhPublicKeyBase64(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return b64Encode(raw);
}

/**
 * Export public identity for upload: "base64(dhPub).base64(signPub)".
 */
export async function exportIdentityPublic(keys: IdentityKeys): Promise<string> {
  const [dhPub, signPub] = await Promise.all([
    crypto.subtle.exportKey('raw', keys.identityDhKeyPair.publicKey!),
    crypto.subtle.exportKey('raw', keys.identitySignKeyPair.publicKey!),
  ]);
  return `${b64Encode(dhPub)}.${b64Encode(signPub)}`;
}

/**
 * Export identity ECDH public only (for initial message so responder can run X3DH).
 */
export async function exportIdentityDhBase64(keys: IdentityKeys): Promise<string> {
  const dhPub = await crypto.subtle.exportKey('raw', keys.identityDhKeyPair.publicKey!);
  return b64Encode(dhPub);
}

/**
 * Export signed prekey public and signature for upload.
 */
export async function exportSignedPreKeyPublic(sk: SignedPreKey): Promise<{
  key: string;
  signature: string;
  keyId: number;
}> {
  const pubRaw = await crypto.subtle.exportKey('raw', sk.keyPair.publicKey!);
  return {
    key: b64Encode(pubRaw),
    signature: b64Encode(sk.signature),
    keyId: sk.keyId,
  };
}

/**
 * Export one-time prekey public for upload.
 */
export async function exportOneTimePreKeyPublic(otk: OneTimePreKey): Promise<{
  key: string;
  keyId: string;
}> {
  const pubRaw = await crypto.subtle.exportKey('raw', otk.keyPair.publicKey!);
  return {
    key: b64Encode(pubRaw),
    keyId: otk.keyId,
  };
}

/**
 * Parse remote identity string into raw public keys (dh, sign).
 * Format: "base64(dh).base64(sign)".
 */
export function parseIdentityPublic(identityKey: string): { dhPub: ArrayBuffer; signPub: ArrayBuffer } {
  const parts = identityKey.split('.');
  if (parts.length < 2) throw new Error('E2EE: invalid identity key format');
  const dhBytes = b64Decode(parts[0] ?? '');
  const signBytes = parts[1] ? b64Decode(parts[1]) : undefined;
  if (!signBytes) throw new Error('E2EE: missing identity signing key');
  const dhSlice =
    dhBytes.buffer.byteLength === dhBytes.byteLength && dhBytes.byteOffset === 0
      ? dhBytes.buffer.slice(0)
      : dhBytes.buffer.slice(dhBytes.byteOffset, dhBytes.byteOffset + dhBytes.byteLength);
  const signSlice =
    signBytes.buffer.byteLength === signBytes.byteLength && signBytes.byteOffset === 0
      ? signBytes.buffer.slice(0)
      : signBytes.buffer.slice(signBytes.byteOffset, signBytes.byteOffset + signBytes.byteLength);
  return {
    dhPub: dhSlice as ArrayBuffer,
    signPub: signSlice as ArrayBuffer,
  };
}

/**
 * Import remote ECDH public key from base64.
 */
export async function importEcdhPublicKey(rawBase64: string): Promise<CryptoKey> {
  const raw = b64Decode(rawBase64);
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('raw', buf, P256, false, []);
}

/**
 * Import our own ECDH private key (for storage/restore - we don't persist private keys to server).
 */
export async function importEcdhPrivateKey(rawBase64: string): Promise<CryptoKey> {
  const raw = b64Decode(rawBase64);
  const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer;
  return crypto.subtle.importKey('raw', buf, P256, true, ['deriveKey', 'deriveBits']);
}
