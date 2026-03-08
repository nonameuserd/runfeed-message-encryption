/**
 * IndexedDB backing for E2EE key material and encrypted ratchet/sender-key state.
 * Keys are stored as non-extractable CryptoKeys; session/sender state is encrypted at rest.
 */

const DB_NAME = 'e2ee_db_v1';
const DB_VERSION = 1;
export const STORE_KEYS = 'keys';
export const STORE_SESSIONS = 'sessions';
export const STORE_SENDER_KEYS = 'senderKeys';
export const STORE_VERIFIED_PEERS = 'verifiedPeers';

const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const STORAGE_KEY_INFO = new TextEncoder().encode('e2ee-ratchet-storage-v1');
const FIXED_P256_PUBLIC_HEX =
  '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes.buffer;
}

export function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB not available'));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = (ev) => {
      const db = (ev.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_KEYS)) db.createObjectStore(STORE_KEYS);
      if (!db.objectStoreNames.contains(STORE_SESSIONS)) db.createObjectStore(STORE_SESSIONS);
      if (!db.objectStoreNames.contains(STORE_SENDER_KEYS)) db.createObjectStore(STORE_SENDER_KEYS);
      if (!db.objectStoreNames.contains(STORE_VERIFIED_PEERS)) db.createObjectStore(STORE_VERIFIED_PEERS);
    };
  });
}

export async function deriveStorageEncryptionKey(identityDhPrivateKey: CryptoKey): Promise<CryptoKey> {
  const fixedPublicRaw = hexToArrayBuffer(FIXED_P256_PUBLIC_HEX);
  const fixedPublic = await crypto.subtle.importKey('raw', fixedPublicRaw, P256, false, []);
  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: fixedPublic },
    identityDhPrivateKey,
    256
  );
  const sharedArr = new Uint8Array(shared instanceof ArrayBuffer ? shared : shared);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sharedArr,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new ArrayBuffer(0),
      info: STORAGE_KEY_INFO,
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export async function encryptAtRest(plaintext: string, key: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH * 8 },
    key,
    encoded as BufferSource
  );
  return { iv, ciphertext: ciphertext instanceof ArrayBuffer ? ciphertext : (ciphertext as unknown as ArrayBuffer) };
}

export async function decryptAtRest(
  iv: Uint8Array,
  ciphertext: ArrayBuffer,
  key: CryptoKey
): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, tagLength: TAG_LENGTH * 8 },
    key,
    ciphertext as BufferSource
  );
  return new TextDecoder().decode(plaintext);
}

function b64Encode(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...u));
}

function b64Decode(s: string): Uint8Array {
  return new Uint8Array(atob(s).split('').map((c) => c.charCodeAt(0)));
}

export function encodeEncryptedPayload(iv: Uint8Array, ciphertext: ArrayBuffer): string {
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return b64Encode(combined);
}

export function decodeEncryptedPayload(encoded: string): { iv: Uint8Array; ciphertext: ArrayBuffer } {
  const combined = b64Decode(encoded);
  const iv = combined.slice(0, IV_LENGTH);
  const sliced = combined.slice(IV_LENGTH);
  const ciphertext = new Uint8Array(sliced).buffer;
  return { iv, ciphertext };
}

export async function getFromStore<T>(db: IDBDatabase, storeName: string, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const v = req.result;
      resolve(v === undefined ? undefined : (v as T));
    };
  });
}

export async function putInStore(db: IDBDatabase, storeName: string, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).put(value, key);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve();
  });
}

export async function deleteFromStore(db: IDBDatabase, storeName: string, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).delete(key);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve();
  });
}

export async function getAllKeysFromStore(db: IDBDatabase, storeName: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAllKeys();
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve((req.result as IDBValidKey[]).map(String));
  });
}

export async function clearStoreByPrefix(db: IDBDatabase, storeName: string, prefix: string): Promise<void> {
  const keys = await getAllKeysFromStore(db, storeName);
  for (const k of keys) {
    if (k.startsWith(prefix)) await deleteFromStore(db, storeName, k);
  }
}
