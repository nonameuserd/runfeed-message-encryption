/**
 * Sender key state per (conversationId, senderUserId, senderDeviceId).
 * Persisted in IndexedDB with state encrypted at rest (identity-derived key).
 */

import type { SenderKeyState } from './sender-keys';
import {
  senderKeyStateToJson,
  senderKeyStateToJsonAsync,
  senderKeyStateFromJson,
  senderKeyStateFromJsonAsync,
} from './sender-keys';
import { getStorageEncryptionKey } from './keys';
import {
  openDb,
  STORE_SENDER_KEYS,
  getFromStore,
  putInStore,
  getAllKeysFromStore,
  deleteFromStore,
  encryptAtRest,
  decryptAtRest,
  encodeEncryptedPayload,
  decodeEncryptedPayload,
} from './idb';
import { getStoragePrefix } from './storage-prefix';

function key(conversationId: string, senderUserId: string, senderDeviceId: string): string {
  return `${conversationId}:${senderUserId}:${senderDeviceId}`;
}

const STORAGE_PREFIX = 'e2ee_sender_key_v1:';
const MEMBERS_PREFIX = 'e2ee_sender_key_members_v1:';
const store = new Map<string, string>();
const memberSnapshots = new Map<string, string[]>();

function storageKey(conversationId: string, senderUserId: string, senderDeviceId: string): string {
  const base = `${STORAGE_PREFIX}${key(conversationId, senderUserId, senderDeviceId)}`;
  const p = getStoragePrefix();
  return p ? `${p}:${base}` : base;
}

function membersStorageKey(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string
): string {
  const base = `${MEMBERS_PREFIX}${key(conversationId, senderUserId, senderDeviceId)}`;
  const p = getStoragePrefix();
  return p ? `${p}:${base}` : base;
}

interface StoredRecord {
  encrypted?: string;
  plain?: string;
}

async function loadFromStorage(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string
): Promise<string | undefined> {
  if (typeof indexedDB === 'undefined') return undefined;
  const key = storageKey(conversationId, senderUserId, senderDeviceId);
  const db = await openDb();
  let record = await getFromStore<StoredRecord>(db, STORE_SENDER_KEYS, key);
  db.close();
  if (!record && typeof window !== 'undefined') {
    try {
      const raw = window.localStorage.getItem(key);
      if (raw) {
        const kek = await getStorageEncryptionKey();
        let rec: StoredRecord;
        if (kek) {
          const { iv, ciphertext } = await encryptAtRest(raw, kek);
          rec = { encrypted: encodeEncryptedPayload(iv, ciphertext) };
        } else {
          rec = { plain: raw };
        }
        const db2 = await openDb();
        await putInStore(db2, STORE_SENDER_KEYS, key, rec);
        db2.close();
        window.localStorage.removeItem(key);
        return raw;
      }
    } catch {
      // ignore
    }
  }
  if (!record) return undefined;
  if (record.plain) return record.plain;
  if (!record.encrypted) return undefined;
  const kek = await getStorageEncryptionKey();
  if (!kek) return undefined;
  try {
    const { iv, ciphertext } = decodeEncryptedPayload(record.encrypted);
    return await decryptAtRest(iv, ciphertext, kek);
  } catch {
    return undefined;
  }
}

async function saveToStorage(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string,
  raw: string
): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const kek = await getStorageEncryptionKey();
  let record: StoredRecord;
  if (kek) {
    const { iv, ciphertext } = await encryptAtRest(raw, kek);
    record = { encrypted: encodeEncryptedPayload(iv, ciphertext) };
  } else {
    record = { plain: raw };
  }
  const db = await openDb();
  await putInStore(
    db,
    STORE_SENDER_KEYS,
    storageKey(conversationId, senderUserId, senderDeviceId),
    record
  );
  db.close();
}

async function clearStorageByPrefix(prefix: string): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const db = await openDb();
  const keys = await getAllKeysFromStore(db, STORE_SENDER_KEYS);
  for (const k of keys) {
    if (k.startsWith(prefix)) await deleteFromStore(db, STORE_SENDER_KEYS, k);
  }
  db.close();
}

export async function clearSenderKeys(): Promise<void> {
  store.clear();
  memberSnapshots.clear();
  await clearStorageByPrefix(STORAGE_PREFIX);
  await clearStorageByPrefix(MEMBERS_PREFIX);
}

export async function getSenderKey(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string
): Promise<SenderKeyState | undefined> {
  const k = key(conversationId, senderUserId, senderDeviceId);
  const raw = store.get(k) ?? (await loadFromStorage(conversationId, senderUserId, senderDeviceId));
  if (!raw) return undefined;
  store.set(k, raw);
  const hasPrivate = raw.includes('signingPrivateKeyPkcs8B64');
  if (hasPrivate) {
    return senderKeyStateFromJsonAsync(raw);
  }
  return senderKeyStateFromJson(raw);
}

export async function setSenderKey(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string,
  state: SenderKeyState
): Promise<void> {
  const raw = state.signingPrivateKey
    ? await senderKeyStateToJsonAsync(state)
    : senderKeyStateToJson(state);
  store.set(key(conversationId, senderUserId, senderDeviceId), raw);
  await saveToStorage(conversationId, senderUserId, senderDeviceId, raw);
}

export function hasSenderKey(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string
): boolean {
  const k = key(conversationId, senderUserId, senderDeviceId);
  return store.has(k);
}

export async function getSenderKeyMemberSnapshot(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string
): Promise<string[] | undefined> {
  const k = key(conversationId, senderUserId, senderDeviceId);
  const cached = memberSnapshots.get(k);
  if (cached) return cached;
  if (typeof indexedDB === 'undefined') return undefined;
  const membersKey = membersStorageKey(conversationId, senderUserId, senderDeviceId);
  const db = await openDb();
  let raw = await getFromStore<string>(db, STORE_SENDER_KEYS, membersKey);
  db.close();
  if (raw === undefined && typeof window !== 'undefined') {
    try {
      const legacy = window.localStorage.getItem(membersKey);
      if (legacy) {
        const parsed = JSON.parse(legacy) as string[];
        if (Array.isArray(parsed)) {
          const db2 = await openDb();
          await putInStore(db2, STORE_SENDER_KEYS, membersKey, legacy);
          db2.close();
          window.localStorage.removeItem(membersKey);
          memberSnapshots.set(k, parsed);
          return parsed;
        }
      }
    } catch {
      // ignore
    }
  }
  if (raw === undefined) return undefined;
  try {
    const parsed = typeof raw === 'string' ? (JSON.parse(raw) as string[]) : raw;
    if (!Array.isArray(parsed)) return undefined;
    memberSnapshots.set(k, parsed);
    return parsed;
  } catch {
    return undefined;
  }
}

export async function setSenderKeyMemberSnapshot(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string,
  memberIds: string[]
): Promise<void> {
  const unique = Array.from(new Set(memberIds));
  const k = key(conversationId, senderUserId, senderDeviceId);
  memberSnapshots.set(k, unique);
  if (typeof indexedDB === 'undefined') return;
  const db = await openDb();
  await putInStore(
    db,
    STORE_SENDER_KEYS,
    membersStorageKey(conversationId, senderUserId, senderDeviceId),
    JSON.stringify(unique)
  );
  db.close();
}
