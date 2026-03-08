/**
 * Session store per (conversationId, peerUserId, peerDeviceId).
 * Persisted in IndexedDB with ratchet state encrypted at rest (identity-derived key).
 */

import type { RatchetState } from './ratchet';
import { ratchetStateToJson, ratchetStateFromJson } from './ratchet';
import { getStorageEncryptionKey } from './keys';
import {
  openDb,
  STORE_SESSIONS,
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

export interface StoredSession {
  ratchetStateJson: string;
  x3dh?: {
    signedPreKeyId?: number;
    oneTimePreKeyId?: string;
    initiator?: boolean;
  };
}

function sessionKey(conversationId: string, peerUserId: string, peerDeviceId?: string): string {
  return peerDeviceId ? `${conversationId}:${peerUserId}:${peerDeviceId}` : `${conversationId}:${peerUserId}`;
}

const STORAGE_PREFIX = 'e2ee_session_v1:';
const sessions = new Map<string, StoredSession>();

function idbKey(conversationId: string, peerUserId: string, peerDeviceId?: string): string {
  const base = `${STORAGE_PREFIX}${sessionKey(conversationId, peerUserId, peerDeviceId)}`;
  const p = getStoragePrefix();
  return p ? `${p}:${base}` : base;
}

function legacyIdbKey(conversationId: string, peerUserId: string, peerDeviceId?: string): string {
  return `${STORAGE_PREFIX}${sessionKey(conversationId, peerUserId, peerDeviceId)}`;
}

interface StoredRecord {
  encrypted?: string;
  plain?: StoredSession;
}

async function loadFromStorage(
  conversationId: string,
  peerUserId: string,
  peerDeviceId?: string
): Promise<StoredSession | undefined> {
  if (typeof indexedDB === 'undefined') return undefined;
  const key = idbKey(conversationId, peerUserId, peerDeviceId);
  const db = await openDb();
  let record = await getFromStore<StoredRecord>(db, STORE_SESSIONS, key);
  if (!record && getStoragePrefix()) {
    const legacyKey = legacyIdbKey(conversationId, peerUserId, peerDeviceId);
    const legacy = await getFromStore<StoredRecord>(db, STORE_SESSIONS, legacyKey);
    if (legacy) {
      // Migrate legacy unscoped session to current scoped namespace.
      await putInStore(db, STORE_SESSIONS, key, legacy);
      await deleteFromStore(db, STORE_SESSIONS, legacyKey);
      record = legacy;
    }
  }
  db.close();
  if (!record && typeof window !== 'undefined') {
    try {
      const raw = window.localStorage.getItem(key);
      if (raw) {
        const parsed = JSON.parse(raw) as StoredSession;
        if (parsed && typeof parsed.ratchetStateJson === 'string') {
          const kek = await getStorageEncryptionKey();
          let rec: StoredRecord;
          if (kek) {
            const { iv, ciphertext } = await encryptAtRest(JSON.stringify(parsed), kek);
            rec = { encrypted: encodeEncryptedPayload(iv, ciphertext) };
          } else {
            rec = { plain: parsed };
          }
          const db2 = await openDb();
          await putInStore(db2, STORE_SESSIONS, key, rec);
          db2.close();
          window.localStorage.removeItem(key);
          return parsed;
        }
      }
    } catch {
      // ignore
    }
  }
  if (!record) return undefined;
  if (record.plain && typeof record.plain.ratchetStateJson === 'string') return record.plain;
  if (!record.encrypted) return undefined;
  const kek = await getStorageEncryptionKey();
  if (!kek) return undefined;
  try {
    const { iv, ciphertext } = decodeEncryptedPayload(record.encrypted);
    const plain = await decryptAtRest(iv, ciphertext, kek);
    const parsed = JSON.parse(plain) as StoredSession;
    if (!parsed || typeof parsed.ratchetStateJson !== 'string') return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

async function saveToStorage(
  conversationId: string,
  peerUserId: string,
  session: StoredSession,
  peerDeviceId?: string
): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const key = idbKey(conversationId, peerUserId, peerDeviceId);
  const kek = await getStorageEncryptionKey();
  let record: StoredRecord;
  if (kek) {
    const { iv, ciphertext } = await encryptAtRest(JSON.stringify(session), kek);
    record = { encrypted: encodeEncryptedPayload(iv, ciphertext) };
  } else {
    record = { plain: session };
  }
  const db = await openDb();
  await putInStore(db, STORE_SESSIONS, key, record);
  db.close();
}

async function clearStorageByPrefix(prefix: string): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  const db = await openDb();
  const keys = await getAllKeysFromStore(db, STORE_SESSIONS);
  for (const k of keys) {
    if (k.startsWith(prefix)) await deleteFromStore(db, STORE_SESSIONS, k);
  }
  db.close();
}

export async function clearSessions(): Promise<void> {
  sessions.clear();
  await clearStorageByPrefix(STORAGE_PREFIX);
}

export async function getSession(
  conversationId: string,
  peerUserId: string,
  peerDeviceId?: string
): Promise<StoredSession | undefined> {
  const key = sessionKey(conversationId, peerUserId, peerDeviceId);
  const existing = sessions.get(key);
  if (existing) return existing;
  const stored = await loadFromStorage(conversationId, peerUserId, peerDeviceId);
  if (stored) sessions.set(key, stored);
  return stored;
}

export async function setSession(
  conversationId: string,
  peerUserId: string,
  state: RatchetState,
  x3dh?: StoredSession['x3dh'],
  peerDeviceId?: string
): Promise<void> {
  const existing = await getSession(conversationId, peerUserId, peerDeviceId);
  const entry: StoredSession = {
    ratchetStateJson: ratchetStateToJson(state),
    x3dh: x3dh ?? existing?.x3dh,
  };
  sessions.set(sessionKey(conversationId, peerUserId, peerDeviceId), entry);
  await saveToStorage(conversationId, peerUserId, entry, peerDeviceId);
}

export async function getRatchetState(
  conversationId: string,
  peerUserId: string,
  peerDeviceId?: string
): Promise<RatchetState | undefined> {
  const s = await getSession(conversationId, peerUserId, peerDeviceId);
  if (!s) return undefined;
  return ratchetStateFromJson(s.ratchetStateJson);
}

export async function setRatchetState(
  conversationId: string,
  peerUserId: string,
  state: RatchetState,
  x3dh?: StoredSession['x3dh'],
  peerDeviceId?: string
): Promise<void> {
  await setSession(conversationId, peerUserId, state, x3dh, peerDeviceId);
}

/**
 * Return all stored ratchet states for a peer in a conversation across known device IDs.
 * Useful as a recovery path when sender device ID changes but an older session still exists.
 */
export async function getRatchetStatesForPeer(
  conversationId: string,
  peerUserId: string
): Promise<Array<{ peerDeviceId?: string; state: RatchetState }>> {
  const prefix = sessionKey(conversationId, peerUserId);
  const found = new Map<string, StoredSession>();

  for (const [k, v] of sessions.entries()) {
    if (k === prefix || k.startsWith(`${prefix}:`)) {
      found.set(k, v);
    }
  }

  if (typeof indexedDB !== 'undefined') {
    const p = getStoragePrefix();
    const scopedPrefix = p ? `${p}:${STORAGE_PREFIX}${prefix}` : `${STORAGE_PREFIX}${prefix}`;
    const legacyPrefix = `${STORAGE_PREFIX}${prefix}`;
    const db = await openDb();
    const keys = await getAllKeysFromStore(db, STORE_SESSIONS);
    for (const k of keys) {
      const isScoped = k === scopedPrefix || k.startsWith(`${scopedPrefix}:`);
      const isLegacy = p ? k === legacyPrefix || k.startsWith(`${legacyPrefix}:`) : false;
      if (!isScoped && !isLegacy) continue;
      const activePrefix = isScoped ? scopedPrefix : legacyPrefix;
      if (k === activePrefix) {
        if (!found.has(prefix)) {
          const s = await loadFromStorage(
            conversationId,
            peerUserId,
            undefined
          );
          if (s) found.set(prefix, s);
        }
        continue;
      }
      const deviceId = k.slice(activePrefix.length + 1);
      if (!deviceId) continue;
      const memKey = `${prefix}:${deviceId}`;
      if (found.has(memKey)) continue;
      const s = await loadFromStorage(conversationId, peerUserId, deviceId);
      if (s) found.set(memKey, s);
    }
    db.close();
  }

  const out: Array<{ peerDeviceId?: string; state: RatchetState }> = [];
  for (const [k, s] of found.entries()) {
    try {
      const state = await ratchetStateFromJson(s.ratchetStateJson);
      const suffix = k.slice(prefix.length);
      const peerDeviceId = suffix.startsWith(':') ? suffix.slice(1) : undefined;
      out.push({ peerDeviceId, state });
    } catch {
      // ignore invalid state
    }
  }
  return out;
}
