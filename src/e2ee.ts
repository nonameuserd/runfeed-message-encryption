/**
 * E2EE facade: key generation, session setup (X3DH), encrypt before send, decrypt on receive.
 * 1:1 via X3DH + Double Ratchet; group via Sender Keys (distribution over 1:1 sessions).
 * Call initE2EE(options) before using other APIs.
 */

import type { E2EECryptoOptions } from './types';
import { KeyChangedError, identityToDhBase64 } from './types';
import type { IdentityKeys, SignedPreKey, OneTimePreKey } from './keys';
import {
  generateIdentityKeys,
  generateSignedPreKey,
  generateOneTimePreKeys,
  exportIdentityPublic,
  exportIdentityDhBase64,
  exportSignedPreKeyPublic,
  exportOneTimePreKeyPublic,
  loadKeysFromStorage,
  persistKeysToStorage,
  clearStoredKeys,
  SIGNED_PREKEY_RETENTION,
} from './keys';
import { x3dhInitiator, x3dhResponder } from './x3dh';
import type { RemoteBundle } from './x3dh';
import {
  ratchetStateFromRoot,
  ratchetEncrypt,
  ratchetDecrypt,
  payloadToBase64,
  base64ToPayload,
} from './ratchet';
import { getSession, getRatchetState, getRatchetStatesForPeer, setRatchetState } from './session-store';
import {
  createSenderKeyState,
  senderKeyEncrypt,
  senderKeyDecrypt,
  type SenderKeySigningContext,
  type SenderKeyVerificationContext,
} from './sender-keys';
import type { SenderKeyState } from './sender-keys';
import {
  getSenderKey,
  setSenderKey,
  clearSenderKeys,
  getSenderKeyMemberSnapshot,
  setSenderKeyMemberSnapshot,
} from './sender-key-store';
import { clearSessions } from './session-store';
import { setStoragePrefixGetter } from './storage-prefix';

let options: E2EECryptoOptions | null = null;

/**
 * Initialize E2EE with device id and optional TOFU/verified-peers adapters. Call once before using encrypt/decrypt.
 */
export function initE2EE(opts: E2EECryptoOptions): void {
  options = opts;
  setStoragePrefixGetter(opts.getStoragePrefix);
}

function getOpts(): E2EECryptoOptions {
  if (!options) throw new Error('E2EE: call initE2EE(options) before using crypto');
  return options;
}

async function isPrivateKeyExtractable(privateKey: CryptoKey | undefined): Promise<boolean> {
  if (!privateKey) return false;
  try {
    await crypto.subtle.exportKey('pkcs8', privateKey);
    return true;
  } catch {
    return false;
  }
}

async function getMyDeviceId(): Promise<string> {
  const id = getOpts().getDeviceId();
  return typeof id === 'string' ? id : id;
}

function checkTofu(
  myUserId: string,
  peerUserId: string,
  peerDeviceId: string,
  identityKeyOrDh: string
): void {
  const tofu = getOpts().tofu;
  if (!tofu) return;
  const currentDh = identityToDhBase64(identityKeyOrDh);
  if (!currentDh) return;
  const first = tofu.getFirstSeenDh(myUserId, peerUserId, peerDeviceId);
  if (!first) {
    tofu.setFirstSeenDh(myUserId, peerUserId, peerDeviceId, currentDh);
    return;
  }
  if (first !== currentDh) {
    getOpts().onKeyChanged?.(peerUserId, peerDeviceId);
    throw new KeyChangedError(first, currentDh, peerUserId, peerDeviceId);
  }
}

const INITIAL_PREFIX = 'e2ee0:';
const CONTINUING_PREFIX = 'e2ee1:';
const GROUP_PREFIX = 'e2ee-group1:';
const SENDER_KEY_DISTRIBUTION_PREFIX = 'e2ee-senderkey0:';

let cachedIdentity: IdentityKeys | null = null;
let cachedSignedPreKey: SignedPreKey | null = null;
let cachedSignedPreKeysById = new Map<number, SignedPreKey>();
let cachedOneTimePreKeys = new Map<string, OneTimePreKey>();
let cachedConsumedOneTimePreKeys = new Map<string, OneTimePreKey>();

const ONE_TIME_PREKEY_BATCH = 20;
const ONE_TIME_PREKEY_MIN = 5;
// Keep a large archive of consumed OTKs so delayed initial packets can still recover.
const CONSUMED_ONE_TIME_PREKEY_RETENTION = 5000;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
const LAST_ROTATION_KEY = 'e2ee_signed_prekey_last_rotation';

export interface KeyBundleForUpload {
  identityKey: string;
  signedPreKey: { key: string; signature: string; keyId: number };
  oneTimePreKeys?: Array<{ key: string; keyId: string }>;
}

/**
 * Generate and cache identity + signed prekey + one-time prekeys. Call once (e.g. on app load or before first send).
 * Returns public bundle for PUT /me/keys.
 */
export async function ensureKeysGenerated(): Promise<KeyBundleForUpload> {
  if (!cachedIdentity || !cachedSignedPreKey) {
    const stored = await loadKeysFromStorage();
    if (stored) {
      cachedIdentity = stored.identity;
      cachedSignedPreKey = stored.signedPreKey;
      cachedSignedPreKeysById = new Map(stored.signedPreKeys.map((k) => [k.keyId, k]));
      cachedOneTimePreKeys = new Map(stored.oneTimePreKeys.map((k) => [k.keyId, k]));
      cachedConsumedOneTimePreKeys = new Map(
        (stored.consumedOneTimePreKeys ?? []).map((k) => [k.keyId, k])
      );
      if (!(await isPrivateKeyExtractable(cachedSignedPreKey.keyPair.privateKey))) {
        const nextKeyId = cachedSignedPreKey.keyId + 1;
        const replacement = await generateSignedPreKey(
          cachedIdentity.identitySignKeyPair.privateKey!,
          nextKeyId
        );
        cachedSignedPreKey = replacement;
        cachedSignedPreKeysById.set(replacement.keyId, replacement);
        const retained = Array.from(cachedSignedPreKeysById.values())
          .filter((k) => k.keyId !== replacement.keyId)
          .sort((a, b) => b.keyId - a.keyId)
          .slice(0, SIGNED_PREKEY_RETENTION);
        await persistKeysToStorage(
          cachedIdentity,
          replacement,
          Array.from(cachedOneTimePreKeys.values()),
          retained,
          Array.from(cachedConsumedOneTimePreKeys.values())
        );
      }
    } else {
      const identity = await generateIdentityKeys();
      const signedPreKey = await generateSignedPreKey(identity.identitySignKeyPair.privateKey!, 1);
      cachedIdentity = identity;
      cachedSignedPreKey = signedPreKey;
      cachedSignedPreKeysById = new Map([[signedPreKey.keyId, signedPreKey]]);
      await persistKeysToStorage(identity, signedPreKey, []);
    }
  }

  let newOneTimePreKeys: OneTimePreKey[] = [];
  if (cachedOneTimePreKeys.size < ONE_TIME_PREKEY_MIN) {
    newOneTimePreKeys = await generateOneTimePreKeys(ONE_TIME_PREKEY_BATCH);
    for (const k of newOneTimePreKeys) {
      cachedOneTimePreKeys.set(k.keyId, k);
    }
    const retained = Array.from(cachedSignedPreKeysById.values())
      .filter((k) => k.keyId !== cachedSignedPreKey!.keyId)
      .sort((a, b) => b.keyId - a.keyId)
      .slice(0, SIGNED_PREKEY_RETENTION);
    await persistKeysToStorage(
      cachedIdentity!,
      cachedSignedPreKey!,
      Array.from(cachedOneTimePreKeys.values()),
      retained,
      Array.from(cachedConsumedOneTimePreKeys.values())
    );
  }

  const [identityKey, signedPreKey] = await Promise.all([
    exportIdentityPublic(cachedIdentity!),
    exportSignedPreKeyPublic(cachedSignedPreKey!),
  ]);
  const oneTimePreKeys = newOneTimePreKeys.length
    ? await Promise.all(newOneTimePreKeys.map(exportOneTimePreKeyPublic))
    : undefined;
  return { identityKey, signedPreKey, oneTimePreKeys };
}

export async function resetE2EEState(): Promise<void> {
  cachedIdentity = null;
  cachedSignedPreKey = null;
  cachedSignedPreKeysById.clear();
  cachedOneTimePreKeys.clear();
  cachedConsumedOneTimePreKeys.clear();
  await clearStoredKeys();
  await clearSessions();
  await clearSenderKeys();
  const opts = options;
  if (opts?.clearVerifiedPeers) await opts.clearVerifiedPeers();
  opts?.tofu?.clear();
}

/**
 * Rotate signed prekey: generate new with keyId = current + 1, retain previous N, persist and return bundle for upload.
 * Call on a schedule (e.g. weekly). Returns null if rotation not needed or keys not loaded.
 */
export async function rotateSignedPreKeyIfDue(): Promise<KeyBundleForUpload | null> {
  if (!cachedIdentity || !cachedSignedPreKey) {
    await ensureKeysGenerated();
  }
  if (!cachedIdentity || !cachedSignedPreKey) return null;
  if (typeof window === 'undefined') return null;
  const raw = window.localStorage.getItem(LAST_ROTATION_KEY);
  const last = raw ? Number(raw) : 0;
  if (Number.isFinite(last) && Date.now() - last < SIGNED_PREKEY_ROTATION_MS) {
    return null;
  }
  const nextKeyId = cachedSignedPreKey.keyId + 1;
  const newSignedPreKey = await generateSignedPreKey(
    cachedIdentity.identitySignKeyPair.privateKey!,
    nextKeyId
  );
  const retained = Array.from(cachedSignedPreKeysById.values())
    .sort((a, b) => b.keyId - a.keyId)
    .slice(0, SIGNED_PREKEY_RETENTION);
  cachedSignedPreKey = newSignedPreKey;
  cachedSignedPreKeysById.set(newSignedPreKey.keyId, newSignedPreKey);
  await persistKeysToStorage(
    cachedIdentity,
    newSignedPreKey,
    Array.from(cachedOneTimePreKeys.values()),
    retained,
    Array.from(cachedConsumedOneTimePreKeys.values())
  );
  try {
    window.localStorage.setItem(LAST_ROTATION_KEY, String(Date.now()));
  } catch {
    // ignore
  }
  const [identityKey, signedPreKey] = await Promise.all([
    exportIdentityPublic(cachedIdentity),
    exportSignedPreKeyPublic(newSignedPreKey),
  ]);
  return { identityKey, signedPreKey, oneTimePreKeys: undefined };
}

/**
 * Return our public identity string (for safety number / key verification).
 * Uses cached keys or generates and caches. Same format as uploaded identityKey.
 */
export async function getMyIdentityPublic(): Promise<string> {
  const bundle = await ensureKeysGenerated();
  return bundle.identityKey;
}

const AAD_SEP = '\0';

function aadFromConversationId(conversationId: string, messageId?: string): ArrayBuffer {
  const s = messageId ? `${conversationId}${AAD_SEP}${messageId}` : conversationId;
  const u = new TextEncoder().encode(s);
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
}

/**
 * Establish session with peer as initiator (we send first). peerDeviceId for device-session binding (one session per peer device).
 * When myUserId and peerDeviceId are provided and TOFU is configured, first-seen identity key is stored; key change throws KeyChangedError.
 */
export async function ensureSessionWith(
  conversationId: string,
  peerUserId: string,
  theirBundle: RemoteBundle,
  peerDeviceId?: string,
  myUserId?: string
): Promise<void> {
  const existing = await getSession(conversationId, peerUserId, peerDeviceId);
  if (existing) {
    if (myUserId && peerDeviceId && theirBundle.identityKey) {
      checkTofu(myUserId, peerUserId, peerDeviceId, theirBundle.identityKey);
    }
    const existingSignedPreKeyId = existing.x3dh?.signedPreKeyId;
    const currentSignedPreKeyId = theirBundle.signedPreKey?.keyId;
    const needsReestablish =
      Number.isFinite(existingSignedPreKeyId) &&
      Number.isFinite(currentSignedPreKeyId) &&
      existingSignedPreKeyId !== currentSignedPreKeyId;
    if (!needsReestablish) return;
  }
  if (!cachedIdentity || !cachedSignedPreKey) await ensureKeysGenerated();
  if (!theirBundle.signedPreKey?.key || !theirBundle.signedPreKey.signature) {
    throw new Error('E2EE: peer missing signed prekey');
  }
  if (myUserId && peerDeviceId && theirBundle.identityKey) {
    checkTofu(myUserId, peerUserId, peerDeviceId, theirBundle.identityKey);
  }
  const result = await x3dhInitiator(cachedIdentity!, theirBundle);
  const state = await ratchetStateFromRoot(result.rootKey, {
    isInitiator: true,
    ourDhKeyPair: result.ephemeralKeyPair,
    theirDhPublicKeyBase64: theirBundle.signedPreKey.key,
  });
  await setRatchetState(
    conversationId,
    peerUserId,
    state,
    {
      signedPreKeyId: result.signedPreKeyId,
      oneTimePreKeyId: result.oneTimePreKeyId,
      initiator: true,
    },
    peerDeviceId
  );
}

/**
 * Encrypt plaintext for peer (optionally for a specific peer device). Session must exist.
 * When messageId is provided it is included in AAD to bind ciphertext to that message (use when API accepts client-generated message ids).
 */
export async function encryptForPeer(
  conversationId: string,
  peerUserId: string,
  plaintext: string,
  peerDeviceId?: string,
  messageId?: string
): Promise<string> {
  const state = await getRatchetState(conversationId, peerUserId, peerDeviceId);
  if (!state) throw new Error('E2EE: no session with peer; call ensureSessionWith first');
  const aad = aadFromConversationId(conversationId, messageId);
  const { payload, state: nextState } = await ratchetEncrypt(state, plaintext, aad);
  await setRatchetState(conversationId, peerUserId, nextState, undefined, peerDeviceId);
  const payloadB64 = payloadToBase64(payload);
  const senderDeviceId = await getMyDeviceId();
  const session = await getSession(conversationId, peerUserId, peerDeviceId);
  if (state.ns === 0 && session?.x3dh?.initiator) {
    const signedPreKeyId = session.x3dh?.signedPreKeyId;
    if (signedPreKeyId == null) throw new Error('E2EE: missing signed prekey id for initial message');
    const identityDh = await exportIdentityDhBase64(cachedIdentity!);
    const ephemeralDh = state.dhsPublicKeyB64;
    const oneTimeId = session?.x3dh?.oneTimePreKeyId ?? '-';
    return `${INITIAL_PREFIX}${senderDeviceId}:${identityDh}:${ephemeralDh}:${signedPreKeyId}:${oneTimeId}:${payloadB64}`;
  }
  return `${CONTINUING_PREFIX}${senderDeviceId}:${payloadB64}`;
}

/**
 * Decrypt payload from sender. If no session, treats payload as initial (e2ee0:...) and creates session.
 * conversationId (and optional messageId) are verified as AAD so ciphertext cannot be replayed or moved to another conversation/message.
 * When myUserId is provided and TOFU is configured, key change on initial message throws KeyChangedError.
 */
export async function decryptFrom(
  conversationId: string,
  senderId: string,
  ciphertextBase64: string,
  messageId?: string,
  myUserId?: string
): Promise<string> {
  const aad = aadFromConversationId(conversationId, messageId);
  if (ciphertextBase64.startsWith(INITIAL_PREFIX)) {
    const rest = ciphertextBase64.slice(INITIAL_PREFIX.length);
    const parts = rest.split(':');
    if (parts.length < 6) throw new Error('E2EE: invalid initial message format');
    const senderDeviceId = parts[0] ?? '';
    const theirIdentityDh = parts[1] ?? '';
    const theirEphemeralDh = parts[2] ?? '';
    const signedPreKeyId = Number(parts[3] ?? '');
    const oneTimePreKeyId = parts[4] ?? '';
    const payloadB64 = parts.slice(5).join(':');
    if (!senderDeviceId) throw new Error('E2EE: missing sender device id');
    const payload = base64ToPayload(payloadB64);
    let existingAttemptFailed = false;
    let candidateCount = 0;
    let candidateFailures = 0;

    // Replay-safe path: if a session already exists for this sender device, decrypt with it
    // instead of attempting X3DH again (which would fail after OTK consumption).
    const existing = await getRatchetState(conversationId, senderId, senderDeviceId);
    if (existing) {
      try {
        const { plaintext, state: nextState } = await ratchetDecrypt(existing, payload, aad);
        await setRatchetState(conversationId, senderId, nextState, undefined, senderDeviceId);
        return plaintext;
      } catch {
        // Existing session can be stale/out-of-sync; continue with recovery paths.
        existingAttemptFailed = true;
      }
    }

    // Recovery path for legacy/mismatched sender device ids.
    const candidates = await getRatchetStatesForPeer(conversationId, senderId);
    for (const candidate of candidates) {
      candidateCount += 1;
      try {
        const { plaintext, state: nextState } = await ratchetDecrypt(candidate.state, payload, aad);
        await setRatchetState(conversationId, senderId, nextState, undefined, senderDeviceId);
        return plaintext;
      } catch {
        // keep trying other candidate sessions
        candidateFailures += 1;
      }
    }

    if (myUserId) checkTofu(myUserId, senderId, senderDeviceId, theirIdentityDh);
    if (!cachedIdentity || !cachedSignedPreKey) await ensureKeysGenerated();
    if (!Number.isFinite(signedPreKeyId)) {
      throw new Error('E2EE: invalid signed prekey id');
    }
    const ourSignedPreKey = cachedSignedPreKeysById.get(signedPreKeyId);
    if (!ourSignedPreKey) {
      throw new Error('E2EE: signed prekey not found (rotated or expired)');
    }
    let oneTimePreKeyPrivate: CryptoKey | undefined;
    if (oneTimePreKeyId && oneTimePreKeyId !== '-') {
      const otk =
        cachedOneTimePreKeys.get(oneTimePreKeyId) ??
        cachedConsumedOneTimePreKeys.get(oneTimePreKeyId);
      if (!otk) {
        throw new Error(
          `E2EE: one-time prekey not found [senderDeviceId=${senderDeviceId} existingFailed=${existingAttemptFailed} candidates=${candidateCount} candidateFailures=${candidateFailures}]`
        );
      }
      oneTimePreKeyPrivate = otk.keyPair.privateKey!;
      if (cachedOneTimePreKeys.has(oneTimePreKeyId)) {
        cachedOneTimePreKeys.delete(oneTimePreKeyId);
        cachedConsumedOneTimePreKeys.set(oneTimePreKeyId, otk);
        while (cachedConsumedOneTimePreKeys.size > CONSUMED_ONE_TIME_PREKEY_RETENTION) {
          const oldest = cachedConsumedOneTimePreKeys.keys().next().value as string | undefined;
          if (!oldest) break;
          cachedConsumedOneTimePreKeys.delete(oldest);
        }
      }
      const retained = Array.from(cachedSignedPreKeysById.values())
        .filter((k) => k.keyId !== cachedSignedPreKey!.keyId)
        .sort((a, b) => b.keyId - a.keyId)
        .slice(0, SIGNED_PREKEY_RETENTION);
      await persistKeysToStorage(
        cachedIdentity!,
        cachedSignedPreKey!,
        Array.from(cachedOneTimePreKeys.values()),
        retained,
        Array.from(cachedConsumedOneTimePreKeys.values())
      );
    }
    const rootKey = await x3dhResponder(
      cachedIdentity!,
      ourSignedPreKey,
      theirIdentityDh,
      theirEphemeralDh,
      oneTimePreKeyPrivate
    );
    const state = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: ourSignedPreKey.keyPair,
      theirDhPublicKeyBase64: theirEphemeralDh,
    });
    const { plaintext, state: nextState } = await ratchetDecrypt(state, payload, aad);
    await setRatchetState(
      conversationId,
      senderId,
      nextState,
      { initiator: false },
      senderDeviceId
    );
    return plaintext;
  }
  if (ciphertextBase64.startsWith(CONTINUING_PREFIX)) {
    const payloadB64 = ciphertextBase64.slice(CONTINUING_PREFIX.length);
    const parts = payloadB64.split(':');
    if (parts.length < 2) throw new Error('E2EE: invalid payload');
    const senderDeviceId = parts[0] ?? '';
    const payload = parts.slice(1).join(':');
    if (!senderDeviceId) throw new Error('E2EE: missing sender device id');
    const payloadBytes = base64ToPayload(payload);
    let existingAttemptFailed = false;
    let candidateCount = 0;
    let candidateFailures = 0;
    const state = await getRatchetState(conversationId, senderId, senderDeviceId);
    if (state) {
      try {
        const { plaintext, state: nextState } = await ratchetDecrypt(state, payloadBytes, aad);
        await setRatchetState(conversationId, senderId, nextState, undefined, senderDeviceId);
        return plaintext;
      } catch {
        // Existing session can be stale/out-of-sync; continue with recovery candidates.
        existingAttemptFailed = true;
      }
    }

    const candidates = await getRatchetStatesForPeer(conversationId, senderId);
    for (const candidate of candidates) {
      candidateCount += 1;
      try {
        const { plaintext, state: nextState } = await ratchetDecrypt(
          candidate.state,
          payloadBytes,
          aad
        );
        await setRatchetState(conversationId, senderId, nextState, undefined, senderDeviceId);
        return plaintext;
      } catch {
        // Try next candidate; states can be out of sync for old device IDs.
        candidateFailures += 1;
      }
    }
    throw new Error(
      `E2EE: no session with sender [senderDeviceId=${senderDeviceId} existingFailed=${existingAttemptFailed} candidates=${candidateCount} candidateFailures=${candidateFailures}]`
    );
  }
  throw new Error('E2EE: unknown payload format');
}

/**
 * Check if a payload looks like our E2EE format (1:1 or group or sender key distribution).
 */
export function isE2EEPayload(payload: string): boolean {
  return (
    payload.startsWith(INITIAL_PREFIX) ||
    payload.startsWith(CONTINUING_PREFIX) ||
    payload.startsWith(GROUP_PREFIX) ||
    payload.startsWith(SENDER_KEY_DISTRIBUTION_PREFIX)
  );
}

/** True if payload is group message or sender key distribution (use decryptFromGroup). */
export function isGroupE2EEPayload(payload: string): boolean {
  return payload.startsWith(GROUP_PREFIX) || payload.startsWith(SENDER_KEY_DISTRIBUTION_PREFIX);
}

const DISTRIBUTION_SEP = ':';

function buildDistributionPayload(
  conversationId: string,
  senderUserId: string,
  senderDeviceId: string,
  state: SenderKeyState
): string {
  const chainKeyB64 = payloadToBase64(state.chainKey);
  const fields = [conversationId, senderUserId, senderDeviceId, chainKeyB64, state.iteration];
  if (state.signingPublicKey) {
    fields.push(payloadToBase64(state.signingPublicKey));
  }
  return fields.join(DISTRIBUTION_SEP);
}

function parseDistributionPayload(payload: string): {
  conversationId: string;
  senderUserId: string;
  senderDeviceId: string;
  state: SenderKeyState;
} | null {
  const parts = payload.split(DISTRIBUTION_SEP);
  if (parts.length < 5) return null;
  const conversationId = parts[0] ?? '';
  const senderUserId = parts[1] ?? '';
  const senderDeviceId = parts[2] ?? '';
  const chainKeyB64 = parts[3] ?? '';
  const iteration = parseInt(parts[4] ?? '0', 10);
  if (!senderDeviceId || isNaN(iteration) || iteration < 0) return null;
  const chainKey = base64ToPayload(chainKeyB64);
  const state: SenderKeyState = { chainKey, iteration, skippedKeys: {} };
  if (parts.length >= 6 && parts[5]) {
    state.signingPublicKey = base64ToPayload(parts[5]);
  }
  return {
    conversationId,
    senderUserId,
    senderDeviceId,
    state,
  };
}

/**
 * Ensure we have a sender key for this conversation and 1:1 sessions with all members.
 * Returns distribution payloads to send only when we just created the key (first group message). Caller sends those first, then the group message.
 */
export async function ensureGroupSenderKey(
  conversationId: string,
  myUserId: string,
  memberIds: string[],
  getBundlesForUser: (userId: string) => Promise<Array<{ deviceId: string; bundle: RemoteBundle }>>
): Promise<{ distributionDevicePayloads?: Record<string, string> }> {
  const myDeviceId = await getMyDeviceId();
  const uniqueMembers = Array.from(new Set(memberIds));
  const others = uniqueMembers.filter((id) => id !== myUserId);

  let state = await getSenderKey(conversationId, myUserId, myDeviceId);
  const prevMembers = await getSenderKeyMemberSnapshot(conversationId, myUserId, myDeviceId);
  const prevSet = new Set(prevMembers ?? []);
  const nextSet = new Set(uniqueMembers);
  const removed = prevMembers ? prevMembers.filter((id) => !nextSet.has(id)) : [];
  const added = prevMembers ? uniqueMembers.filter((id) => !prevSet.has(id)) : uniqueMembers;
  const shouldRotate = removed.length > 0;
  const shouldDistribute = !state || !prevMembers || shouldRotate || added.length > 0;

  if (!state || shouldRotate) {
    state = await createSenderKeyState();
    await setSenderKey(conversationId, myUserId, myDeviceId, state);
  }

  if (!shouldDistribute) return {};

  const distributionPayload = buildDistributionPayload(
    conversationId,
    myUserId,
    myDeviceId,
    state
  );
  const distributionDevicePayloads: Record<string, string> = {};
  for (const recipientId of others) {
    const devices = await getBundlesForUser(recipientId);
    for (const device of devices) {
      await ensureSessionWith(conversationId, recipientId, device.bundle, device.deviceId, myUserId);
      const encrypted = await encryptForPeer(
        conversationId,
        recipientId,
        distributionPayload,
        device.deviceId
      );
      distributionDevicePayloads[device.deviceId] = `${SENDER_KEY_DISTRIBUTION_PREFIX}${encrypted}`;
    }
  }

  await setSenderKeyMemberSnapshot(conversationId, myUserId, myDeviceId, uniqueMembers);
  return { distributionDevicePayloads };
}

/**
 * Encrypt plaintext for a group conversation. Uses our sender key for this conversation; create and distribute it first via ensureGroupSenderKey.
 * Ciphertext is bound to conversationId (and optional messageId) via AAD. Signs with per-sender key when available.
 */
export async function encryptForGroup(
  conversationId: string,
  myUserId: string,
  plaintext: string,
  messageId?: string
): Promise<string> {
  const myDeviceId = await getMyDeviceId();
  let state = await getSenderKey(conversationId, myUserId, myDeviceId);
  if (!state) {
    state = await createSenderKeyState();
    await setSenderKey(conversationId, myUserId, myDeviceId, state);
  }
  const aad = aadFromConversationId(conversationId, messageId);
  const signingContext: SenderKeySigningContext = { conversationId, senderDeviceId: myDeviceId };
  const { payload, state: nextState } = await senderKeyEncrypt(
    state,
    plaintext,
    aad,
    signingContext
  );
  await setSenderKey(conversationId, myUserId, myDeviceId, nextState);
  return `${GROUP_PREFIX}${myDeviceId}:${payloadToBase64(payload)}`;
}

/**
 * Decrypt a group or sender-key-distribution message. Returns { type: 'message', plaintext } or { type: 'distribution' } (no plaintext to show).
 * messageId binds to the same value used when encrypting (when client-generated message ids are used).
 */
export async function decryptFromGroup(
  senderId: string,
  conversationId: string,
  ciphertextBase64: string,
  messageId?: string,
  myUserId?: string
): Promise<{ type: 'message'; plaintext: string } | { type: 'distribution' }> {
  if (ciphertextBase64.startsWith(SENDER_KEY_DISTRIBUTION_PREFIX)) {
    const rest = ciphertextBase64.slice(SENDER_KEY_DISTRIBUTION_PREFIX.length);
    const decrypted = await decryptFrom(conversationId, senderId, rest, undefined, myUserId);
    const parsed = parseDistributionPayload(decrypted);
    if (parsed && parsed.conversationId === conversationId) {
      await setSenderKey(parsed.conversationId, parsed.senderUserId, parsed.senderDeviceId, parsed.state);
      return { type: 'distribution' };
    }
    return { type: 'distribution' };
  }

  if (ciphertextBase64.startsWith(GROUP_PREFIX)) {
    const payloadB64 = ciphertextBase64.slice(GROUP_PREFIX.length);
    const parts = payloadB64.split(':');
    if (parts.length < 2) throw new Error('E2EE: invalid group payload');
    const senderDeviceId = parts[0] ?? '';
    const payload = parts.slice(1).join(':');
    if (!senderDeviceId) throw new Error('E2EE: missing sender device id');
    const state = await getSenderKey(conversationId, senderId, senderDeviceId);
    if (!state)
      throw new Error('E2EE: no sender key for this group sender; need distribution first');
    const payloadBytes = base64ToPayload(payload);
    const aad = aadFromConversationId(conversationId, messageId);
    const verificationContext: SenderKeyVerificationContext = {
      conversationId,
      senderDeviceId,
    };
    const { plaintext, state: nextState } = await senderKeyDecrypt(
      state,
      payloadBytes,
      aad,
      verificationContext
    );
    await setSenderKey(conversationId, senderId, senderDeviceId, nextState);
    return { type: 'message', plaintext };
  }

  throw new Error('E2EE: unknown group payload format');
}
