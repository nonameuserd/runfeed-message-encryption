import { describe, expect, it } from 'vitest';
import {
  payloadToBase64,
  ratchetDecrypt,
  ratchetEncrypt,
  ratchetStateFromJson,
  ratchetStateFromRoot,
  ratchetStateToJson,
} from './ratchet';
import {
  createSenderKeyState,
  senderKeyDecrypt,
  senderKeyEncrypt,
  senderKeyStateFromJson,
  senderKeyStateToJson,
  type SenderKeyState,
} from './sender-keys';
import {
  decryptFrom,
  ensureKeysGenerated,
  ensureSessionWith,
  encryptForPeer,
  initE2EE,
  resetE2EEState,
} from './e2ee';
import { clearSessions, getRatchetState, getSession, setRatchetState } from './session-store';
import {
  exportIdentityPublic,
  exportOneTimePreKeyPublic,
  exportSignedPreKeyPublic,
  generateIdentityKeys,
  generateOneTimePreKeys,
  generateSignedPreKey,
} from './keys';

const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;

function toBase64(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

async function exportDhPublicKeyBase64(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return toBase64(raw);
}

function randomRootKey(): ArrayBuffer {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function aad(conversationId: string): ArrayBuffer {
  const u8 = new TextEncoder().encode(conversationId);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

describe('replay regression', () => {
  it('double-ratchet decrypt remains stable on duplicate decrypt + replay after state reload', async () => {
    // GIVEN
    const [senderDh, receiverDh] = await Promise.all([
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
    ]);
    const [senderPub, receiverPub] = await Promise.all([
      exportDhPublicKeyBase64(senderDh.publicKey),
      exportDhPublicKeyBase64(receiverDh.publicKey),
    ]);
    const rootKey = randomRootKey();
    const conversationAad = aad('conv-1');

    const senderState = await ratchetStateFromRoot(rootKey, {
      isInitiator: true,
      ourDhKeyPair: senderDh,
      theirDhPublicKeyBase64: receiverPub,
    });
    const receiverState = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });

    const encrypted = await ratchetEncrypt(senderState, 'hi', conversationAad);

    // WHEN
    const firstDecrypt = await ratchetDecrypt(receiverState, encrypted.payload, conversationAad);
    const duplicateDecrypt = await ratchetDecrypt(
      firstDecrypt.state,
      encrypted.payload,
      conversationAad
    );
    const restored = await ratchetStateFromJson(ratchetStateToJson(firstDecrypt.state));
    const replayAfterRestore = await ratchetDecrypt(restored, encrypted.payload, conversationAad);

    // THEN
    expect(firstDecrypt.plaintext).toBe('hi');
    expect(duplicateDecrypt.plaintext).toBe('hi');
    expect(replayAfterRestore.plaintext).toBe('hi');
  });

  it('sender-key decrypt remains stable on duplicate decrypt + replay after state reload', async () => {
    // GIVEN
    const conversationId = 'group-conv-1';
    const senderDeviceId = 'sender-device-1';
    const conversationAad = aad(conversationId);

    const senderState = await createSenderKeyState();
    const receiverState: SenderKeyState = {
      chainKey: senderState.chainKey.slice(0),
      iteration: senderState.iteration,
      skippedKeys: {},
      signingPublicKey: senderState.signingPublicKey?.slice(0),
    };

    const encrypted = await senderKeyEncrypt(senderState, 'hello-group', conversationAad, {
      conversationId,
      senderDeviceId,
    });

    // WHEN
    const firstDecrypt = await senderKeyDecrypt(receiverState, encrypted.payload, conversationAad, {
      conversationId,
      senderDeviceId,
    });
    const duplicateDecrypt = await senderKeyDecrypt(
      firstDecrypt.state,
      encrypted.payload,
      conversationAad,
      {
        conversationId,
        senderDeviceId,
      }
    );
    const restored = senderKeyStateFromJson(senderKeyStateToJson(firstDecrypt.state));
    const replayAfterRestore = await senderKeyDecrypt(restored, encrypted.payload, conversationAad, {
      conversationId,
      senderDeviceId,
    });

    // THEN
    expect(firstDecrypt.plaintext).toBe('hello-group');
    expect(duplicateDecrypt.plaintext).toBe('hello-group');
    expect(replayAfterRestore.plaintext).toBe('hello-group');
  });

  it('decryptFrom recovers when continuing payload senderDeviceId changed', async () => {
    // GIVEN
    await clearSessions();
    const [senderDh, receiverDh] = await Promise.all([
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
    ]);
    const [senderPub, receiverPub] = await Promise.all([
      exportDhPublicKeyBase64(senderDh.publicKey),
      exportDhPublicKeyBase64(receiverDh.publicKey),
    ]);
    const rootKey = randomRootKey();
    const conversationId = 'conv-device-rebind';
    const senderId = 'sender-user';
    const oldDeviceId = 'sender-old-device';
    const newDeviceId = 'sender-new-device';

    const senderState = await ratchetStateFromRoot(rootKey, {
      isInitiator: true,
      ourDhKeyPair: senderDh,
      theirDhPublicKeyBase64: receiverPub,
    });
    const receiverState = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });
    await setRatchetState(conversationId, senderId, receiverState, undefined, oldDeviceId);

    const encrypted = await ratchetEncrypt(senderState, 'rebind-ok', aad(conversationId));
    const continuingPayload = `e2ee1:${newDeviceId}:${payloadToBase64(encrypted.payload)}`;

    // WHEN
    const plaintext = await decryptFrom(conversationId, senderId, continuingPayload);
    const reboundState = await getRatchetState(conversationId, senderId, newDeviceId);

    // THEN
    expect(plaintext).toBe('rebind-ok');
    expect(reboundState).toBeDefined();
  });

  it('decryptFrom replays e2ee0 initial payload via existing session without requiring OTK again', async () => {
    // GIVEN
    await clearSessions();
    const [senderDh, receiverDh] = await Promise.all([
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
    ]);
    const [senderPub, receiverPub] = await Promise.all([
      exportDhPublicKeyBase64(senderDh.publicKey),
      exportDhPublicKeyBase64(receiverDh.publicKey),
    ]);
    const rootKey = randomRootKey();
    const conversationId = 'conv-initial-replay';
    const senderId = 'sender-user';
    const senderDeviceId = 'sender-device';

    const senderState = await ratchetStateFromRoot(rootKey, {
      isInitiator: true,
      ourDhKeyPair: senderDh,
      theirDhPublicKeyBase64: receiverPub,
    });
    const receiverState = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });
    await setRatchetState(conversationId, senderId, receiverState, undefined, senderDeviceId);

    const encrypted = await ratchetEncrypt(senderState, 'initial-replay-ok', aad(conversationId));
    const fakeInitialPayload =
      `e2ee0:${senderDeviceId}:ignoredIdentity:ignoredEph:1:otk-consumed:${payloadToBase64(encrypted.payload)}`;

    // WHEN
    const plaintext = await decryptFrom(conversationId, senderId, fakeInitialPayload);

    // THEN
    expect(plaintext).toBe('initial-replay-ok');
  });

  it('decryptFrom falls back when same-device session exists but is stale', async () => {
    // GIVEN
    await clearSessions();
    const [senderDh, receiverDh] = await Promise.all([
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
      crypto.subtle.generateKey(P256, true, ['deriveKey', 'deriveBits']),
    ]);
    const [senderPub, receiverPub] = await Promise.all([
      exportDhPublicKeyBase64(senderDh.publicKey),
      exportDhPublicKeyBase64(receiverDh.publicKey),
    ]);
    const rootKey = randomRootKey();
    const conversationId = 'conv-stale-existing';
    const senderId = 'sender-user';
    const senderDeviceId = 'sender-device';

    const senderState = await ratchetStateFromRoot(rootKey, {
      isInitiator: true,
      ourDhKeyPair: senderDh,
      theirDhPublicKeyBase64: receiverPub,
    });
    const receiverState = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });

    const encrypted = await ratchetEncrypt(senderState, 'recover-after-stale', aad(conversationId));
    const continuingPayload = `e2ee1:${senderDeviceId}:${payloadToBase64(encrypted.payload)}`;

    const staleState = await ratchetStateFromRoot(randomRootKey(), {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });
    await setRatchetState(conversationId, senderId, staleState, undefined, senderDeviceId);
    await setRatchetState(conversationId, senderId, receiverState, undefined, 'sender-device-old');

    // WHEN
    const plaintext = await decryptFrom(conversationId, senderId, continuingPayload);

    // THEN
    expect(plaintext).toBe('recover-after-stale');
  });

  it('decryptFrom can replay e2ee0 after session loss using archived consumed OTK', async () => {
    // GIVEN
    initE2EE({
      getDeviceId: () => 'device-a',
      getStoragePrefix: () => 'user-a',
    });
    await resetE2EEState();

    const me = await ensureKeysGenerated();
    await ensureSessionWith(
      'conv-otk-archive',
      'peer-user',
      {
        identityKey: me.identityKey,
        signedPreKey: me.signedPreKey,
        oneTimePreKeys: me.oneTimePreKeys,
      },
      'peer-device',
      'user-a'
    );
    const initialPayload = await encryptForPeer(
      'conv-otk-archive',
      'peer-user',
      'hello-archive',
      'peer-device',
      'msg-archive'
    );
    const first = await decryptFrom(
      'conv-otk-archive',
      'peer-user',
      initialPayload,
      'msg-archive',
      'user-a'
    );
    await clearSessions();

    // WHEN
    const replay = await decryptFrom(
      'conv-otk-archive',
      'peer-user',
      initialPayload,
      'msg-archive',
      'user-a'
    );

    // THEN
    expect(initialPayload.startsWith('e2ee0:')).toBe(true);
    expect(first).toBe('hello-archive');
    expect(replay).toBe('hello-archive');
  });

  it('ensureSessionWith re-establishes when peer signed prekey id changes', async () => {
    // GIVEN
    initE2EE({
      getDeviceId: () => 'device-a',
      getStoragePrefix: () => 'user-a',
    });
    await resetE2EEState();

    await ensureKeysGenerated();

    const remoteIdentity = await generateIdentityKeys();
    const remoteSignedPreKey1 = await generateSignedPreKey(
      remoteIdentity.identitySignKeyPair.privateKey,
      1001
    );
    const remoteSignedPreKey2 = await generateSignedPreKey(
      remoteIdentity.identitySignKeyPair.privateKey,
      1002
    );
    const [remoteOneTimePreKey1] = await generateOneTimePreKeys(1);
    const [remoteOneTimePreKey2] = await generateOneTimePreKeys(1);
    if (!remoteOneTimePreKey1 || !remoteOneTimePreKey2) {
      throw new Error('Expected one-time prekeys for test setup');
    }

    const identityKey = await exportIdentityPublic(remoteIdentity);
    const spk1 = await exportSignedPreKeyPublic(remoteSignedPreKey1);
    const spk2 = await exportSignedPreKeyPublic(remoteSignedPreKey2);
    const otk1 = await exportOneTimePreKeyPublic(remoteOneTimePreKey1);
    const otk2 = await exportOneTimePreKeyPublic(remoteOneTimePreKey2);

    const conversationId = 'conv-spk-rotate';
    const peerUserId = 'peer-user';
    const peerDeviceId = 'peer-device';

    await ensureSessionWith(
      conversationId,
      peerUserId,
      {
        identityKey,
        signedPreKey: spk1,
        oneTimePreKeys: [otk1],
      },
      peerDeviceId,
      'user-a'
    );
    const first = await getSession(conversationId, peerUserId, peerDeviceId);

    // WHEN
    await ensureSessionWith(
      conversationId,
      peerUserId,
      {
        identityKey,
        signedPreKey: spk2,
        oneTimePreKeys: [otk2],
      },
      peerDeviceId,
      'user-a'
    );
    const second = await getSession(conversationId, peerUserId, peerDeviceId);

    // THEN
    expect(first?.x3dh?.signedPreKeyId).toBe(1001);
    expect(second?.x3dh?.signedPreKeyId).toBe(1002);
  });
});
