import { describe, expect, it } from 'vitest';
import { decryptFrom } from './e2ee';
import { payloadToBase64, ratchetDecrypt, ratchetEncrypt, ratchetStateFromRoot } from './ratchet';
import { clearSessions, setRatchetState } from './session-store';

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

function aadConversation(conversationId: string): ArrayBuffer {
  const u8 = new TextEncoder().encode(conversationId);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

function aadConversationMessage(conversationId: string, messageId: string): ArrayBuffer {
  const u8 = new TextEncoder().encode(`${conversationId}\0${messageId}`);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

describe('security invariants', () => {
  it('fails decrypt when conversation AAD is wrong', async () => {
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
    const encrypted = await ratchetEncrypt(senderState, 'hello', aadConversation('conv-A'));

    // WHEN / THEN
    await expect(
      ratchetDecrypt(receiverState, encrypted.payload, aadConversation('conv-B'))
    ).rejects.toThrow();
  });

  it('fails decrypt when ciphertext is tampered', async () => {
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
    const encrypted = await ratchetEncrypt(senderState, 'hello', aadConversation('conv-A'));
    const tampered = new Uint8Array(encrypted.payload.slice(0));
    const lastIndex = tampered.length - 1;
    const last = tampered[lastIndex];
    if (last == null) throw new Error('Unexpected empty ciphertext payload');
    tampered[lastIndex] = last ^ 0x01;

    // WHEN / THEN
    await expect(
      ratchetDecrypt(receiverState, tampered.buffer, aadConversation('conv-A'))
    ).rejects.toThrow();
  });

  it('fails decrypt when messageId-bound AAD does not match', async () => {
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
    const encrypted = await ratchetEncrypt(
      senderState,
      'hello',
      aadConversationMessage('conv-A', 'msg-1')
    );

    // WHEN / THEN
    await expect(
      ratchetDecrypt(receiverState, encrypted.payload, aadConversationMessage('conv-A', 'msg-2'))
    ).rejects.toThrow();
  });

  it('decryptFrom fallback does not decrypt across wrong sender or conversation', async () => {
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
    const conversationId = 'conv-allowed';
    const senderId = 'sender-allowed';
    const senderDeviceId = 'sender-device';
    const receiverState = await ratchetStateFromRoot(rootKey, {
      isInitiator: false,
      ourDhKeyPair: receiverDh,
      theirDhPublicKeyBase64: senderPub,
    });
    const senderState = await ratchetStateFromRoot(rootKey, {
      isInitiator: true,
      ourDhKeyPair: senderDh,
      theirDhPublicKeyBase64: receiverPub,
    });
    await setRatchetState(conversationId, senderId, receiverState, undefined, 'sender-device-old');

    const encrypted = await ratchetEncrypt(senderState, 'secret', aadConversation(conversationId));
    const payload = `e2ee1:${senderDeviceId}:${payloadToBase64(encrypted.payload)}`;

    // WHEN / THEN
    await expect(decryptFrom(conversationId, 'sender-wrong', payload)).rejects.toThrow(
      'E2EE: no session with sender'
    );
    await expect(decryptFrom('conv-wrong', senderId, payload)).rejects.toThrow(
      'E2EE: no session with sender'
    );
  });
});
