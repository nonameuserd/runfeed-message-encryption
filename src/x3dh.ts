/**
 * X3DH-style key agreement: derive shared secret from identity + signed prekeys + one-time prekeys.
 * Root key is used to initialize the Double Ratchet session.
 */

import type { IdentityKeys, SignedPreKey } from './keys';
import { importEcdhPublicKey, parseIdentityPublic } from './keys';

const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const P256_SIGN = { name: 'ECDSA', namedCurve: 'P-256' } as const;

function concat(...bufs: ArrayBuffer[]): ArrayBuffer {
  const total = bufs.reduce((a, b) => a + b.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    out.set(new Uint8Array(b), off);
    off += b.byteLength;
  }
  return out.buffer;
}

function b64Decode(s: string): Uint8Array {
  return new Uint8Array(
    atob(s)
      .split('')
      .map((c) => c.charCodeAt(0))
  );
}

async function ecdh(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
}

async function hkdf(length: number, ikm: ArrayBuffer, salt: ArrayBuffer, info: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF', hash: 'SHA-256' },
    false,
    ['deriveBits']
  );
  const infoBytes = new TextEncoder().encode(info);
  return crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: infoBytes },
    key,
    length * 8
  );
}

export interface RemoteBundle {
  identityKey: string;
  signedPreKey?: { key: string; signature: string; keyId: number };
  oneTimePreKey?: { key: string; keyId: string };
  oneTimePreKeys?: Array<{ key: string; keyId: string }>;
}

export interface X3DHInitiatorResult {
  rootKey: ArrayBuffer;
  ephemeralKeyPair: CryptoKeyPair;
  oneTimePreKeyId?: string;
  signedPreKeyId?: number;
}

/**
 * Perform X3DH as initiator: we have our identity, we have their bundle.
 * Verifies signed prekey signature when possible.
 * Returns root key + our ephemeral key pair for Double Ratchet.
 */
export async function x3dhInitiator(
  ourIdentity: IdentityKeys,
  theirBundle: RemoteBundle
): Promise<X3DHInitiatorResult> {
  const { dhPub: theirIdentityDh, signPub } = parseIdentityPublic(theirBundle.identityKey);
  const theirIdentityKey = await crypto.subtle.importKey(
    'raw',
    theirIdentityDh,
    P256,
    false,
    []
  );

  if (!theirBundle.signedPreKey?.key || !theirBundle.signedPreKey.signature) {
    throw new Error('E2EE: missing signed prekey');
  }
  const theirSignedPreKeyB64 = theirBundle.signedPreKey.key;
  const theirSignedPreKey = await importEcdhPublicKey(theirSignedPreKeyB64);

  const signKey = await crypto.subtle.importKey(
    'raw',
    signPub,
    P256_SIGN,
    false,
    ['verify']
  );
  const spkRaw = b64Decode(theirBundle.signedPreKey.key);
  const sigRaw = b64Decode(theirBundle.signedPreKey.signature);
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    signKey,
    sigRaw as BufferSource,
    spkRaw as BufferSource
  );
  if (!ok) throw new Error('E2EE: invalid signed prekey signature');

  const oneTime = theirBundle.oneTimePreKey ?? theirBundle.oneTimePreKeys?.[0];
  const theirOneTimePreKey = oneTime?.key ? await importEcdhPublicKey(oneTime.key) : undefined;

  const ephemeralKeyPair = await crypto.subtle.generateKey(P256, true, [
    'deriveKey',
    'deriveBits',
  ]);

  const dh1 = await ecdh(ourIdentity.identityDhKeyPair.privateKey!, theirSignedPreKey);
  const dh2 = await ecdh(ephemeralKeyPair.privateKey!, theirIdentityKey);
  const dh3 = await ecdh(ephemeralKeyPair.privateKey!, theirSignedPreKey);
  const dh4 = theirOneTimePreKey
    ? await ecdh(ephemeralKeyPair.privateKey!, theirOneTimePreKey)
    : null;
  const secret = dh4 ? concat(dh1, dh2, dh3, dh4) : concat(dh1, dh2, dh3);
  const salt = new ArrayBuffer(32);
  const rootKey = await hkdf(32, secret, salt, 'x3dh-root');
  return {
    rootKey,
    ephemeralKeyPair,
    oneTimePreKeyId: oneTime?.keyId,
    signedPreKeyId: theirBundle.signedPreKey?.keyId,
  };
}

/**
 * Perform X3DH as responder: we have our identity + signed prekey (and optional one-time prekey).
 * From message we have their identity + ephemeral key.
 * Returns 32-byte root key.
 */
export async function x3dhResponder(
  ourIdentity: IdentityKeys,
  ourSignedPreKey: SignedPreKey,
  theirIdentityDhBase64: string,
  theirEphemeralBase64: string,
  ourOneTimePreKeyPrivate?: CryptoKey
): Promise<ArrayBuffer> {
  const theirIdentityDh = await importEcdhPublicKey(theirIdentityDhBase64);
  const theirEphemeralDh = await importEcdhPublicKey(theirEphemeralBase64);

  const dh1 = await ecdh(ourSignedPreKey.keyPair.privateKey, theirIdentityDh);
  const dh2 = await ecdh(ourIdentity.identityDhKeyPair.privateKey!, theirEphemeralDh);
  const dh3 = await ecdh(ourSignedPreKey.keyPair.privateKey, theirEphemeralDh);
  const dh4 = ourOneTimePreKeyPrivate
    ? await ecdh(ourOneTimePreKeyPrivate, theirEphemeralDh)
    : null;
  const secret = dh4 ? concat(dh1, dh2, dh3, dh4) : concat(dh1, dh2, dh3);
  const salt = new ArrayBuffer(32);
  const rootKey = await hkdf(32, secret, salt, 'x3dh-root');
  return rootKey;
}
