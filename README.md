# @runfeed/message-encryption

Client-side E2EE for messaging: **X3DH** key agreement, **Double Ratchet** (1:1), and **Sender Keys** (group). Uses Web Crypto (P-256, AES-GCM, HKDF). Keys and session state live in IndexedDB; optional encrypt-at-rest for ratchet/sender-key state.

**Architecture and design:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — component map, data flow, wire format, and references (X3DH, Double Ratchet, Web Crypto, etc.).

## Algorithms

- **1:1**: X3DH for the first shared secret, then Double Ratchet (DH + symmetric chains, skipped-key cache for out-of-order messages).
- **Group**: Sender Keys (one symmetric chain per sender), distributed over 1:1 sessions; per-sender ECDSA P-256 signing for group message authentication.

Key distribution (upload/download of identity, signed prekeys, one-time prekeys) is **your responsibility** (e.g. `PUT /me/keys`, `GET /users/:userId/keys`). This package only does key generation, agreement, and encrypt/decrypt.

## Wire format

| Prefix              | Meaning                 |
|---------------------|-------------------------|
| `e2ee0:`            | Initial 1:1 (X3DH)      |
| `e2ee1:`            | Continuing 1:1 (ratchet)|
| `e2ee-group1:`      | Group message           |
| `e2ee-senderkey0:`  | Sender key distribution |
| `e2ee-pad1:`        | Padding wrapper         |

## Usage

1. **Init** once with device id and optional TOFU/verified-peers adapters:

```ts
import { initE2EE } from '@runfeed/message-encryption';

initE2EE({
  getDeviceId: () => 'my-device-id',
  tofu: {
    getFirstSeenDh: (myUserId, peerUserId, peerDeviceId) => storage.get(...) ?? null,
    setFirstSeenDh: (myUserId, peerUserId, peerDeviceId, dhBase64) => storage.set(...),
    clear: () => storage.clear(),
  },
  clearVerifiedPeers: async () => { /* optional */ },
});
```

2. **Generate keys** and upload the public bundle to your server:

```ts
import { ensureKeysGenerated } from '@runfeed/message-encryption';

const bundle = await ensureKeysGenerated();
// POST/PUT bundle (identityKey, signedPreKey, oneTimePreKeys) to your backend.
```

3. **Establish a 1:1 session** (e.g. before first send):

```ts
import { ensureSessionWith } from '@runfeed/message-encryption';

await ensureSessionWith(conversationId, peerUserId, theirBundle, peerDeviceId, myUserId);
```

4. **Encrypt / decrypt**:

```ts
import { encryptForPeer, decryptFrom, padForSend, unpadFromReceive } from '@runfeed/message-encryption';

const ciphertext = await encryptForPeer(conversationId, peerUserId, plaintext, peerDeviceId, messageId);
const toSend = padForSend(ciphertext); // optional: metadata-reducing padding

const plaintext = await decryptFrom(conversationId, senderId, unpadFromReceive(received), messageId, myUserId);
```

For **group** conversations use `ensureGroupSenderKey`, `encryptForGroup`, `decryptFromGroup` (see package exports).

## Requirements

- Browser (or environment with `crypto.subtle`, IndexedDB). Signed prekey rotation uses `localStorage` for the last-rotation timestamp.
- Key distribution (upload/fetch of public key bundles) and any transport or persistence of **ciphertext** (e.g. to a server) are the app's responsibility. This package does **not** store message content; it only encrypts and decrypts.

## License

MIT
