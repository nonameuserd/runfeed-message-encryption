/**
 * Adapter options for E2EE crypto. Pass to initE2EE() before using encrypt/decrypt APIs.
 */

export class KeyChangedError extends Error {
  constructor(
    public readonly firstSeenDh: string,
    public readonly currentDh: string,
    public readonly peerUserId: string,
    public readonly peerDeviceId: string
  ) {
    super('E2EE: peer identity key changed since first use (possible MITM). Verify the new key.');
    this.name = 'KeyChangedError';
  }
}

export interface TofuAdapter {
  getFirstSeenDh: (
    myUserId: string,
    peerUserId: string,
    peerDeviceId: string
  ) => string | null;
  setFirstSeenDh: (
    myUserId: string,
    peerUserId: string,
    peerDeviceId: string,
    dhBase64: string
  ) => void;
  clear: () => void;
}

export interface E2EECryptoOptions {
  getDeviceId: () => Promise<string> | string;
  /** When set, all IndexedDB keys are prefixed so multiple users in the same origin do not overwrite each other. */
  getStoragePrefix?: () => string | undefined;
  tofu?: TofuAdapter;
  onKeyChanged?: (peerUserId: string, peerDeviceId: string) => void;
  clearVerifiedPeers?: () => Promise<void>;
}

/** Normalize identity key to DH part only for comparison (format is "dhBase64.signatureBase64"). */
export function identityToDhBase64(identityKeyOrDh: string): string {
  const trimmed = identityKeyOrDh.trim();
  const dot = trimmed.indexOf('.');
  return dot >= 0 ? trimmed.slice(0, dot) : trimmed;
}
