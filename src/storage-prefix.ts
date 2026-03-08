/**
 * Optional storage prefix so multiple users in the same origin get isolated E2EE state.
 * Set by initE2EE via setStoragePrefixGetter.
 */

let getter: (() => string | undefined) | null = null;

export function setStoragePrefixGetter(g: (() => string | undefined) | undefined): void {
  getter = g ?? null;
}

export function getStoragePrefix(): string | undefined {
  return getter?.() ?? undefined;
}
