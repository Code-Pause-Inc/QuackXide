// The device's tenant HPKE private key, held as ADR 0007 ("Browser
// private-key storage") describes. Web Crypto cannot run the envelope
// suite's KEM, so the raw key has to reach the wasm module. It is therefore:
// * generated here (32 random bytes; the KEM clamps any value), with its
//   public key derived by the wasm module for enrollment;
// * stored only encrypted under the device's non-extractable seed key, with
//   AAD binding the tenant and the public key (`privateKeyAad`);
// * decrypted only in the crypto worker immediately before an open, handed
//   to wasm, and overwritten with zeros (envelope.ts) when the open ends.
//
// Imported only by worker-side code.

import { decryptPayload, encryptPayload, generateSeedKey, privateKeyAad } from "./core";
import { openWithPrivateKey, publicKeyOf } from "./envelope";
import type { EncryptedPayload } from "./types";

/** Raw X25519 private key length for the `HPK1` suite. */
export const PRIVATE_KEY_BYTES = 32;

export interface DeviceHpkeKey {
  /** Non-extractable AES-256-GCM key that encrypts `sealedPrivateKey`. */
  readonly seedKey: CryptoKey;
  /** Raw public key: what the tenant enrolls. */
  readonly publicKeyRaw: ArrayBuffer;
  /** The private key, AES-GCM under `seedKey` with `privateKeyAad`. */
  readonly sealedPrivateKey: EncryptedPayload;
}

/** A new device HPKE key for `tenantId`. No plaintext copy of the private
 *  key outlives this call. */
export async function createDeviceHpkeKey(tenantId: string): Promise<DeviceHpkeKey> {
  const seedKey = await generateSeedKey();
  const privateKey = crypto.getRandomValues(new Uint8Array(PRIVATE_KEY_BYTES));
  try {
    const publicKeyRaw = await publicKeyOf(privateKey);
    const sealedPrivateKey = await encryptPayload(
      seedKey,
      await privateKeyAad(tenantId, publicKeyRaw),
      privateKey.buffer,
    );
    return { seedKey, publicKeyRaw, sealedPrivateKey };
  } finally {
    privateKey.fill(0);
  }
}

/** Open an envelope sealed to this device's key. Rejects if the stored key
 *  record was altered, moved to another tenant or paired with another
 *  public key, and on any failed open. */
export async function openWithDeviceKey(
  tenantId: string,
  key: DeviceHpkeKey,
  info: Uint8Array,
  envelope: ArrayBuffer,
): Promise<ArrayBuffer> {
  const aad = await privateKeyAad(tenantId, key.publicKeyRaw);
  const decrypted = await decryptPayload(key.seedKey, aad, key.sealedPrivateKey);
  // openWithPrivateKey zeroes this view, and with it the decrypted buffer.
  return openWithPrivateKey(new Uint8Array(decrypted), info, envelope);
}
