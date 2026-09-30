// AES-256-GCM and X25519 on Web Crypto. Environment-agnostic (no DOM or
// worker globals) so it runs in the crypto worker and under Node tests. This
// is the only module that handles key material.
//
// Custody rules enforced here:
// * KEK: non-extractable, usable only to wrap/unwrap DEKs.
// * DEK: generated extractable so it can be wrapped; unwrapped copies are
//   non-extractable.
// * HPKE X25519 private key: non-extractable; only the public half exports.
//
// Every AES-GCM operation binds tenant id, object id, and role via AAD, so a
// vault cannot splice records across objects, reorder chunks, or swap
// wrapped keys undetected.

import type {
  EncryptedPayload,
  FileManifest,
  HpkeKeypairHandle,
  WrappedKey,
} from "./types";

const AES_KEY_BITS = 256;
export const GCM_IV_BYTES = 12;
export const CHUNK_SIZE_BYTES = 4 * 1024 * 1024;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function randomIv(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
}

/** TextEncoder always returns a plain ArrayBuffer; narrow the type so it
 *  satisfies `BufferSource`. */
function utf8(text: string): Uint8Array<ArrayBuffer> {
  return textEncoder.encode(text) as Uint8Array<ArrayBuffer>;
}

/** Context bound into every AES-GCM operation via AAD. */
export type Aad = Uint8Array<ArrayBuffer>;

// AAD builders: canonical, fixed field order.

export function chunkAad(tenantId: string, objectId: string, chunkIndex: number): Aad {
  return utf8(`${tenantId}|${objectId}|chunk|${chunkIndex}`);
}

export function manifestAad(tenantId: string, objectId: string): Aad {
  return utf8(`${tenantId}|${objectId}|manifest`);
}

export function dekAad(tenantId: string, objectId: string): Aad {
  return utf8(`${tenantId}|${objectId}|dek`);
}

/** Device master key (KEK): non-extractable, wrap/unwrap only. */
export function generateMasterKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: AES_KEY_BITS }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
}

/** Per-file key (DEK), extractable so it can be wrapped. Upload code uses
 *  `createFileKey`, which never lets the extractable handle escape. */
export function generateFileKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: AES_KEY_BITS }, true, [
    "encrypt",
    "decrypt",
  ]);
}

/** Wrap a DEK under the KEK; the AAD binds it to its tenant and object. */
export async function wrapFileKey(
  kek: CryptoKey,
  dek: CryptoKey,
  aad: Aad,
): Promise<WrappedKey> {
  const iv = randomIv();
  const data = await crypto.subtle.wrapKey("raw", dek, kek, {
    name: "AES-GCM",
    iv,
    additionalData: aad,
  });
  return { iv: iv.buffer, data };
}

/** New DEK for an upload: wrapped under the KEK, and returned only as a
 *  non-extractable handle unwrapped from that wrapping. */
export async function createFileKey(
  kek: CryptoKey,
  aad: Aad,
): Promise<{ dek: CryptoKey; wrappedKey: WrappedKey }> {
  const wrappedKey = await wrapFileKey(kek, await generateFileKey(), aad);
  return { dek: await unwrapFileKey(kek, wrappedKey, aad), wrappedKey };
}

/** Unwrap a DEK as non-extractable, so raw DEK bytes never reappear in
 *  script-accessible memory. */
export function unwrapFileKey(
  kek: CryptoKey,
  wrapped: WrappedKey,
  aad: Aad,
): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped.data,
    kek,
    { name: "AES-GCM", iv: wrapped.iv, additionalData: aad },
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptPayload(
  dek: CryptoKey,
  aad: Aad,
  plaintext: ArrayBuffer,
): Promise<EncryptedPayload> {
  const iv = randomIv();
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    dek,
    plaintext,
  );
  return { iv: iv.buffer, data };
}

/** Rejects with OperationError if the ciphertext, IV, or AAD was altered. */
export function decryptPayload(
  dek: CryptoKey,
  aad: Aad,
  payload: EncryptedPayload,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: payload.iv, additionalData: aad },
    dek,
    payload.data,
  );
}

export function encryptManifest(
  dek: CryptoKey,
  aad: Aad,
  manifest: FileManifest,
): Promise<EncryptedPayload> {
  return encryptPayload(dek, aad, utf8(JSON.stringify(manifest)).buffer);
}

export async function decryptManifest(
  dek: CryptoKey,
  aad: Aad,
  payload: EncryptedPayload,
): Promise<FileManifest> {
  const bytes = await decryptPayload(dek, aad, payload);
  return JSON.parse(textDecoder.decode(bytes)) as FileManifest;
}

/** X25519 support is newer than AES-GCM; detect it so the drive still works
 *  without it. */
export async function isX25519Supported(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
}

/** Tenant HPKE keypair (backend suite DHKEM(X25519, HKDF-SHA256)). The
 *  private key is non-extractable; the raw public key is exported for
 *  enrollment. */
export async function generateHpkeKeypair(): Promise<HpkeKeypairHandle> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const publicKeyRaw = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyRaw };
}

const FINGERPRINT_BYTES = 8;

/** Human-checkable fingerprint: first 8 bytes of SHA-256, hex in groups of 4. */
export async function keyFingerprint(publicKeyRaw: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", publicKeyRaw);
  const head = [...new Uint8Array(digest).subarray(0, FINGERPRINT_BYTES)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return head.replace(/(.{4})(?=.)/g, "$1-");
}
