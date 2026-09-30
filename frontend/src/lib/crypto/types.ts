// Crypto and vault record types. Invariants:
// * The master key (KEK) is generated in this browser, non-extractable, and
//   never leaves it; code holds only opaque CryptoKey handles.
// * Per-file keys (DEKs) are extractable only for the instant they are
//   wrapped under the KEK; every handle used for encryption is a
//   non-extractable copy unwrapped from that wrapping.
// * The HPKE X25519 private key is non-extractable; only the public half is
//   exported, for tenant enrollment.
// * No file content or name reaches a vault in plaintext; filenames and
//   metadata live inside the encrypted manifest.

/** AES-GCM output with its per-use 96-bit IV. */
export interface EncryptedPayload {
  readonly iv: ArrayBuffer;
  readonly data: ArrayBuffer;
}

/** A per-file DEK wrapped (AES-GCM) under the non-extractable master key. */
export interface WrappedKey {
  readonly iv: ArrayBuffer;
  readonly data: ArrayBuffer;
}

/** Plaintext file metadata; stored only encrypted under the file's DEK. */
export interface FileManifest {
  readonly name: string;
  readonly mimeType: string;
  readonly sizeBytes: number;
  readonly chunkCount: number;
  readonly chunkSizeBytes: number;
  readonly createdAtIso: string;
}

/** What a vault stores per object: ids, sizes, a timestamp, and ciphertext. */
export interface ManifestRecord {
  readonly objectId: string;
  readonly tenantId: string;
  readonly wrappedKey: WrappedKey;
  readonly manifest: EncryptedPayload;
  readonly chunkCount: number;
  readonly encryptedSizeBytes: number;
  readonly createdAtIso: string;
}

/** One encrypted chunk (AAD binds tenant, object, and chunk index). */
export interface ChunkRecord {
  readonly objectId: string;
  readonly chunkIndex: number;
  readonly iv: ArrayBuffer;
  readonly data: ArrayBuffer;
}

/** X25519 keypair for HPKE; matches the backend's DHKEM(X25519, HKDF-SHA256)
 *  suite (platform-crypto::TenantKem). */
export interface HpkeKeypairHandle {
  readonly privateKey: CryptoKey;
  readonly publicKeyRaw: ArrayBuffer;
}
