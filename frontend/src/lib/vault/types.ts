// Vault client contract, implemented by LocalVault (IndexedDB) and HttpVault
// (drive API). Everything crossing this boundary is ciphertext or an opaque
// id; the types admit nothing else.

import type { ChunkRecord, ManifestRecord } from "../crypto/types";

export interface VaultClient {
  putManifest(record: ManifestRecord): Promise<void>;
  getManifest(objectId: string): Promise<ManifestRecord | null>;
  listManifests(): Promise<ManifestRecord[]>;
  putChunk(record: ChunkRecord): Promise<void>;
  getChunk(objectId: string, chunkIndex: number): Promise<ChunkRecord | null>;
  /** Removes the manifest and every chunk for the object. */
  deleteObject(objectId: string): Promise<void>;
  /** Enroll the tenant HPKE public key. Server-backed vaults only. */
  enrollTenantKey?(publicKeyB64: string): Promise<void>;
}
