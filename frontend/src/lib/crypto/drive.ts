// Drive operations over a vault, parameterized by the device keys so the
// crypto worker and tests share one implementation. Imported only by the
// worker in the app bundle.

import type { VaultClient } from "../vault/types";
import {
  CHUNK_SIZE_BYTES,
  chunkAad,
  createFileKey,
  decryptManifest,
  decryptPayload,
  dekAad,
  encryptManifest,
  encryptPayload,
  manifestAad,
  unwrapFileKey,
} from "./core";
import type { DeviceKeys } from "./keystore";
import type { DownloadResult, DriveFileSummary } from "./protocol";
import type { ChunkRecord, FileManifest, ManifestRecord } from "./types";

export interface DriveContext {
  keys: DeviceKeys;
  vault: VaultClient;
  onProgress?: (done: number, total: number) => void;
}

function summarize(record: ManifestRecord, manifest: FileManifest): DriveFileSummary {
  return {
    objectId: record.objectId,
    name: manifest.name,
    mimeType: manifest.mimeType,
    sizeBytes: manifest.sizeBytes,
    chunkCount: record.chunkCount,
    createdAtIso: record.createdAtIso,
  };
}

export async function uploadFile(
  { keys, vault, onProgress }: DriveContext,
  file: File,
): Promise<DriveFileSummary> {
  const objectId = crypto.randomUUID();
  const tenantId = keys.tenantId;
  const chunkCount = Math.ceil(file.size / CHUNK_SIZE_BYTES);

  const { dek, wrappedKey } = await createFileKey(keys.kek, dekAad(tenantId, objectId));

  let encryptedSizeBytes = 0;
  for (let index = 0; index < chunkCount; index += 1) {
    const start = index * CHUNK_SIZE_BYTES;
    const plain = await file.slice(start, start + CHUNK_SIZE_BYTES).arrayBuffer();
    const sealed = await encryptPayload(dek, chunkAad(tenantId, objectId, index), plain);
    encryptedSizeBytes += sealed.data.byteLength;
    const record: ChunkRecord = {
      objectId,
      chunkIndex: index,
      iv: sealed.iv,
      data: sealed.data,
    };
    await vault.putChunk(record);
    onProgress?.(index + 1, chunkCount);
  }

  const createdAtIso = new Date().toISOString();
  const manifest: FileManifest = {
    name: file.name,
    mimeType: file.type || "application/octet-stream",
    sizeBytes: file.size,
    chunkCount,
    chunkSizeBytes: CHUNK_SIZE_BYTES,
    createdAtIso,
  };
  const sealedManifest = await encryptManifest(dek, manifestAad(tenantId, objectId), manifest);

  const record: ManifestRecord = {
    objectId,
    tenantId,
    wrappedKey,
    manifest: sealedManifest,
    chunkCount,
    encryptedSizeBytes,
    createdAtIso,
  };
  await vault.putManifest(record);
  return summarize(record, manifest);
}

async function openManifest(
  keys: DeviceKeys,
  record: ManifestRecord,
): Promise<{ dek: CryptoKey; manifest: FileManifest }> {
  const dek = await unwrapFileKey(
    keys.kek,
    record.wrappedKey,
    dekAad(record.tenantId, record.objectId),
  );
  const manifest = await decryptManifest(
    dek,
    manifestAad(record.tenantId, record.objectId),
    record.manifest,
  );
  return { dek, manifest };
}

export async function listFiles({ keys, vault }: DriveContext): Promise<DriveFileSummary[]> {
  const records = await vault.listManifests();
  const summaries: DriveFileSummary[] = [];
  for (const record of records) {
    try {
      const { manifest } = await openManifest(keys, record);
      summaries.push(summarize(record, manifest));
    } catch {
      // Surface records that fail authentication rather than hiding them.
      summaries.push({
        objectId: record.objectId,
        name: "(unreadable — failed integrity check)",
        mimeType: "application/octet-stream",
        sizeBytes: 0,
        chunkCount: record.chunkCount,
        createdAtIso: record.createdAtIso,
      });
    }
  }
  return summaries;
}

export async function downloadFile(
  { keys, vault, onProgress }: DriveContext,
  objectId: string,
): Promise<DownloadResult> {
  const record = await vault.getManifest(objectId);
  if (!record) throw new Error("object not found");

  const { dek, manifest } = await openManifest(keys, record);
  // The chunk count comes from the authenticated manifest; the vault's copy
  // is untrusted, and a mismatch means the record was tampered with.
  const { chunkCount } = manifest;
  if (!Number.isSafeInteger(chunkCount) || chunkCount < 0 || chunkCount !== record.chunkCount) {
    throw new Error("chunk count does not match the authenticated manifest");
  }
  const parts: ArrayBuffer[] = [];
  for (let index = 0; index < chunkCount; index += 1) {
    const chunk = await vault.getChunk(objectId, index);
    if (!chunk) throw new Error(`missing chunk ${index}`);
    const plain = await decryptPayload(dek, chunkAad(record.tenantId, objectId, index), {
      iv: chunk.iv,
      data: chunk.data,
    });
    parts.push(plain);
    onProgress?.(index + 1, chunkCount);
  }

  return {
    summary: summarize(record, manifest),
    blob: new Blob(parts, { type: manifest.mimeType }),
  };
}

export async function removeFile(
  { vault }: DriveContext,
  objectId: string,
): Promise<{ objectId: string }> {
  await vault.deleteObject(objectId);
  return { objectId };
}
