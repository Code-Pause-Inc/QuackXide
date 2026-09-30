// IndexedDB vault so the drive works end-to-end without a backend. Stores
// exactly the records the server would.

import type { ChunkRecord, ManifestRecord } from "../crypto/types";
import { idbRequest, openDb, txDone } from "../idb";
import type { VaultClient } from "./types";

const DB_NAME = "drive-vault";
const DB_VERSION = 1;
const MANIFESTS = "manifests";
const CHUNKS = "chunks";

function open(): Promise<IDBDatabase> {
  return openDb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(MANIFESTS)) {
      db.createObjectStore(MANIFESTS, { keyPath: "objectId" });
    }
    if (!db.objectStoreNames.contains(CHUNKS)) {
      db.createObjectStore(CHUNKS, { keyPath: ["objectId", "chunkIndex"] });
    }
  });
}

async function withDb<T>(fn: (db: IDBDatabase) => Promise<T>): Promise<T> {
  const db = await open();
  try {
    return await fn(db);
  } finally {
    db.close();
  }
}

export class LocalVault implements VaultClient {
  putManifest(record: ManifestRecord): Promise<void> {
    return withDb(async (db) => {
      const tx = db.transaction(MANIFESTS, "readwrite");
      tx.objectStore(MANIFESTS).put(record);
      await txDone(tx);
    });
  }

  getManifest(objectId: string): Promise<ManifestRecord | null> {
    return withDb(async (db) => {
      const tx = db.transaction(MANIFESTS, "readonly");
      const record = (await idbRequest(tx.objectStore(MANIFESTS).get(objectId))) as
        | ManifestRecord
        | undefined;
      return record ?? null;
    });
  }

  listManifests(): Promise<ManifestRecord[]> {
    return withDb(async (db) => {
      const tx = db.transaction(MANIFESTS, "readonly");
      const records = (await idbRequest(tx.objectStore(MANIFESTS).getAll())) as ManifestRecord[];
      return records.sort((a, b) => b.createdAtIso.localeCompare(a.createdAtIso));
    });
  }

  putChunk(record: ChunkRecord): Promise<void> {
    return withDb(async (db) => {
      const tx = db.transaction(CHUNKS, "readwrite");
      tx.objectStore(CHUNKS).put(record);
      await txDone(tx);
    });
  }

  getChunk(objectId: string, chunkIndex: number): Promise<ChunkRecord | null> {
    return withDb(async (db) => {
      const tx = db.transaction(CHUNKS, "readonly");
      const record = (await idbRequest(tx.objectStore(CHUNKS).get([objectId, chunkIndex]))) as
        | ChunkRecord
        | undefined;
      return record ?? null;
    });
  }

  deleteObject(objectId: string): Promise<void> {
    return withDb(async (db) => {
      const tx = db.transaction([MANIFESTS, CHUNKS], "readwrite");
      tx.objectStore(MANIFESTS).delete(objectId);
      tx.objectStore(CHUNKS).delete(
        IDBKeyRange.bound([objectId, 0], [objectId, Number.POSITIVE_INFINITY]),
      );
      await txDone(tx);
    });
  }
}
