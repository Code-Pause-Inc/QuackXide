import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import type { ChunkRecord, ManifestRecord } from "../crypto/types";
import { LocalVault } from "./localVault";

function buf(fill: number, length = 8): ArrayBuffer {
  return new Uint8Array(length).fill(fill).buffer;
}

function manifestRecord(objectId: string, createdAtIso: string): ManifestRecord {
  return {
    objectId,
    tenantId: "6f2c8a2e-1111-4222-8333-444455556666",
    wrappedKey: { iv: buf(1, 12), data: buf(2, 40) },
    manifest: { iv: buf(3, 12), data: buf(4, 64) },
    chunkCount: 2,
    encryptedSizeBytes: 128,
    createdAtIso,
  };
}

function chunkRecord(objectId: string, chunkIndex: number): ChunkRecord {
  return { objectId, chunkIndex, iv: buf(5, 12), data: buf(6, 32) };
}

describe("LocalVault", () => {
  let vault: LocalVault;

  beforeEach(() => {
    indexedDB.deleteDatabase("drive-vault");
    vault = new LocalVault();
  });

  it("stores and retrieves manifests and chunks", async () => {
    await vault.putManifest(manifestRecord("obj-1", "2026-07-30T10:00:00.000Z"));
    await vault.putChunk(chunkRecord("obj-1", 0));
    await vault.putChunk(chunkRecord("obj-1", 1));

    const manifest = await vault.getManifest("obj-1");
    expect(manifest?.chunkCount).toBe(2);

    const chunk = await vault.getChunk("obj-1", 1);
    expect(chunk?.chunkIndex).toBe(1);
    expect(new Uint8Array(chunk?.data ?? new ArrayBuffer(0))[0]).toBe(6);
  });

  it("returns null for missing records", async () => {
    expect(await vault.getManifest("nope")).toBeNull();
    expect(await vault.getChunk("nope", 0)).toBeNull();
  });

  it("lists manifests newest first", async () => {
    await vault.putManifest(manifestRecord("obj-old", "2026-07-29T10:00:00.000Z"));
    await vault.putManifest(manifestRecord("obj-new", "2026-07-30T10:00:00.000Z"));
    const list = await vault.listManifests();
    expect(list.map((m) => m.objectId)).toEqual(["obj-new", "obj-old"]);
  });

  it("deleteObject removes the manifest and every chunk, and nothing else", async () => {
    await vault.putManifest(manifestRecord("obj-1", "2026-07-30T10:00:00.000Z"));
    await vault.putChunk(chunkRecord("obj-1", 0));
    await vault.putChunk(chunkRecord("obj-1", 1));
    await vault.putManifest(manifestRecord("obj-2", "2026-07-30T11:00:00.000Z"));
    await vault.putChunk(chunkRecord("obj-2", 0));

    await vault.deleteObject("obj-1");

    expect(await vault.getManifest("obj-1")).toBeNull();
    expect(await vault.getChunk("obj-1", 0)).toBeNull();
    expect(await vault.getChunk("obj-1", 1)).toBeNull();
    expect(await vault.getManifest("obj-2")).not.toBeNull();
    expect(await vault.getChunk("obj-2", 0)).not.toBeNull();
  });
});
