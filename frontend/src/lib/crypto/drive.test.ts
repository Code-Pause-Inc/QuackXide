import { beforeEach, describe, expect, it } from "vitest";
import type { VaultClient } from "../vault/types";
import { CHUNK_SIZE_BYTES, generateMasterKey } from "./core";
import { downloadFile, listFiles, removeFile, uploadFile, type DriveContext } from "./drive";
import type { DeviceKeys } from "./keystore";
import type { ChunkRecord, ManifestRecord } from "./types";

/** Stores structured clones, as IndexedDB and the drive API would. */
class MemoryVault implements VaultClient {
  readonly manifests = new Map<string, ManifestRecord>();
  readonly chunks = new Map<string, ChunkRecord>();

  static chunkKey(objectId: string, chunkIndex: number): string {
    return `${objectId}/${chunkIndex}`;
  }

  async putManifest(record: ManifestRecord): Promise<void> {
    this.manifests.set(record.objectId, structuredClone(record));
  }

  async getManifest(objectId: string): Promise<ManifestRecord | null> {
    const record = this.manifests.get(objectId);
    return record ? structuredClone(record) : null;
  }

  async listManifests(): Promise<ManifestRecord[]> {
    return [...this.manifests.values()].map((r) => structuredClone(r));
  }

  async putChunk(record: ChunkRecord): Promise<void> {
    this.chunks.set(
      MemoryVault.chunkKey(record.objectId, record.chunkIndex),
      structuredClone(record),
    );
  }

  async getChunk(objectId: string, chunkIndex: number): Promise<ChunkRecord | null> {
    const record = this.chunks.get(MemoryVault.chunkKey(objectId, chunkIndex));
    return record ? structuredClone(record) : null;
  }

  async deleteObject(objectId: string): Promise<void> {
    this.manifests.delete(objectId);
    for (const key of this.chunks.keys()) {
      if (key.startsWith(`${objectId}/`)) this.chunks.delete(key);
    }
  }

  patchManifest(objectId: string, patch: Partial<ManifestRecord>): void {
    const record = this.manifests.get(objectId);
    if (!record) throw new Error(`no manifest for ${objectId}`);
    this.manifests.set(objectId, { ...record, ...patch });
  }
}

async function deviceKeys(): Promise<DeviceKeys> {
  return {
    tenantId: crypto.randomUUID(),
    kek: await generateMasterKey(),
    hpkePrivateKey: null,
    hpkePublicKeyRaw: null,
    createdAtIso: new Date().toISOString(),
  };
}

function patterned(length: number, seed: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) bytes[i] = (i * 31 + seed) & 0xff;
  return bytes;
}

/** Compares multi-megabyte buffers by digest; deep equality is too slow. */
async function sha256(data: BufferSource | Blob): Promise<string> {
  const bytes = data instanceof Blob ? await data.arrayBuffer() : data;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const TWO_CHUNKS = CHUNK_SIZE_BYTES + 1_000;

describe("drive round trip", () => {
  let vault: MemoryVault;
  let ctx: DriveContext;

  beforeEach(async () => {
    vault = new MemoryVault();
    ctx = { keys: await deviceKeys(), vault };
  });

  it("uploads, lists, and downloads bytes and metadata unchanged", async () => {
    const bytes = patterned(TWO_CHUNKS, 7);
    const progress: Array<[number, number]> = [];
    const uploaded = await uploadFile(
      { ...ctx, onProgress: (done, total) => progress.push([done, total]) },
      new File([bytes], "cohort-summary.pdf", { type: "application/pdf" }),
    );

    expect(uploaded).toMatchObject({
      name: "cohort-summary.pdf",
      mimeType: "application/pdf",
      sizeBytes: TWO_CHUNKS,
      chunkCount: 2,
    });
    expect(progress).toEqual([
      [1, 2],
      [2, 2],
    ]);

    expect(await listFiles(ctx)).toEqual([uploaded]);

    const { summary, blob } = await downloadFile(ctx, uploaded.objectId);
    expect(summary).toEqual(uploaded);
    expect(blob.type).toBe("application/pdf");
    expect(blob.size).toBe(TWO_CHUNKS);
    expect(await sha256(blob)).toBe(await sha256(bytes));
  });

  it("round-trips an empty file with no chunks", async () => {
    const uploaded = await uploadFile(ctx, new File([], "empty.txt"));
    expect(uploaded).toMatchObject({
      chunkCount: 0,
      sizeBytes: 0,
      mimeType: "application/octet-stream",
    });

    const { blob } = await downloadFile(ctx, uploaded.objectId);
    expect(blob.size).toBe(0);
  });

  it("stores only ciphertext: neither the filename nor the content reaches the vault", async () => {
    const marker = "plaintext-marker-6c1d";
    const { objectId } = await uploadFile(ctx, new File([marker], `${marker}.txt`));
    const stored = JSON.stringify(
      [vault.manifests.get(objectId), ...vault.chunks.values()],
      (_key, value: unknown) =>
        value instanceof ArrayBuffer ? new TextDecoder().decode(value) : value,
    );
    expect(stored).not.toContain(marker);
  });

  it("removes the manifest and every chunk", async () => {
    const { objectId } = await uploadFile(ctx, new File([patterned(TWO_CHUNKS, 1)], "a.bin"));
    await removeFile(ctx, objectId);
    expect(vault.manifests.size).toBe(0);
    expect(vault.chunks.size).toBe(0);
    await expect(downloadFile(ctx, objectId)).rejects.toThrow("object not found");
  });
});

describe("drive integrity", () => {
  let vault: MemoryVault;
  let ctx: DriveContext;
  let objectId: string;

  beforeEach(async () => {
    vault = new MemoryVault();
    ctx = { keys: await deviceKeys(), vault };
    ({ objectId } = await uploadFile(ctx, new File([patterned(TWO_CHUNKS, 3)], "data.bin")));
  });

  it("rejects a tampered chunk", async () => {
    const key = MemoryVault.chunkKey(objectId, 1);
    const chunk = vault.chunks.get(key)!;
    const data = new Uint8Array(chunk.data.slice(0));
    data[0]! ^= 0x01;
    vault.chunks.set(key, { ...chunk, data: data.buffer });

    await expect(downloadFile(ctx, objectId)).rejects.toThrow();
  });

  it("rejects chunks delivered out of order", async () => {
    const first = vault.chunks.get(MemoryVault.chunkKey(objectId, 0))!;
    const second = vault.chunks.get(MemoryVault.chunkKey(objectId, 1))!;
    vault.chunks.set(MemoryVault.chunkKey(objectId, 0), { ...second, chunkIndex: 0 });
    vault.chunks.set(MemoryVault.chunkKey(objectId, 1), { ...first, chunkIndex: 1 });

    await expect(downloadFile(ctx, objectId)).rejects.toThrow();
  });

  it.each([
    ["lowered", 1],
    ["raised", 3],
  ])("rejects a vault chunk count %s against the authenticated manifest", async (_, count) => {
    vault.patchManifest(objectId, { chunkCount: count });
    await expect(downloadFile(ctx, objectId)).rejects.toThrow("chunk count does not match");
  });

  it("rejects a wrapped key moved from another object", async () => {
    const other = await uploadFile(ctx, new File(["other"], "other.txt"));
    vault.patchManifest(objectId, { wrappedKey: vault.manifests.get(other.objectId)!.wrappedKey });

    await expect(downloadFile(ctx, objectId)).rejects.toThrow();
    const listed = await listFiles(ctx);
    expect(listed.find((f) => f.objectId === objectId)?.name).toMatch(/failed integrity check/);
    expect(listed.find((f) => f.objectId === other.objectId)?.name).toBe("other.txt");
  });

  it("rejects a missing chunk", async () => {
    vault.chunks.delete(MemoryVault.chunkKey(objectId, 1));
    await expect(downloadFile(ctx, objectId)).rejects.toThrow("missing chunk 1");
  });

  it("rejects objects sealed under another device's master key", async () => {
    await expect(downloadFile({ ...ctx, keys: await deviceKeys() }, objectId)).rejects.toThrow();
  });
});
