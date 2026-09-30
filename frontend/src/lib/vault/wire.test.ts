import { describe, expect, it } from "vitest";
import type { ChunkRecord, ManifestRecord } from "../crypto/types";
import {
  IV_BYTES,
  bodyToManifestRecord,
  decodeChunkBody,
  encodeChunkBody,
  manifestRecordToBody,
} from "./wire";

function buf(fill: number, length: number): ArrayBuffer {
  return new Uint8Array(length).fill(fill).buffer;
}

describe("chunk wire format", () => {
  const record: ChunkRecord = {
    objectId: "obj-1",
    chunkIndex: 4,
    iv: buf(9, IV_BYTES),
    data: buf(7, 40),
  };

  it("frames as [iv][ciphertext] and decodes back at the 12-byte boundary", () => {
    const body = encodeChunkBody(record);
    expect(body.length).toBe(IV_BYTES + 40);

    const decoded = decodeChunkBody("obj-1", 4, body.buffer);
    expect(new Uint8Array(decoded.iv)).toEqual(new Uint8Array(record.iv));
    expect(new Uint8Array(decoded.data)).toEqual(new Uint8Array(record.data));
    expect(decoded.chunkIndex).toBe(4);
  });

  it("rejects an IV of the wrong length at encode time", () => {
    expect(() => encodeChunkBody({ ...record, iv: buf(9, 4) })).toThrow();
  });

  it("rejects bodies too small to contain a sealed chunk", () => {
    expect(() => decodeChunkBody("obj-1", 0, buf(0, 10))).toThrow();
  });
});

describe("manifest wire format", () => {
  const record: ManifestRecord = {
    objectId: "obj-1",
    tenantId: "tenant-1",
    wrappedKey: { iv: buf(1, IV_BYTES), data: buf(2, 40) },
    manifest: { iv: buf(3, IV_BYTES), data: buf(4, 64) },
    chunkCount: 3,
    encryptedSizeBytes: 12_345,
    createdAtIso: "2026-07-30T12:00:00.000Z",
  };

  it("round-trips through the snake_case JSON body", () => {
    const body = manifestRecordToBody(record);
    expect(body.chunk_count).toBe(3);
    expect(typeof body.wrapped_key.iv_b64).toBe("string");

    const back = bodyToManifestRecord("obj-1", "tenant-1", body);
    expect(back.chunkCount).toBe(record.chunkCount);
    expect(back.encryptedSizeBytes).toBe(record.encryptedSizeBytes);
    expect(back.createdAtIso).toBe(record.createdAtIso);
    expect(new Uint8Array(back.wrappedKey.data)).toEqual(new Uint8Array(record.wrappedKey.data));
    expect(new Uint8Array(back.manifest.iv)).toEqual(new Uint8Array(record.manifest.iv));
  });
});
