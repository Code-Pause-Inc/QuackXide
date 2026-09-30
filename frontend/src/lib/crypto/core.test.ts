// Node's WebCrypto enforces the same extractability and AES-GCM semantics as
// browsers.

import { describe, expect, it } from "vitest";
import {
  CHUNK_SIZE_BYTES,
  chunkAad,
  createFileKey,
  decryptManifest,
  decryptPayload,
  dekAad,
  encryptManifest,
  encryptPayload,
  generateFileKey,
  generateHpkeKeypair,
  generateMasterKey,
  isX25519Supported,
  keyFingerprint,
  manifestAad,
  unwrapFileKey,
  wrapFileKey,
} from "./core";
import type { FileManifest } from "./types";

const TENANT = "6f2c8a2e-1111-4222-8333-444455556666";
const OBJECT = "00000000-aaaa-4bbb-8ccc-000000000001";

function bytes(text: string): ArrayBuffer {
  return new TextEncoder().encode(text).buffer as ArrayBuffer;
}

describe("master key custody", () => {
  it("generates a non-extractable KEK that cannot be exported", async () => {
    const kek = await generateMasterKey();
    expect(kek.extractable).toBe(false);
    expect(kek.usages.sort()).toEqual(["unwrapKey", "wrapKey"]);
    await expect(crypto.subtle.exportKey("raw", kek)).rejects.toThrow();
  });
});

describe("file key wrap/unwrap", () => {
  it("round-trips a DEK through the KEK and keeps the unwrapped copy non-extractable", async () => {
    const kek = await generateMasterKey();
    const dek = await generateFileKey();
    const aad = dekAad(TENANT, OBJECT);

    const sealed = await encryptPayload(dek, chunkAad(TENANT, OBJECT, 0), bytes("hello vault"));
    const wrapped = await wrapFileKey(kek, dek, aad);

    const unwrapped = await unwrapFileKey(kek, wrapped, aad);
    expect(unwrapped.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", unwrapped)).rejects.toThrow();

    const plain = await decryptPayload(unwrapped, chunkAad(TENANT, OBJECT, 0), sealed);
    expect(new TextDecoder().decode(plain)).toBe("hello vault");
  });

  it("creates upload keys that are non-extractable from the start", async () => {
    const kek = await generateMasterKey();
    const aad = dekAad(TENANT, OBJECT);
    const { dek, wrappedKey } = await createFileKey(kek, aad);
    expect(dek.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", dek)).rejects.toThrow();

    const sealed = await encryptPayload(dek, chunkAad(TENANT, OBJECT, 0), bytes("upload"));
    const reopened = await unwrapFileKey(kek, wrappedKey, aad);
    const plain = await decryptPayload(reopened, chunkAad(TENANT, OBJECT, 0), sealed);
    expect(new TextDecoder().decode(plain)).toBe("upload");
  });

  it("refuses to unwrap a DEK under a different object's AAD (no key re-attachment)", async () => {
    const kek = await generateMasterKey();
    const dek = await generateFileKey();
    const wrapped = await wrapFileKey(kek, dek, dekAad(TENANT, OBJECT));
    await expect(
      unwrapFileKey(kek, wrapped, dekAad(TENANT, "00000000-aaaa-4bbb-8ccc-999999999999")),
    ).rejects.toThrow();
  });
});

describe("chunk encryption", () => {
  it("round-trips content, including the empty payload", async () => {
    const dek = await generateFileKey();
    for (const text of ["", "ledger row", "x".repeat(10_000)]) {
      const aad = chunkAad(TENANT, OBJECT, 0);
      const sealed = await encryptPayload(dek, aad, bytes(text));
      const plain = await decryptPayload(dek, aad, sealed);
      expect(new TextDecoder().decode(plain)).toBe(text);
    }
  });

  it("rejects tampered ciphertext", async () => {
    const dek = await generateFileKey();
    const aad = chunkAad(TENANT, OBJECT, 0);
    const sealed = await encryptPayload(dek, aad, bytes("payload"));
    const corrupted = new Uint8Array(sealed.data.slice(0));
    corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
    await expect(
      decryptPayload(dek, aad, { iv: sealed.iv, data: corrupted.buffer }),
    ).rejects.toThrow();
  });

  it("rejects a chunk replayed at a different index (AAD binding)", async () => {
    const dek = await generateFileKey();
    const sealed = await encryptPayload(dek, chunkAad(TENANT, OBJECT, 3), bytes("chunk 3"));
    await expect(decryptPayload(dek, chunkAad(TENANT, OBJECT, 4), sealed)).rejects.toThrow();
  });

  it("uses a fresh random IV per encryption", async () => {
    const dek = await generateFileKey();
    const ivs = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      const sealed = await encryptPayload(dek, chunkAad(TENANT, OBJECT, i), bytes("same"));
      ivs.add([...new Uint8Array(sealed.iv)].join(","));
    }
    expect(ivs.size).toBe(50);
  });

  it("keeps the chunk size a sane constant", () => {
    expect(CHUNK_SIZE_BYTES).toBe(4 * 1024 * 1024);
  });
});

describe("encrypted manifest", () => {
  const manifest: FileManifest = {
    name: "Q3 board deck.pdf",
    mimeType: "application/pdf",
    sizeBytes: 123_456,
    chunkCount: 1,
    chunkSizeBytes: CHUNK_SIZE_BYTES,
    createdAtIso: "2026-07-30T12:00:00.000Z",
  };

  it("round-trips filenames and metadata under encryption", async () => {
    const dek = await generateFileKey();
    const sealed = await encryptManifest(dek, manifestAad(TENANT, OBJECT), manifest);
    expect(new TextDecoder().decode(sealed.data)).not.toContain("board deck");
    const opened = await decryptManifest(dek, manifestAad(TENANT, OBJECT), sealed);
    expect(opened).toEqual(manifest);
  });

  it("is bound to its object id", async () => {
    const dek = await generateFileKey();
    const sealed = await encryptManifest(dek, manifestAad(TENANT, OBJECT), manifest);
    await expect(
      decryptManifest(dek, manifestAad(TENANT, "00000000-aaaa-4bbb-8ccc-999999999999"), sealed),
    ).rejects.toThrow();
  });
});

const x25519 = await isX25519Supported();

describe.runIf(x25519)("HPKE X25519 enrollment keys", () => {
  it("keeps the private key non-extractable and exports a 32-byte public key", async () => {
    const pair = await generateHpkeKeypair();
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.publicKeyRaw.byteLength).toBe(32);
    await expect(crypto.subtle.exportKey("raw", pair.privateKey)).rejects.toThrow();
  });

  it("produces distinct keypairs with stable fingerprints", async () => {
    const a = await generateHpkeKeypair();
    const b = await generateHpkeKeypair();
    const fpA1 = await keyFingerprint(a.publicKeyRaw);
    const fpA2 = await keyFingerprint(a.publicKeyRaw);
    const fpB = await keyFingerprint(b.publicKeyRaw);
    expect(fpA1).toBe(fpA2);
    expect(fpA1).not.toBe(fpB);
    expect(fpA1).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
  });
});

describe.runIf(!x25519)("HPKE X25519 unsupported environment", () => {
  it("reports unsupported instead of failing", () => {
    expect(x25519).toBe(false);
  });
});
