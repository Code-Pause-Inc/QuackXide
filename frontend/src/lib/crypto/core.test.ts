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
  generateMasterKey,
  generateSeedKey,
  keyFingerprint,
  manifestAad,
  privateKeyAad,
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

describe("seed key and private-key AAD", () => {
  it("keeps the seed key non-extractable and limited to encrypt and decrypt", async () => {
    const key = await generateSeedKey();
    expect(key.extractable).toBe(false);
    expect([...key.usages].sort()).toEqual(["decrypt", "encrypt"]);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
  });

  it("binds the tenant and the full public-key digest", async () => {
    const publicKey = new Uint8Array(32).fill(7).buffer;
    const aad = new TextDecoder().decode(await privateKeyAad(TENANT, publicKey));
    expect(aad).toMatch(new RegExp(`^x25519-key-v1\\|${TENANT}\\|[0-9a-f]{64}$`));
    const other = new TextDecoder().decode(
      await privateKeyAad(TENANT, new Uint8Array(32).fill(8).buffer),
    );
    expect(other).not.toBe(aad);
  });

  it("gives distinct public keys distinct, stable fingerprints", async () => {
    const a = new Uint8Array(32).fill(1).buffer;
    const b = new Uint8Array(32).fill(2).buffer;
    expect(await keyFingerprint(a)).toBe(await keyFingerprint(a));
    expect(await keyFingerprint(a)).not.toBe(await keyFingerprint(b));
    expect(await keyFingerprint(a)).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
  });
});
