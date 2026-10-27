// The wasm envelope module against the shared vectors (fixtures/envelope/,
// checked on the Rust side by backend/crates/envelope-wasm/tests/vectors.rs).
// Node cannot fetch the module by URL, so the tests load it inline.

import { beforeAll, describe, expect, it } from "vitest";
import vectors from "../../../../fixtures/envelope/hpk1.json";
import browserSealed from "../../../../fixtures/envelope/hpk1-browser-sealed.json";
import { fromB64 } from "../encoding";
import { generateHpkeKeypair, isX25519Supported } from "./core";
import { envelopeInfo, loadEnvelopeModule, sealToTenant } from "./envelope";
import envelopeWasmInline from "./wasm/envelope_bg.wasm?url&inline";

const text = (bytes: Uint8Array | ArrayBuffer) => new TextDecoder().decode(bytes);
const utf8 = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;
const recipientA = () => fromB64(vectors.recipients.find((r) => r.name === "a")!.public_b64);

const { magic, encapped_key_bytes: encappedKeyBytes, tag_bytes: tagBytes } = vectors.suite;
const infoBuilders: Record<string, (...fields: string[]) => Promise<Uint8Array>> = {
  steward_upload: (t, d, o) => envelopeInfo.stewardUpload(t!, d!, o!),
  connector_object: (t, c, o) => envelopeInfo.connectorObject(t!, c!, o!),
  snapshot_manifest: (t, c, v) => envelopeInfo.snapshotManifest(t!, c!, v!),
  research_result: (t, q) => envelopeInfo.researchResult(t!, q!),
};

beforeAll(async () => {
  await loadEnvelopeModule(envelopeWasmInline);
});

describe("info strings", () => {
  it.each(vectors.info)("$kind matches the shared vector", async ({ kind, fields, info }) => {
    const build = infoBuilders[kind];
    expect(build).toBeDefined();
    expect(text(await build!(...fields))).toBe(info);
  });

  it.each(vectors.refused_info_fields)("refuses the field %j", async (field) => {
    await expect(envelopeInfo.stewardUpload(field, "d", "o")).rejects.toThrow(
      "invalid envelope info field",
    );
    await expect(envelopeInfo.researchResult("t", field)).rejects.toThrow(
      "invalid envelope info field",
    );
  });
});

describe("enrollment keys", () => {
  it.each(vectors.enrollment)("$name", async ({ public_b64: b64, valid }) => {
    let raw: ArrayBuffer;
    try {
      raw = fromB64(b64);
    } catch {
      expect(valid).toBe(false);
      return;
    }
    const seal = sealToTenant(raw, new Uint8Array([105]), utf8("x"));
    if (valid) await expect(seal).resolves.toBeInstanceOf(ArrayBuffer);
    else await expect(seal).rejects.toThrow("invalid public key");
  });

  it("seals to a browser-generated key once enrolled as raw bytes", async () => {
    if (!(await isX25519Supported())) return;
    const { publicKeyRaw } = await generateHpkeKeypair();
    const envelope = await sealToTenant(publicKeyRaw, new Uint8Array([105]), utf8("x"));
    expect(text(envelope.slice(0, 4))).toBe(magic);
  });
});

describe("seal", () => {
  it("frames the envelope as magic || encapped key || ciphertext", async () => {
    const plaintext = utf8(vectors.envelopes[0]!.plaintext);
    const info = new TextEncoder().encode(vectors.envelopes[0]!.info);
    const envelope = await sealToTenant(recipientA(), info, plaintext);
    expect(text(envelope.slice(0, 4))).toBe(magic);
    expect(envelope.byteLength).toBe(4 + encappedKeyBytes + plaintext.byteLength + tagBytes);
  });

  it("uses a fresh ephemeral key for every seal", async () => {
    const info = new Uint8Array([105]);
    const first = new Uint8Array(await sealToTenant(recipientA(), info, utf8("x")));
    const second = new Uint8Array(await sealToTenant(recipientA(), info, utf8("x")));
    expect(first.subarray(4, 4 + encappedKeyBytes)).not.toEqual(
      second.subarray(4, 4 + encappedKeyBytes),
    );
  });

  it("leaves the caller's plaintext untouched", async () => {
    const plaintext = utf8("synthetic rows");
    await sealToTenant(recipientA(), new Uint8Array([105]), plaintext);
    expect(text(plaintext)).toBe("synthetic rows");
  });

  it("committed browser-sealed envelopes use the current frame", () => {
    expect(browserSealed.envelopes.length).toBeGreaterThan(0);
    for (const { envelope_b64: b64, plaintext } of browserSealed.envelopes) {
      const envelope = fromB64(b64);
      expect(text(envelope.slice(0, 4))).toBe(magic);
      expect(envelope.byteLength).toBe(4 + encappedKeyBytes + utf8(plaintext).byteLength + tagBytes);
    }
  });
});
