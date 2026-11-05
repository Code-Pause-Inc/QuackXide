// The wasm envelope module against the shared vectors (fixtures/envelope/,
// checked on the Rust side by backend/crates/envelope-wasm/tests/vectors.rs).
// Node cannot fetch the module by URL, so the tests load it inline.

import { beforeAll, describe, expect, it } from "vitest";
import vectors from "../../../../fixtures/envelope/hpk1.json";
import browserSealed from "../../../../fixtures/envelope/hpk1-browser-sealed.json";
import { fromB64 } from "../encoding";
import { decryptPayload, privateKeyAad } from "./core";
import { createDeviceHpkeKey, openWithDeviceKey, PRIVATE_KEY_BYTES } from "./devicekey";
import {
  envelopeInfo,
  loadEnvelopeModule,
  openWithPrivateKey,
  publicKeyOf,
  sealToTenant,
} from "./envelope";
import envelopeWasmInline from "./wasm/envelope_bg.wasm?url&inline";

const text = (bytes: Uint8Array | ArrayBuffer) => new TextDecoder().decode(bytes);
const utf8 = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;
const recipient = (name: string) => vectors.recipients.find((r) => r.name === name)!;
const recipientA = () => fromB64(recipient("a").public_b64);
/** A fresh copy each call: opening zeroes the key it is given. */
const privateKeyOf = (name: string) =>
  new Uint8Array(fromB64(recipient(name).private_b64_test_only));

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

  it.each(vectors.recipients)("derives recipient $name's public key", async (r) => {
    const derived = await publicKeyOf(privateKeyOf(r.name));
    expect(new Uint8Array(derived)).toEqual(new Uint8Array(fromB64(r.public_b64)));
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

describe("open", () => {
  // Rust-sealed vectors, opened by the wasm build: the reverse of
  // hpk1-browser-sealed.json, which Rust opens.
  it.each(vectors.envelopes)("$name", async ({ recipient: name, info, envelope_b64, plaintext, error }) => {
    const open = openWithPrivateKey(
      privateKeyOf(name),
      new TextEncoder().encode(info),
      fromB64(envelope_b64),
    );
    if (error === null) expect(text(await open)).toBe(plaintext);
    else await expect(open).rejects.toThrow(error);
  });

  it("zeroes the caller's private key whether or not the open succeeds", async () => {
    const [opens, fails] = [vectors.envelopes[0]!, vectors.envelopes[1]!];
    for (const v of [opens, fails]) {
      const key = privateKeyOf("a");
      await openWithPrivateKey(key, new TextEncoder().encode(v.info), fromB64(v.envelope_b64)).catch(
        () => undefined,
      );
      expect(key.every((b) => b === 0)).toBe(true);
    }
  });

  it("refuses a private key of the wrong length", async () => {
    const envelope = fromB64(vectors.envelopes[0]!.envelope_b64);
    for (const length of [0, 31, 33]) {
      await expect(
        openWithPrivateKey(new Uint8Array(length), new Uint8Array([105]), envelope),
      ).rejects.toThrow("invalid key length");
    }
  });
});

describe("device HPKE key (ADR 0007 storage)", () => {
  const TENANT = "6f2c8a2e-1111-4222-8333-444455556666";
  const OTHER_TENANT = "6f2c8a2e-9999-4222-8333-444455556666";
  const info = new TextEncoder().encode("research-result-v1|t|q");

  it("seals to its public key and opens with the stored key", async () => {
    const key = await createDeviceHpkeKey(TENANT);
    expect(key.publicKeyRaw.byteLength).toBe(vectors.suite.public_key_bytes);
    expect(key.seedKey.extractable).toBe(false);
    const envelope = await sealToTenant(key.publicKeyRaw, info, utf8("synthetic result: n=42"));
    expect(text(await openWithDeviceKey(TENANT, key, info, envelope))).toBe(
      "synthetic result: n=42",
    );
    await expect(
      openWithDeviceKey(TENANT, key, new TextEncoder().encode("other"), envelope),
    ).rejects.toThrow("open failed");
  });

  it("stores the private key only encrypted, bound to tenant and public key", async () => {
    const key = await createDeviceHpkeKey(TENANT);
    const raw = new Uint8Array(
      await decryptPayload(key.seedKey, await privateKeyAad(TENANT, key.publicKeyRaw), key.sealedPrivateKey),
    );
    expect(raw.byteLength).toBe(PRIVATE_KEY_BYTES);
    expect(new Uint8Array(await publicKeyOf(raw))).toEqual(new Uint8Array(key.publicKeyRaw));
    expect(new Uint8Array(key.sealedPrivateKey.data)).not.toEqual(raw);
  });

  it("refuses a key record moved to another tenant or paired with another public key", async () => {
    const key = await createDeviceHpkeKey(TENANT);
    const other = await createDeviceHpkeKey(TENANT);
    const envelope = await sealToTenant(key.publicKeyRaw, info, utf8("x"));
    await expect(openWithDeviceKey(OTHER_TENANT, key, info, envelope)).rejects.toThrow();
    await expect(
      openWithDeviceKey(TENANT, { ...key, publicKeyRaw: other.publicKeyRaw }, info, envelope),
    ).rejects.toThrow();
    await expect(
      openWithDeviceKey(TENANT, { ...key, seedKey: other.seedKey }, info, envelope),
    ).rejects.toThrow();
  });

  it("generates a distinct key each time", async () => {
    const a = await createDeviceHpkeKey(TENANT);
    const b = await createDeviceHpkeKey(TENANT);
    expect(new Uint8Array(a.publicKeyRaw)).not.toEqual(new Uint8Array(b.publicKeyRaw));
  });
});
