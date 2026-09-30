import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { ManifestRecord } from "../crypto/types";
import {
  IV_BYTES,
  bodyToManifestRecord,
  decodeChunkBody,
  encodeChunkBody,
  manifestRecordToBody,
} from "./wire";

const MIN_SEALED_BYTES = IV_BYTES + 16;

const bytes = (constraints?: fc.IntArrayConstraints) =>
  fc.uint8Array(constraints).map((a) => a.slice().buffer);

const payload = fc.record({
  iv: bytes({ minLength: IV_BYTES, maxLength: IV_BYTES }),
  data: bytes(),
});

const manifestRecord: fc.Arbitrary<ManifestRecord> = fc.record({
  objectId: fc.uuid(),
  tenantId: fc.uuid(),
  wrappedKey: payload,
  manifest: payload,
  chunkCount: fc.nat(),
  encryptedSizeBytes: fc.maxSafeNat(),
  createdAtIso: fc.date({ noInvalidDate: true }).map((d) => d.toISOString()),
});

function sameBytes(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** A refusal raised by the decoder itself, not a runtime fault. */
function expectControlledRefusal(run: () => unknown): void {
  let thrown: unknown;
  try {
    run();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(Error);
  expect(thrown).not.toBeInstanceOf(TypeError);
  expect(thrown).not.toBeInstanceOf(RangeError);
}

describe("chunk framing properties", () => {
  it("round-trips any sealed chunk", () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.nat(),
        bytes({ minLength: IV_BYTES, maxLength: IV_BYTES }),
        bytes({ minLength: MIN_SEALED_BYTES - IV_BYTES }),
        (objectId, chunkIndex, iv, data) => {
          const body = encodeChunkBody({ objectId, chunkIndex, iv, data });
          const back = decodeChunkBody(objectId, chunkIndex, body.buffer);
          return (
            back.objectId === objectId &&
            back.chunkIndex === chunkIndex &&
            sameBytes(back.iv, iv) &&
            sameBytes(back.data, data)
          );
        },
      ),
    );
  });

  it("refuses to encode an IV of any other length", () => {
    fc.assert(
      fc.property(
        bytes({ maxLength: 64 }).filter((iv) => iv.byteLength !== IV_BYTES),
        (iv) =>
          expectControlledRefusal(() =>
            encodeChunkBody({ objectId: "o", chunkIndex: 0, iv, data: iv }),
          ),
      ),
    );
  });

  it("never accepts a body too short to hold an IV and tag", () => {
    fc.assert(
      fc.property(bytes({ maxLength: MIN_SEALED_BYTES - 1 }), (body) =>
        expectControlledRefusal(() => decodeChunkBody("o", 0, body)),
      ),
    );
  });

  it("decodes arbitrary bytes into a lossless split or a controlled refusal", () => {
    fc.assert(
      fc.property(bytes({ maxLength: 256 }), (body) => {
        if (body.byteLength < MIN_SEALED_BYTES) {
          expectControlledRefusal(() => decodeChunkBody("o", 0, body));
          return;
        }
        const record = decodeChunkBody("o", 0, body);
        expect(record.iv.byteLength).toBe(IV_BYTES);
        expect(sameBytes(encodeChunkBody(record).buffer, body)).toBe(true);
      }),
    );
  });
});

describe("manifest body properties", () => {
  it("round-trips any record through the JSON body", () => {
    fc.assert(
      fc.property(manifestRecord, (record) => {
        const json = JSON.parse(JSON.stringify(manifestRecordToBody(record)));
        const back = bodyToManifestRecord(record.objectId, record.tenantId, json);
        expect(back).toMatchObject({
          objectId: record.objectId,
          tenantId: record.tenantId,
          chunkCount: record.chunkCount,
          encryptedSizeBytes: record.encryptedSizeBytes,
          createdAtIso: record.createdAtIso,
        });
        expect(sameBytes(back.wrappedKey.iv, record.wrappedKey.iv)).toBe(true);
        expect(sameBytes(back.wrappedKey.data, record.wrappedKey.data)).toBe(true);
        expect(sameBytes(back.manifest.iv, record.manifest.iv)).toBe(true);
        expect(sameBytes(back.manifest.data, record.manifest.data)).toBe(true);
      }),
    );
  });

  it("refuses arbitrary JSON with a controlled error", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (json) =>
        expectControlledRefusal(() => bodyToManifestRecord("o", "t", json as never)),
      ),
    );
  });

  it("refuses a valid body with any one field corrupted", () => {
    const corrupt = fc.oneof(
      fc.constant(undefined),
      fc.constant(null),
      fc.boolean(),
      fc.double().filter((n) => !Number.isSafeInteger(n) || n < 0),
      fc.constant("not base64!"),
      fc.constant({}),
    );
    const field: fc.Arbitrary<readonly [string, string?]> = fc.constantFrom(
      ["wrapped_key", "iv_b64"],
      ["wrapped_key", "data_b64"],
      ["manifest", "iv_b64"],
      ["manifest", "data_b64"],
      ["chunk_count"],
      ["encrypted_size_bytes"],
      ["created_at_iso"],
    );
    fc.assert(
      fc.property(manifestRecord, field, corrupt, (record, path, value) => {
        const body = JSON.parse(JSON.stringify(manifestRecordToBody(record)));
        const [head, leaf] = path;
        if (leaf === undefined) body[head] = value;
        else body[head][leaf] = value;
        const valid =
          (leaf !== undefined && typeof value === "string" && value !== "not base64!") ||
          (head === "created_at_iso" && typeof value === "string");
        fc.pre(!valid);
        expectControlledRefusal(() => bodyToManifestRecord("o", "t", body));
      }),
    );
  });
});
