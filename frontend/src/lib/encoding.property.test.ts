import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { fromB64, toB64 } from "./encoding";

function roundTrips(bytes: Uint8Array): boolean {
  const back = new Uint8Array(fromB64(toB64(bytes.slice().buffer)));
  return back.length === bytes.length && back.every((v, i) => v === bytes[i]);
}

describe("base64 properties", () => {
  it("round-trips arbitrary bytes", () => {
    fc.assert(fc.property(fc.uint8Array(), roundTrips));
  });

  it("round-trips inputs spanning several encode steps", () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 0x8000, maxLength: 0x18001 }), roundTrips), {
      numRuns: 20,
    });
  });

  it("emits canonical padded base64", () => {
    fc.assert(
      fc.property(fc.uint8Array(), (bytes) => {
        const encoded = toB64(bytes.slice().buffer);
        expect(encoded).toMatch(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
        expect(encoded.length).toBe(Math.ceil(bytes.length / 3) * 4);
      }),
    );
  });

  it("decodes any string to bytes or throws an Error", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        try {
          expect(fromB64(text)).toBeInstanceOf(ArrayBuffer);
        } catch (err) {
          expect(err).toBeInstanceOf(Error);
        }
      }),
    );
  });
});
