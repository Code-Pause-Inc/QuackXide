import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { formatBytes } from "./format";

const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** Inverts formatBytes back to the byte count it displays. */
function displayed(text: string): number {
  const [value, unit] = text.split(" ");
  const exponent = UNITS.indexOf(unit ?? "");
  expect(exponent).toBeGreaterThanOrEqual(0);
  return Number(value) * 1024 ** exponent;
}

const size = fc.double({ min: 0, max: Number.MAX_VALUE, noNaN: true });

describe("formatBytes properties", () => {
  it("never throws and always displays a finite, non-negative size", () => {
    fc.assert(
      fc.property(fc.double(), (n) => {
        const shown = displayed(formatBytes(n));
        expect(Number.isFinite(shown) && shown >= 0).toBe(true);
      }),
    );
  });

  it("is monotonic for non-negative sizes", () => {
    fc.assert(
      fc.property(size, size, (a, b) => {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        expect(displayed(formatBytes(lo))).toBeLessThanOrEqual(displayed(formatBytes(hi)));
      }),
    );
  });

  it("stays below 1024 in every unit short of the largest", () => {
    fc.assert(
      fc.property(size, (n) => {
        const [value, unit] = formatBytes(n).split(" ");
        if (unit !== "TB") expect(Number(value)).toBeLessThanOrEqual(1024);
      }),
    );
  });
});
