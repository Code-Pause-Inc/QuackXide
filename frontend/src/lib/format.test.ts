import { describe, expect, it } from "vitest";
import { errorMessage, formatBytes } from "./format";

describe("formatBytes", () => {
  it("formats across units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(13)).toBe("13 B");
    expect(formatBytes(1024)).toBe("1 KB");
    expect(formatBytes(1730)).toBe("1.7 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5 MB");
  });

  it("treats non-positive/invalid input as zero", () => {
    expect(formatBytes(-5)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
  });
});

describe("errorMessage", () => {
  it("uses the error's message, or the fallback for non-errors", () => {
    expect(errorMessage(new Error("boom"), "fallback")).toBe("boom");
    expect(errorMessage("boom", "fallback")).toBe("fallback");
  });
});
