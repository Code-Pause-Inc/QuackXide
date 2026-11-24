import { describe, expect, it } from "vitest";

import { parsePageHeaders } from "./pageHeaders";

describe("parsePageHeaders", () => {
  it("reads one header per line, keeping the file's names", () => {
    expect(parsePageHeaders("X-Frame-Options: DENY\nReferrer-Policy: no-referrer\n")).toEqual({
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    });
  });

  it("refuses a line that is not `Name: value`", () => {
    expect(() => parsePageHeaders("X-Frame-Options DENY\n")).toThrow(/Name: value/);
    expect(() => parsePageHeaders("X-Frame-Options: DENY\n\n")).toThrow(/Name: value/);
  });

  it("refuses a header named twice, in any case", () => {
    expect(() => parsePageHeaders("X-Frame-Options: DENY\nx-frame-options: SAMEORIGIN\n")).toThrow(/twice/);
  });
});
