import { describe, expect, it } from "vitest";
import {
  budgetPath,
  dollarsToCents,
  formatMoney,
  formatRate,
  requestAccessPath,
  requestResolvePath,
  shortId,
  tenantFromJwt,
} from "./client";

describe("formatMoney", () => {
  it("renders whole amounts without cents", () => {
    expect(formatMoney(120000, "USD")).toBe("$1,200");
    expect(formatMoney(0, "USD")).toBe("$0");
  });

  it("keeps cents when they matter", () => {
    expect(formatMoney(40, "USD")).toBe("$0.40");
    expect(formatMoney(1250, "USD")).toBe("$12.50");
  });

  it("falls back for unknown currency codes", () => {
    expect(formatMoney(1234, "NOPE")).toBe("12.34 NOPE");
  });

  it("formats rates per query unit", () => {
    expect(formatRate(40, "USD")).toBe("$0.40 / query");
  });
});

describe("shortId", () => {
  it("takes the first uuid block", () => {
    expect(shortId("3f2a91c4-1111-2222-3333-444444444444")).toBe("3f2a91c4");
    expect(shortId("plain")).toBe("plain");
  });
});

describe("tenantFromJwt", () => {
  const encode = (claims: object) =>
    `h.${btoa(JSON.stringify(claims)).replace(/\+/g, "-").replace(/\//g, "_")}.s`;

  it("extracts the tid claim without verification", () => {
    expect(tenantFromJwt(encode({ tid: "abc-123", sub: "user" }))).toBe("abc-123");
  });

  it("returns null for malformed tokens or missing tid", () => {
    expect(tenantFromJwt("not-a-jwt")).toBeNull();
    expect(tenantFromJwt("a.%%%.c")).toBeNull();
    expect(tenantFromJwt(encode({ sub: "user" }))).toBeNull();
  });
});

describe("paths", () => {
  it("escape identifiers", () => {
    expect(requestAccessPath("a/b")).toBe("/api/v1/catalog/a%2Fb/request");
    expect(budgetPath("g1")).toBe("/api/v1/grants/g1/budget");
    expect(requestResolvePath("r1", "approve")).toBe("/api/v1/research/requests/r1/approve");
    expect(requestResolvePath("r/2", "deny")).toBe("/api/v1/research/requests/r%2F2/deny");
  });
});

describe("dollarsToCents", () => {
  it("parses whole and fractional amounts", () => {
    expect(dollarsToCents("1200")).toBe(120000);
    expect(dollarsToCents("12.50")).toBe(1250);
    expect(dollarsToCents("0.4")).toBe(40);
    expect(dollarsToCents("0")).toBe(0);
  });

  it("accepts human formatting", () => {
    expect(dollarsToCents(" $1,200 ")).toBe(120000);
    expect(dollarsToCents("$0.40")).toBe(40);
  });

  it("rejects anything that is not a clean amount", () => {
    expect(dollarsToCents("")).toBeNull();
    expect(dollarsToCents("abc")).toBeNull();
    expect(dollarsToCents("-5")).toBeNull();
    expect(dollarsToCents("1.234")).toBeNull();
    expect(dollarsToCents("1.")).toBeNull();
  });
});
