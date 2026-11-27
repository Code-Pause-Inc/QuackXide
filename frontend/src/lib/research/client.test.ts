import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ResearchClient,
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

describe("ResearchClient.budget", () => {
  afterEach(() => vi.unstubAllGlobals());

  const respond = (status: number) =>
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status })));

  it("returns null when the grant has no budget", async () => {
    respond(404);
    await expect(new ResearchClient("", "t").budget("g1")).resolves.toBeNull();
  });

  it("throws on any other failure, so it is not read as no budget", async () => {
    respond(502);
    await expect(new ResearchClient("", "t").budget("g1")).rejects.toThrow(
      "failed to load budget standing (502)",
    );
  });
});

describe("ResearchClient.datasets", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("lists the stored datasets with the caller's token", async () => {
    const listing = {
      datasets: [
        {
          dataset: "upload_cohorts",
          version: `01763116830123456789-${"0".repeat(32)}`,
          written_at: "2025-11-14T10:40:30.123Z",
          suite: "HPK1",
          row_cap: 7,
          schema: [{ name: "condition", type: "string" }],
          object_count: 1,
          ciphertext_bytes: 1932,
          objects: ["00000000-aaaa-4bbb-8ccc-000000000001"],
        },
      ],
      dataset_max_bytes: 67108864,
    };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(listing)));
    vi.stubGlobal("fetch", fetchMock);
    await expect(new ResearchClient("https://api.example/", "tok").datasets()).resolves.toEqual(listing);
    expect(fetchMock).toHaveBeenCalledWith("https://api.example/api/v1/datasets", {
      headers: { Authorization: "Bearer tok" },
    });
  });

  it.each([
    [401, "not authenticated"],
    [422, "too many datasets to list"],
    [502, "storage is unavailable (502)"],
    [503, "storage is unavailable (503)"],
    [500, "failed to load your datasets (500)"],
  ])("explains a %i", async (status, message) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status })));
    await expect(new ResearchClient("", "t").datasets()).rejects.toThrow(message);
  });
});

describe("ResearchClient.connectors", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("loads the connector columns with the caller's token", async () => {
    const connectors = [
      {
        slug: "quickbooks",
        display_name: "QuickBooks",
        kind: "accounting",
        columns: [{ name: "id", type: "string" }],
      },
    ];
    const fetchMock = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify({ connectors }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(new ResearchClient("https://api.example/", "t").connectors()).resolves.toEqual(
      connectors,
    );
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://api.example/api/v1/connectors");
    expect(init?.headers).toEqual({ Authorization: "Bearer t" });
  });

  it("throws when they cannot be loaded", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 502 })));
    await expect(new ResearchClient("", "t").connectors()).rejects.toThrow(
      "failed to load connector columns (502)",
    );
  });
});

describe("ResearchClient.researchQuery", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("posts the plain query with the caller's token", async () => {
    const result = {
      rows: [{ condition: "flu", n: 6 }],
      row_count: 1,
      suppressed_rows: 1,
      min_cohort: 5,
      budget_remaining: 99,
      tee_platform: "simulated",
    };
    const fetchMock = vi.fn<typeof fetch>(async () => new Response(JSON.stringify(result)));
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      new ResearchClient("https://api.example", "tok").researchQuery("s1", "health", "SELECT 1"),
    ).resolves.toEqual(result);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://api.example/api/v1/research/query");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({
      steward_tenant: "s1",
      connector: "health",
      sql: "SELECT 1",
    });
  });

  it("shows the API's fixed refusal message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "query refused" }), { status: 422 })),
    );
    await expect(new ResearchClient("", "t").researchQuery("s", "c", "x")).rejects.toThrow(
      "query refused (422)",
    );
  });
});
