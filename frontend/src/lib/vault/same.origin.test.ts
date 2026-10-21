// With an empty API base (the default), every client must build
// root-relative paths, so the browser sends them to the page's own origin
// and the Vite dev proxy (or the serving origin) handles them.

import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminClient } from "../admin/client";
import { ResearchClient } from "../research/client";
import { HttpVault } from "./httpVault";

const PAGE_ORIGIN = "http://localhost:5173";
// HttpVault runs in the crypto worker, where fetch resolves relative URLs
// against the worker script's URL. Vite serves the script from the page origin.
const WORKER_SCRIPT_URL = `${PAGE_ORIGIN}/src/lib/crypto/worker.ts?worker_file&type=module`;

function captureFetch(body: unknown = {}): string[] {
  const urls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      urls.push(String(input));
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return urls;
}

function expectRootRelative(url: string | undefined, path: string): void {
  expect(url).toBe(path);
  // "//host" would be protocol-relative and leave the origin.
  expect(url?.startsWith("/") && !url.startsWith("//")).toBe(true);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("same-origin API base", () => {
  it("HttpVault builds /api/v1/drive paths that resolve to the page origin in the worker", async () => {
    const urls = captureFetch([]);
    const vault = new HttpVault({ baseUrl: "", token: "t", tenantId: "tid-1" });

    await vault.listManifests();
    await vault.deleteObject("a/b");

    expectRootRelative(urls[0], "/api/v1/drive/objects");
    expectRootRelative(urls[1], "/api/v1/drive/objects/a%2Fb");
    const resolved = new URL(urls[0] ?? "", WORKER_SCRIPT_URL);
    expect(resolved.origin).toBe(PAGE_ORIGIN);
    expect(resolved.pathname).toBe("/api/v1/drive/objects");
  });

  it("ResearchClient builds /api/v1 paths", async () => {
    const urls = captureFetch({ grants: [] });
    await new ResearchClient("", "t").grants();
    expectRootRelative(urls[0], "/api/v1/grants");
  });

  it("AdminClient builds /admin paths", async () => {
    const urls = captureFetch({ tenants: [] });
    await new AdminClient("", "t").listTenants();
    expectRootRelative(urls[0], "/admin/tenants");
  });

  it("an explicit origin is still honored, with a trailing slash trimmed", async () => {
    const urls = captureFetch({ grants: [] });
    await new ResearchClient("https://api.example/", "t").grants();
    expect(urls[0]).toBe("https://api.example/api/v1/grants");
  });
});
