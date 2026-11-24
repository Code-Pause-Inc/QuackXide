// Drives the crypto worker through its message protocol: session delivery,
// refresh, malformed tokens and the missing-token refusal in http mode.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkerResponse } from "./protocol";

const stored = vi.hoisted(() => ({
  /** Whether the stored keys already hold an HPKE key. */
  hasHpke: false,
  /** Whether the envelope module loads, so a new HPKE key can be made. */
  moduleLoads: false,
  enrollStatus: 204,
}));

const hpkeKey = vi.hoisted(() => (fill: number) => ({
  seedKey: {} as CryptoKey,
  publicKeyRaw: new Uint8Array(32).fill(fill).buffer,
  sealedPrivateKey: { iv: new ArrayBuffer(12), data: new ArrayBuffer(48) },
}));

vi.mock("./keystore", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./keystore")>();
  return {
    ...actual,
    loadDeviceKeys: vi.fn(async (identity: { iss: string; sub: string; tid: string }) => ({
      identity,
      tenantId: identity.tid,
      kek: { stand_in: "kek" } as unknown as CryptoKey,
      hpke: stored.hasHpke ? hpkeKey(1) : null,
      createdAtIso: "2026-01-01T00:00:00.000Z",
    })),
    saveDeviceKeys: vi.fn(),
  };
});

vi.mock("./devicekey", () => ({
  createDeviceHpkeKey: vi.fn(async () => {
    if (!stored.moduleLoads) throw new Error("envelope module unavailable");
    return hpkeKey(9);
  }),
}));

// The envelope WebAssembly is a build artifact; sealing is not under test.
vi.mock("./envelope", () => ({ loadEnvelopeModule: vi.fn(async () => undefined) }));

// Stand-in drive layer: makes one vault request and reports the session
// claims the worker handed to the crypto core.
vi.mock("./drive", () => ({
  listFiles: vi.fn(async (ctx: { vault: { listManifests(): Promise<unknown> }; session: unknown }) => {
    await ctx.vault.listManifests();
    return ctx.session;
  }),
  uploadFile: vi.fn(),
  downloadFile: vi.fn(),
  removeFile: vi.fn(),
}));

function b64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jwt(sub: string, tid = "tenant-1"): string {
  return `${b64url({ alg: "HS256" })}.${b64url({ iss: "quackxide-dev", sub, tid })}.sig`;
}

let handler: ((ev: MessageEvent) => void) | null = null;
let responses: WorkerResponse[] = [];
let authHeaders: (string | null)[] = [];
let nextId = 1;

async function send(msg: Record<string, unknown>): Promise<WorkerResponse> {
  const id = nextId++;
  handler?.(new MessageEvent("message", { data: { ...msg, id } }));
  await vi.waitFor(() => {
    if (!responses.some((r) => r.id === id && r.type !== "progress")) throw new Error("pending");
  });
  return responses.find((r) => r.id === id && r.type !== "progress") as WorkerResponse;
}

beforeEach(async () => {
  vi.resetModules();
  stored.hasHpke = false;
  stored.moduleLoads = false;
  stored.enrollStatus = 204;
  responses = [];
  authHeaders = [];
  vi.stubEnv("VITE_VAULT_MODE", "http");
  vi.stubGlobal("addEventListener", (_type: string, cb: (ev: MessageEvent) => void) => {
    handler = cb;
  });
  vi.stubGlobal("postMessage", (msg: WorkerResponse) => responses.push(msg));
  vi.stubGlobal("location", { origin: "http://localhost:5173" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/enrollment") && init?.method === "PUT") {
        return new Response(null, { status: stored.enrollStatus });
      }
      authHeaders.push(new Headers(init?.headers).get("Authorization"));
      return new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  await import("./worker");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  handler = null;
});

describe("crypto worker session", () => {
  it("delivers a token and exposes its claims to the crypto core", async () => {
    expect(await send({ op: "session", token: jwt("user-1") })).toMatchObject({ type: "result" });
    const listed = await send({ op: "list" });
    expect(listed).toEqual({
      id: listed.id,
      type: "result",
      result: { iss: "quackxide-dev", sub: "user-1", tid: "tenant-1" },
    });
    expect(authHeaders).toEqual([`Bearer ${jwt("user-1")}`]);
  });

  it("uses a refreshed token without a restart", async () => {
    await send({ op: "session", token: jwt("user-1") });
    await send({ op: "list" });
    await send({ op: "session", token: jwt("user-2") });
    const listed = await send({ op: "list" });
    expect(listed).toMatchObject({ type: "result", result: { sub: "user-2" } });
    expect(authHeaders).toEqual([`Bearer ${jwt("user-1")}`, `Bearer ${jwt("user-2")}`]);
  });

  it("refuses a malformed token and exposes no claims", async () => {
    await send({ op: "session", token: jwt("user-1") });
    expect(await send({ op: "session", token: "not.a-jwt" })).toMatchObject({
      type: "error",
      message: "malformed session token",
    });
    // The earlier session is cleared, not kept.
    expect(await send({ op: "list" })).toMatchObject({ type: "error", message: "no session token" });
    expect(authHeaders).toEqual([]);
  });

  it("refuses vault calls in http mode without a token", async () => {
    expect(await send({ op: "list" })).toMatchObject({ type: "error", message: "no session token" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("never echoes the token in a response", async () => {
    const token = jwt("user-1");
    await send({ op: "session", token });
    await send({ op: "session", token: "bad" });
    await send({ op: "list" });
    expect(JSON.stringify(responses)).not.toContain(token);
  });
});

describe("crypto worker keys and enrollment", () => {
  it("binds the keys and tenant id to the session identity", async () => {
    await send({ op: "session", token: jwt("user-1", "tenant-9") });
    const init = await send({ op: "init" });
    expect(init).toMatchObject({
      type: "result",
      result: {
        tenantId: "tenant-9",
        identityKey: JSON.stringify(["quackxide-dev", "user-1", "tenant-9"]),
      },
    });
  });

  it("has no keys without a session in http mode", async () => {
    expect(await send({ op: "init" })).toMatchObject({ type: "error", message: "no session token" });
  });

  it("reports an enrolled key, and a refused one from another device", async () => {
    stored.hasHpke = true;
    await send({ op: "session", token: jwt("user-1") });
    expect(await send({ op: "init" })).toMatchObject({ result: { enrollment: "enrolled" } });

    stored.enrollStatus = 409;
    expect(await send({ op: "init" })).toMatchObject({ result: { enrollment: "refused" } });
  });

  it("adds an HPKE key later without replacing the master key", async () => {
    const keystore = await import("./keystore");
    await send({ op: "session", token: jwt("user-1") });
    expect(await send({ op: "init" })).toMatchObject({ result: { enrollment: "unavailable" } });
    expect(keystore.saveDeviceKeys).not.toHaveBeenCalled();

    // The envelope module now loads; a new worker starts.
    stored.moduleLoads = true;
    vi.resetModules();
    await import("./worker");
    const ks = await import("./keystore");
    await send({ op: "session", token: jwt("user-1") });
    expect(await send({ op: "init" })).toMatchObject({ result: { enrollment: "enrolled" } });
    expect(ks.saveDeviceKeys).toHaveBeenCalledWith(
      expect.objectContaining({
        kek: { stand_in: "kek" },
        hpke: expect.objectContaining({ publicKeyRaw: expect.any(ArrayBuffer) }),
      }),
    );
  });
});

describe("crypto worker dataset uploads", () => {
  const upload = {
    op: "uploadDataset",
    file: new File(["PAR1"], "cohort.parquet"),
    dataset: "upload_cohorts",
    schema: [{ name: "n", type: "int64" }],
    rowCap: 1,
    currentVersion: null,
    maxBytes: 1024,
  };

  it("refuses an upload without a session, before any request", async () => {
    expect(await send(upload)).toMatchObject({ type: "error", message: "no session token" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses an upload on a device without a data key, and creates none", async () => {
    const { saveDeviceKeys } = await import("./keystore");
    const { createDeviceHpkeKey } = await import("./devicekey");
    await send({ op: "session", token: jwt("user-1", "6f2c8a2e-1111-4222-8333-444455556666") });
    const response = await send(upload);
    expect(response).toMatchObject({ type: "error" });
    expect((response as { message: string }).message).toMatch(/no data key/);
    expect(createDeviceHpkeKey).not.toHaveBeenCalled();
    expect(saveDeviceKeys).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses an upload on a device with no key record, and creates none", async () => {
    const { loadDeviceKeys, saveDeviceKeys } = await import("./keystore");
    const { createDeviceHpkeKey } = await import("./devicekey");
    vi.mocked(loadDeviceKeys).mockResolvedValueOnce(null);
    await send({ op: "session", token: jwt("user-1", "6f2c8a2e-1111-4222-8333-444455556666") });
    const response = await send(upload);
    expect(response).toMatchObject({ type: "error" });
    expect((response as { message: string }).message).toMatch(/no data key/);
    expect(createDeviceHpkeKey).not.toHaveBeenCalled();
    expect(saveDeviceKeys).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("ignores a malformed upload request", async () => {
    const id = nextId++;
    handler?.(new MessageEvent("message", { data: { ...upload, id, dataset: "health" } }));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(responses.some((r) => r.id === id)).toBe(false);
  });
});
