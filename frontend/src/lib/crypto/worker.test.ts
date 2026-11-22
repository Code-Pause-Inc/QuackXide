// Drives the crypto worker through its message protocol: session delivery,
// refresh, malformed tokens and the missing-token refusal in http mode.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkerResponse } from "./protocol";

vi.mock("./keystore", () => ({
  loadDeviceKeys: vi.fn(async () => ({
    tenantId: "local-tenant",
    kek: {} as CryptoKey,
    hpkePrivateKey: null,
    hpkePublicKeyRaw: null,
    createdAtIso: "2026-01-01T00:00:00.000Z",
  })),
  saveDeviceKeys: vi.fn(),
}));

// The envelope WebAssembly is a build artifact; sealing is not under test.
vi.mock("./envelope", () => ({ loadEnvelopeModule: vi.fn(async () => undefined) }));

// Key creation succeeds here, so a request that creates a key is seen.
vi.mock("./devicekey", () => ({
  createDeviceHpkeKey: vi.fn(async () => ({
    seedKey: {} as CryptoKey,
    publicKeyRaw: new ArrayBuffer(32),
    sealedPrivateKey: { iv: new ArrayBuffer(12), data: new ArrayBuffer(48) },
  })),
}));

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

// The cache is under test in attestation.test.ts; here only the wiring is.
const cache = vi.hoisted(() => ({
  current: vi.fn(),
  invalidate: vi.fn(),
  clear: vi.fn(),
}));
vi.mock("./attestation", () => ({
  EnclaveCache: vi.fn(function () {
    return cache;
  }),
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
  responses = [];
  authHeaders = [];
  cache.current.mockReset();
  cache.invalidate.mockReset();
  cache.clear.mockReset();
  vi.stubEnv("VITE_VAULT_MODE", "http");
  vi.stubGlobal("addEventListener", (_type: string, cb: (ev: MessageEvent) => void) => {
    handler = cb;
  });
  vi.stubGlobal("postMessage", (msg: WorkerResponse) => responses.push(msg));
  vi.stubGlobal("location", { origin: "http://localhost:5173" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
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

describe("crypto worker enclave operations", () => {
  it("answers the key id and expiry and never the keys", async () => {
    cache.current.mockResolvedValue({
      keyId: "k1",
      expiresAt: 1_800_000_000,
      requestKey: { suite: "s", publicKey: "pk" },
      signingKeys: { ed25519: "a", mlDsa65: "b" },
    });
    const res = await send({ op: "verifyEnclave" });
    expect(res).toEqual({
      id: res.id,
      type: "result",
      result: { keyId: "k1", expiresAtIso: "2027-01-15T08:00:00.000Z" },
    });
    expect(JSON.stringify(res)).not.toContain("requestKey");
  });

  it("reports a failed check with its message", async () => {
    cache.current.mockRejectedValue(new Error("attestation signature invalid"));
    expect(await send({ op: "verifyEnclave" })).toMatchObject({
      type: "error",
      message: "attestation signature invalid",
    });
  });

  it("invalidates the cache on request", async () => {
    expect(await send({ op: "invalidateEnclave" })).toMatchObject({ type: "result" });
    expect(cache.invalidate).toHaveBeenCalledTimes(1);
  });

  it("clears the cache when the tenant changes, not otherwise", async () => {
    await send({ op: "session", token: jwt("user-1", "tenant-1") });
    expect(cache.clear).toHaveBeenCalledTimes(1);
    cache.clear.mockClear();
    await send({ op: "session", token: jwt("user-1", "tenant-1") });
    expect(cache.clear).not.toHaveBeenCalled();
    await send({ op: "session", token: jwt("user-1", "tenant-2") });
    expect(cache.clear).toHaveBeenCalledTimes(1);
  });

  it("clears the cache on a malformed token", async () => {
    await send({ op: "session", token: jwt("user-1") });
    cache.clear.mockClear();
    await send({ op: "session", token: "not.a-jwt" });
    expect(cache.clear).toHaveBeenCalledTimes(1);
  });
});
