// The crypto worker's dataset upload: the body it seals and sends, the
// recipient-key check, and every refusal before anything is sealed.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import vectors from "../../../../fixtures/envelope/hpk1.json";
import { parquetFixture } from "../../test/parquetFixtures";
import { ENVELOPE_OVERHEAD_BYTES, type DeclaredColumn } from "../datasets/schema";
import { fromB64, toB64 } from "../encoding";
import {
  UploadRefused,
  nextSnapshotVersion,
  uploadDataset,
  type DatasetUploadRequest,
  type UploadContext,
} from "./datasetUpload";
import * as envelope from "./envelope";
import type { DeviceKeys } from "./keystore";
import envelopeWasmInline from "./wasm/envelope_bg.wasm?url&inline";

vi.mock("./envelope", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./envelope")>();
  return { ...actual, sealToTenant: vi.fn(actual.sealToTenant) };
});

const API = "https://api.example";
const TENANT = "6f2c8a2e-1111-4222-8333-444455556666";
const DATASET = "upload_cohorts";
const SCHEMA: DeclaredColumn[] = [
  { name: "condition", type: "string" },
  { name: "age", type: "int64" },
];
const recipient = vectors.recipients.find((r) => r.name === "a")!;
const otherRecipient = vectors.recipients.find((r) => r.name === "b")!;

function keysFor(publicB64: string): DeviceKeys {
  return {
    tenantId: "local-device-id",
    kek: {} as CryptoKey,
    hpke: {
      seedKey: {} as CryptoKey,
      publicKeyRaw: fromB64(publicB64),
      sealedPrivateKey: { iv: new ArrayBuffer(12), data: new ArrayBuffer(48) },
    },
    createdAtIso: "2026-11-21T00:00:00.000Z",
  };
}

function context(overrides: Partial<UploadContext> = {}): UploadContext {
  return {
    keys: keysFor(recipient.public_b64),
    session: { token: "the.session.token", claims: { iss: "dev", sub: "steward", tid: TENANT } },
    apiBaseUrl: API,
    now: () => Date.UTC(2026, 10, 21),
    ...overrides,
  };
}

function request(overrides: Partial<DatasetUploadRequest> = {}): DatasetUploadRequest {
  return {
    file: new File([parquetFixture("upload-cohort.parquet")], "cohort.parquet"),
    dataset: DATASET,
    schema: SCHEMA,
    rowCap: 7,
    currentVersion: null,
    maxBytes: 64 * 1024 * 1024,
    ...overrides,
  };
}

interface Sent {
  url: string;
  method: string;
  auth: string | null;
  body: Uint8Array | null;
}

let sent: Sent[];
let enrollment: Response | (() => Response);
let stored: (body: Uint8Array) => Response;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

/** What the upload route answers for a body it stores. */
function storedAs(body: Uint8Array): Response {
  const header = parseBody(body).header;
  return json({
    dataset: DATASET,
    version: header.version,
    object: header.object,
    suite: "HPK1",
    ciphertext_bytes: parseBody(body).object.length,
  });
}

beforeAll(async () => {
  await envelope.loadEnvelopeModule(envelopeWasmInline);
});

beforeEach(() => {
  sent = [];
  enrollment = json({ hpke_public_key_b64: recipient.public_b64, suite: "HPK1" });
  stored = storedAs;
  vi.mocked(envelope.sealToTenant).mockClear();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = init?.body instanceof Blob ? new Uint8Array(await init.body.arrayBuffer()) : null;
      sent.push({
        url,
        method: init?.method ?? "GET",
        auth: new Headers(init?.headers).get("Authorization"),
        body,
      });
      if (url.endsWith("/api/v1/drive/enrollment")) {
        return typeof enrollment === "function" ? enrollment() : enrollment.clone();
      }
      return stored(body!);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The DSU1 body's parts (`platform_connectors::upload`). */
function parseBody(body: Uint8Array) {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const magic = new TextDecoder().decode(body.subarray(0, 4));
  const headerLength = view.getUint32(4, false);
  const header = JSON.parse(new TextDecoder().decode(body.subarray(8, 8 + headerLength)));
  const at = 8 + headerLength;
  const manifestLength = view.getUint32(at, false);
  return {
    magic,
    header,
    headerJson: new TextDecoder().decode(body.subarray(8, 8 + headerLength)),
    manifest: body.subarray(at + 4, at + 4 + manifestLength),
    object: body.subarray(at + 4 + manifestLength),
  };
}

const privateKey = () => new Uint8Array(fromB64(recipient.private_b64_test_only));
const text = (bytes: ArrayBuffer) => new TextDecoder().decode(bytes);

describe("a sealed upload", () => {
  it("seals the file and its manifest to the device key under the session's tenant", async () => {
    const result = await uploadDataset(context(), request());
    const put = sent.find((s) => s.method === "PUT")!;
    expect(put.url).toBe(`${API}/api/v1/datasets/${DATASET}`);
    expect(put.auth).toBe("Bearer the.session.token");

    const body = parseBody(put.body!);
    expect(body.magic).toBe("DSU1");
    expect(Object.keys(body.header)).toEqual(["version", "object", "row_cap", "schema"]);
    expect(body.header).toEqual({
      version: result.version,
      object: result.object,
      row_cap: 7,
      schema: SCHEMA,
    });
    expect(result.object).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    // Both open with the recipient's key under the bindings the enclave uses.
    const objectInfo = await envelope.envelopeInfo.stewardUpload(TENANT, DATASET, result.object);
    expect(text(objectInfo.buffer as ArrayBuffer)).toBe(`steward-upload-v1|${TENANT}|${DATASET}|${result.object}`);
    const parquet = await envelope.openWithPrivateKey(privateKey(), objectInfo, body.object.slice().buffer);
    expect(new Uint8Array(parquet)).toEqual(parquetFixture("upload-cohort.parquet"));
    expect(body.object.length).toBe(parquet.byteLength + ENVELOPE_OVERHEAD_BYTES);

    const manifestInfo = await envelope.envelopeInfo.snapshotManifest(TENANT, DATASET, result.version);
    const manifest = await envelope.openWithPrivateKey(privateKey(), manifestInfo, body.manifest.slice().buffer);
    expect(JSON.parse(text(manifest))).toEqual({ version: result.version, objects: [result.object] });

    // Under another object id, the object does not open.
    const wrong = await envelope.envelopeInfo.stewardUpload(TENANT, DATASET, crypto.randomUUID());
    await expect(envelope.openWithPrivateKey(privateKey(), wrong, body.object.slice().buffer)).rejects.toThrow();
    expect(result).toMatchObject({ dataset: DATASET, suite: "HPK1" });
  });

  it("checks the enrolled key before it seals, with the session's token", async () => {
    await uploadDataset(context(), request());
    expect(sent.map((s) => [s.method, s.url, s.auth])).toEqual([
      ["GET", `${API}/api/v1/drive/enrollment`, "Bearer the.session.token"],
      ["PUT", `${API}/api/v1/datasets/${DATASET}`, "Bearer the.session.token"],
    ]);
  });

  it("zeroes its copy of the plaintext once it is sealed", async () => {
    let copy: ArrayBuffer | undefined;
    class Watched extends File {
      override async arrayBuffer(): Promise<ArrayBuffer> {
        copy = await super.arrayBuffer();
        return copy;
      }
    }
    await uploadDataset(context(), request({ file: new Watched([parquetFixture("upload-cohort.parquet")], "c") }));
    expect(copy!.byteLength).toBeGreaterThan(0);
    expect(new Uint8Array(copy!).every((b) => b === 0)).toBe(true);
  });

  it("refuses a response that names another upload", async () => {
    stored = () => json({ dataset: DATASET, version: "x", object: "y", suite: "HPK1", ciphertext_bytes: 1 });
    await expect(uploadDataset(context(), request())).rejects.toThrow("another upload");
  });
});

describe("the snapshot version", () => {
  const suffix = new Uint8Array(16).fill(0xab);
  it("is the clock in nanoseconds", () => {
    expect(nextSnapshotVersion(null, 1_700_000_000_123, suffix)).toBe(
      `00001700000000123000000-${"ab".repeat(16)}`.slice(3),
    );
  });

  it("is one nanosecond after the current one when the clock has not passed it", () => {
    const current = `01800000000000000000-${"0".repeat(32)}`;
    expect(nextSnapshotVersion(current, 1_700_000_000_000, suffix)).toBe(
      `01800000000000000001-${"ab".repeat(16)}`,
    );
    const older = `00000000000000000005-${"0".repeat(32)}`;
    expect(nextSnapshotVersion(older, 1_700_000_000_000, suffix).slice(0, 20)).toBe("01700000000000000000");
  });

  it("is sent in the header and is later than the current one", async () => {
    const current = `09000000000000000000-${"0".repeat(32)}`;
    const result = await uploadDataset(context(), request({ currentVersion: current }));
    expect(result.version > current).toBe(true);
    expect(result.version.slice(0, 20)).toBe("09000000000000000001");
  });
});

describe("refusals before anything is sealed", () => {
  const cases: Array<[string, () => Promise<unknown>, string | RegExp]> = [
    ["no session", () => uploadDataset(context({ session: null }), request()), "no session token"],
    [
      "a tenant id the API would not issue",
      () =>
        uploadDataset(
          context({ session: { token: "t", claims: { iss: "i", sub: "s", tid: TENANT.toUpperCase() } } }),
          request(),
        ),
      "tenant id",
    ],
    ["no device keys", () => uploadDataset(context({ keys: null }), request()), "no data key"],
    [
      "a device without an HPKE key",
      () => uploadDataset(context({ keys: { ...keysFor(recipient.public_b64), hpke: null } }), request()),
      "no data key",
    ],
    [
      "a hybrid key, which the module does not seal to yet",
      () =>
        uploadDataset(
          context({ keys: keysFor(toB64(new Uint8Array(1216).buffer)) }),
          request(),
        ),
      "cannot|can seal|not one",
    ],
    [
      "a file over the size limit",
      () => uploadDataset(context(), request({ maxBytes: parquetFixture("upload-cohort.parquet").length + ENVELOPE_OVERHEAD_BYTES - 1 })),
      "upload limit",
    ],
    ["a dataset outside the upload namespace", () => uploadDataset(context(), request({ dataset: "health" })), "upload_"],
    ["an invalid schema", () => uploadDataset(context(), request({ schema: [] })), "schema"],
    ["a row cap of zero", () => uploadDataset(context(), request({ rowCap: 0 })), "schema"],
    ["a malformed current version", () => uploadDataset(context(), request({ currentVersion: "v1" })), "version"],
  ];
  for (const [what, run, message] of cases) {
    it(`refuses ${what}`, async () => {
      await expect(run()).rejects.toThrow(new RegExp(message));
      expect(envelope.sealToTenant).not.toHaveBeenCalled();
      expect(sent.some((s) => s.method === "PUT")).toBe(false);
    });
  }

  it("refuses a header over the route's limit before it reads the file or checks the key", async () => {
    // 512 distinct 128-byte names that JSON escapes to nearly twice that:
    // a valid declaration whose header is over 128 KiB.
    const schema: DeclaredColumn[] = Array.from({ length: 512 }, (_, i) => ({
      name: `${'"'.repeat(124)}${String(i).padStart(4, "0")}`,
      type: "int64",
    }));
    let read = false;
    class Watched extends File {
      override async arrayBuffer(): Promise<ArrayBuffer> {
        read = true;
        return super.arrayBuffer();
      }
    }
    const file = new Watched([parquetFixture("upload-cohort.parquet")], "c");
    await expect(uploadDataset(context(), request({ file, schema }))).rejects.toThrow("too large to upload");
    expect(read).toBe(false);
    expect(sent).toEqual([]);
    expect(envelope.sealToTenant).not.toHaveBeenCalled();
  });

  it("refuses every case above with an UploadRefused", async () => {
    for (const run of [
      () => uploadDataset(context({ session: null }), request()),
      () => uploadDataset(context({ keys: null }), request()),
      () => uploadDataset(context(), request({ dataset: "health" })),
    ]) {
      await expect(run()).rejects.toBeInstanceOf(UploadRefused);
    }
    for (const answer of [() => json({}, 404), () => json({ error: "storage" }, 502), () => json({ key: "x" })]) {
      enrollment = answer;
      await expect(uploadDataset(context(), request())).rejects.toBeInstanceOf(UploadRefused);
    }
  });

  it("accepts a file exactly at the size limit", async () => {
    const size = parquetFixture("upload-cohort.parquet").length;
    await expect(uploadDataset(context(), request({ maxBytes: size + ENVELOPE_OVERHEAD_BYTES }))).resolves.toMatchObject({
      dataset: DATASET,
    });
  });

  const keyCases: Array<[string, () => Response, string]> = [
    ["no enrolled key", () => json({ error: "not found" }, 404), "not enrolled"],
    ["another enrolled key", () => json({ hpke_public_key_b64: otherRecipient.public_b64 }), "not this browser's key"],
    ["a session the API rejects", () => json({ error: "unauthorized" }, 401), "Not authenticated"],
    ["a malformed enrollment record", () => json({ key: "x" }), "malformed"],
    ["an enrollment it cannot read", () => json({ error: "storage" }, 502), "Could not read the enrolled key"],
  ];
  for (const [what, answer, message] of keyCases) {
    it(`refuses ${what} before sealing`, async () => {
      enrollment = answer;
      await expect(uploadDataset(context(), request())).rejects.toThrow(message);
      expect(envelope.sealToTenant).not.toHaveBeenCalled();
      expect(sent.map((s) => s.method)).toEqual(["GET"]);
    });
  }
});

describe("the API's answer", () => {
  const answers: Array<[number, unknown, RegExp]> = [
    [401, { error: "unauthorized" }, /Not authenticated/],
    [403, { error: "forbidden" }, /Not authorized/],
    [404, { error: "not found" }, /not a dataset name/],
    [409, { error: "conflict" }, /newer snapshot/],
    [413, { error: "too large" }, /upload limit/],
    [422, { error: "declared schema does not match the dataset's recorded schema" }, /recorded schema/],
    [503, { error: "storage unavailable" }, /Storage is unavailable/],
  ];
  for (const [status, body, message] of answers) {
    it(`shows a ${status} clearly`, async () => {
      stored = () => json(body, status);
      const refusal = uploadDataset(context(), request());
      await expect(refusal).rejects.toThrow(message);
      await expect(refusal).rejects.toBeInstanceOf(UploadRefused);
    });
  }
});
