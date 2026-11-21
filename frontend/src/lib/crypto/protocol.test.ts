import { describe, expect, it } from "vitest";
import { decodeSessionClaims, parseWorkerRequest } from "./protocol";

describe("parseWorkerRequest", () => {
  it("accepts every well-formed request", () => {
    const file = new File(["x"], "a.txt");
    expect(parseWorkerRequest({ id: 1, op: "init" })).toEqual({ id: 1, op: "init" });
    expect(parseWorkerRequest({ id: 2, op: "list" })).toEqual({ id: 2, op: "list" });
    expect(parseWorkerRequest({ id: 3, op: "upload", file })).toEqual({ id: 3, op: "upload", file });
    expect(parseWorkerRequest({ id: 4, op: "download", objectId: "o" })).toEqual({
      id: 4,
      op: "download",
      objectId: "o",
    });
    expect(parseWorkerRequest({ id: 5, op: "remove", objectId: "o" })).toEqual({
      id: 5,
      op: "remove",
      objectId: "o",
    });
    expect(parseWorkerRequest({ id: 6, op: "session", token: "a.b.c" })).toEqual({
      id: 6,
      op: "session",
      token: "a.b.c",
    });
  });

  it("drops extra fields", () => {
    expect(parseWorkerRequest({ id: 1, op: "list", extra: "x" })).toEqual({ id: 1, op: "list" });
  });

  it.each([
    null,
    "list",
    42,
    [],
    {},
    { op: "list" },
    { id: "1", op: "list" },
    { id: 1.5, op: "list" },
    { id: 1, op: "export" },
    { id: 1, op: "upload" },
    { id: 1, op: "upload", file: "not-a-file" },
    { id: 1, op: "download" },
    { id: 1, op: "download", objectId: "" },
    { id: 1, op: "remove", objectId: 7 },
    { id: 1, op: "session" },
    { id: 1, op: "session", token: "" },
    { id: 1, op: "session", token: 42 },
  ])("rejects %j", (data) => {
    expect(parseWorkerRequest(data)).toBeNull();
  });
});

describe("parseWorkerRequest: dataset uploads", () => {
  const file = new File(["PAR1"], "cohort.parquet");
  const upload = {
    id: 9,
    op: "uploadDataset",
    file,
    dataset: "upload_cohorts",
    schema: [
      { name: "condition", type: "string" },
      { name: "age", type: "int64" },
    ],
    rowCap: 7,
    currentVersion: null,
    maxBytes: 1024,
  };

  it("accepts a well-formed upload, keeping only the declared fields", () => {
    const withExtras = {
      ...upload,
      extra: "x",
      schema: upload.schema.map((c) => ({ ...c })),
      currentVersion: `01700000000000000000-${"a".repeat(32)}`,
    };
    expect(parseWorkerRequest(withExtras)).toEqual({
      ...upload,
      currentVersion: `01700000000000000000-${"a".repeat(32)}`,
    });
  });

  it.each([
    ["no file", { file: undefined }],
    ["a name, not a file", { file: "cohort.parquet" }],
    ["a dataset outside the upload namespace", { dataset: "health" }],
    ["a dataset id with a slash", { dataset: "upload_a/b" }],
    ["a dataset id over 64 bytes", { dataset: `upload_${"x".repeat(58)}` }],
    ["no schema", { schema: undefined }],
    ["an empty schema", { schema: [] }],
    ["an unknown type", { schema: [{ name: "a", type: "utf8" }] }],
    ["an extra column field", { schema: [{ name: "a", type: "int64", nullable: true }] }],
    ["a duplicate column", { schema: [{ name: "a", type: "int64" }, { name: "a", type: "date" }] }],
    ["a row cap of zero", { rowCap: 0 }],
    ["a fractional row cap", { rowCap: 1.5 }],
    ["a row cap over 2^53 - 1", { rowCap: 2 ** 53 }],
    ["a malformed version", { currentVersion: "1700000000" }],
    ["no size limit", { maxBytes: undefined }],
    ["a zero size limit", { maxBytes: 0 }],
  ])("rejects %s", (_what, change) => {
    expect(parseWorkerRequest({ ...upload, ...change })).toBeNull();
  });
});

function b64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jwt(payload: unknown): string {
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(payload)}.sig`;
}

describe("decodeSessionClaims", () => {
  const claims = { iss: "quackxide-dev", sub: "user-1", tid: "tenant-1" };

  it("decodes iss, sub and tid, ignoring other claims", () => {
    expect(decodeSessionClaims(jwt({ ...claims, aud: "api", exp: 1, typ: "access" }))).toEqual(
      claims,
    );
  });

  it.each([
    "",
    "not-a-jwt",
    "a.b",
    "a.b.c.d",
    `${b64url({})}..sig`,
    `${b64url({})}.%%%.sig`,
    `${b64url({})}.${btoa("not json")}.sig`,
    jwt(null),
    jwt("string"),
    jwt({ sub: "user-1", tid: "tenant-1" }),
    jwt({ ...claims, tid: "" }),
    jwt({ ...claims, tid: 7 }),
  ])("rejects %j", (token) => {
    expect(decodeSessionClaims(token)).toBeNull();
  });
});
