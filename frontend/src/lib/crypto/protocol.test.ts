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
