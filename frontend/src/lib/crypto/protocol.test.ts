import { describe, expect, it } from "vitest";
import { parseWorkerRequest } from "./protocol";

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
  ])("rejects %j", (data) => {
    expect(parseWorkerRequest(data)).toBeNull();
  });
});
