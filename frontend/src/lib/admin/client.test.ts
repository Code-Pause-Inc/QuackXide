import { describe, expect, it } from "vitest";
import { connectorTogglePath } from "./client";

describe("connectorTogglePath", () => {
  it("builds a tenant-scoped connector path", () => {
    expect(connectorTogglePath("tid-1", "quickbooks")).toBe(
      "/admin/tenants/tid-1/connectors/quickbooks",
    );
  });

  it("url-encodes path segments", () => {
    expect(connectorTogglePath("a/b", "x y")).toBe("/admin/tenants/a%2Fb/connectors/x%20y");
  });
});
