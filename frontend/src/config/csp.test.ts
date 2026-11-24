import { describe, expect, it } from "vitest";

import policy from "../../../backend/crates/platform-api/page-csp.txt?raw";
import { GOOGLE_CS_JWKS_URL } from "./attestation";

describe("page CSP", () => {
  it("lets the page connect only to itself and the attestation key set", () => {
    const connect = policy
      .split(";")
      .map((directive) => directive.trim().split(/\s+/))
      .find(([name]) => name === "connect-src");
    expect(connect?.slice(1)).toEqual(["'self'", GOOGLE_CS_JWKS_URL]);
  });
});
