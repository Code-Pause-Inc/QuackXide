import { describe, expect, it } from "vitest";

import bundles from "../../../fixtures/attestation/bundles.json";
import { resolveAttestationTrust } from "./attestation";

const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

describe("resolveAttestationTrust", () => {
  it("falls back to the simulator defaults outside release", () => {
    expect(resolveAttestationTrust({}, "development")).toEqual({
      issuer: "http://sim-attestation:8070",
      jwksUrl: "/sim-attestation/jwks",
      imageDigests: ["sha256:5155a7ab1d7e4c94d5bb3e1c6f0a3a4d6c7b8e9f00112233445566778899aabb"],
      release: false,
    });
  });

  it("keeps the dev defaults equal to the Rust simulator constants", () => {
    const trust = resolveAttestationTrust({}, "development");
    expect(trust?.issuer).toBe(bundles.simulator.issuer);
    expect(trust?.imageDigests).toEqual([bundles.simulator.image_digest]);
  });

  it("returns the release values, digests split and trimmed", () => {
    const trust = resolveAttestationTrust(
      {
        VITE_ATTESTATION_ISSUER: "https://attest.example",
        VITE_ATTESTATION_JWKS_URL: "https://attest.example/jwks",
        VITE_ATTESTATION_IMAGE_DIGESTS: ` ${DIGEST_A} , ${DIGEST_B}`,
      },
      "release",
    );
    expect(trust).toEqual({
      issuer: "https://attest.example",
      jwksUrl: "https://attest.example/jwks",
      imageDigests: [DIGEST_A, DIGEST_B],
      release: true,
    });
  });

  it("refuses a release build missing any value", () => {
    const full = {
      VITE_ATTESTATION_ISSUER: "https://attest.example",
      VITE_ATTESTATION_JWKS_URL: "https://attest.example/jwks",
      VITE_ATTESTATION_IMAGE_DIGESTS: DIGEST_A,
    };
    for (const key of Object.keys(full) as (keyof typeof full)[]) {
      expect(resolveAttestationTrust({ ...full, [key]: undefined }, "release")).toBeNull();
      expect(resolveAttestationTrust({ ...full, [key]: "  " }, "release")).toBeNull();
    }
  });
});
