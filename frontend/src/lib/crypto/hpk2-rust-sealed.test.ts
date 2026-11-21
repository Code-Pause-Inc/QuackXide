// ADR 0007's second direction: HPK2 frames sealed by the Rust backend
// (fixtures/envelope/hpk2-rust-sealed.json, written by
// backend/crates/platform-crypto/tests/hpk2_vectors.rs) open with hpke-js,
// an implementation that shares no code with it. The matching test of
// hpk2-js-sealed.json runs on the Rust side.

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";
import { describe, expect, it } from "vitest";
import vectors from "../../../../fixtures/envelope/hpk2-rust-sealed.json";
import { fromB64 } from "../encoding";

const MAGIC_BYTES = 4;
const ENCAPPED_KEY_BYTES = 1120;
const kem = new XWing();
const suite = new CipherSuite({ kem, kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("HPK2 frames sealed by Rust", () => {
  it("has the recipient's public key", async () => {
    for (const r of vectors.recipients) {
      const pair = await kem.generateKeyPairDerand(new Uint8Array(fromB64(r.seed_b64)));
      const publicKey = new Uint8Array(await kem.serializePublicKey(pair.publicKey));
      expect(publicKey).toEqual(new Uint8Array(fromB64(r.public_b64)));
    }
  });

  it.each(vectors.envelopes)("opens $kind ($plaintext.length bytes)", async (e) => {
    const recipient = vectors.recipients.find((r) => r.name === e.recipient)!;
    const recipientKey = (
      await kem.generateKeyPairDerand(new Uint8Array(fromB64(recipient.seed_b64)))
    ).privateKey;
    const frame = new Uint8Array(fromB64(e.envelope_b64));
    expect(new TextDecoder().decode(frame.slice(0, MAGIC_BYTES))).toBe("HPK2");
    const enc = frame.slice(MAGIC_BYTES, MAGIC_BYTES + ENCAPPED_KEY_BYTES);
    const ct = frame.slice(MAGIC_BYTES + ENCAPPED_KEY_BYTES);

    const opened = await suite.open({ recipientKey, enc, info: utf8(e.info) }, ct);
    expect(new TextDecoder().decode(opened)).toBe(e.plaintext);

    // The binding is in `info`: another string must not open it.
    await expect(
      suite.open({ recipientKey, enc, info: utf8(`${e.info}x`) }, ct),
    ).rejects.toThrow();
  });
});
