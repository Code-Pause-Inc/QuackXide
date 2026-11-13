// Writes the HPK2 (X-Wing) vectors that backend/crates/platform-crypto/tests/hpk2_vectors.rs
// checks, from implementations other than the Rust one (ADR 0007, "Proof of
// interoperability"):
//   fixtures/envelope/hpk2-kem.json       X-Wing KEM values from @noble/post-quantum
//   fixtures/envelope/hpk2-js-sealed.json HPK2 frames sealed by hpke-js, plus negatives
// Every seed below is public and test-only (docs/DATA_POLICY.md). Sealing is
// randomized: rerunning changes the frames, not whether they open.
//
// Run from frontend/:
//   node scripts/hpk2-vectors.mjs

import { writeFileSync, readFileSync } from "node:fs";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

const fixtures = new URL("../../fixtures/envelope/", import.meta.url);
const ascii = (text, length) => {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length !== length) throw new Error(`${JSON.stringify(text)} is not ${length} bytes`);
  return bytes;
};
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const write = (name, value) =>
  writeFileSync(new URL(name, fixtures), `${JSON.stringify(value, null, 2)}\n`);

// KEM level: seed -> public key; (public key, randomness) -> (ciphertext, shared secret).
const kemCases = [
  ["hpk2 kem 1: test-only seed!!!!!!", "hpk2 kem 1: test-only encapsulation randomness, 64 bytes long!!!"],
  ["hpk2 kem 2: test-only seed!!!!!!", "hpk2 kem 2: test-only encapsulation randomness, 64 bytes long!!!"],
  ["hpk2 kem 3: test-only seed!!!!!!", "hpk2 kem 3: test-only encapsulation randomness, 64 bytes long!!!"],
].map(([seedText, eseedText]) => {
  const seed = ascii(seedText, 32);
  const eseed = ascii(eseedText, 64);
  const { publicKey, secretKey } = ml_kem768_x25519.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(publicKey, eseed);
  if (b64(ml_kem768_x25519.decapsulate(cipherText, secretKey)) !== b64(sharedSecret)) {
    throw new Error("noble X-Wing does not decapsulate its own ciphertext");
  }
  return {
    seed_b64: b64(seed),
    public_key_b64: b64(publicKey),
    encapsulation_randomness_b64: b64(eseed),
    ciphertext_b64: b64(cipherText),
    shared_secret_b64: b64(sharedSecret),
  };
});
write("hpk2-kem.json", {
  note: "Test-only. X-Wing (ml_kem768_x25519) values from @noble/post-quantum; written by frontend/scripts/hpk2-vectors.mjs.",
  vectors: kemCases,
});

// Suite level: HPKE base mode, X-Wing, HKDF-SHA256, AES-256-GCM, empty AAD.
const suite = new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const recipients = {};
for (const name of ["a", "b"]) {
  const seed = ascii(`hpk2 suite recipient ${name}: testonly`, 32);
  const pair = await suite.kem.generateKeyPairDerand(seed);
  recipients[name] = { seed, pair, publicKey: new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)) };
}

const TENANT = "6f2c8a2e-1111-4222-8333-444455556666";
const CONNECTOR = "00000000-cccc-4ccc-8ccc-000000000001";
const DATASET = "00000000-dddd-4ddd-8ddd-000000000001";
const OBJECT = "00000000-aaaa-4bbb-8ccc-000000000001";
const VERSION = "00000000-eeee-4eee-8eee-000000000001";
const QUERY = "00000000-ffff-4fff-8fff-000000000001";
const infos = [
  { kind: "connector_object", fields: [TENANT, CONNECTOR, OBJECT], info: `tenant-envelope-v2|${TENANT}|${CONNECTOR}|${OBJECT}` },
  { kind: "snapshot_manifest", fields: [TENANT, CONNECTOR, VERSION], info: `tenant-snapshot-manifest-v2|${TENANT}|${CONNECTOR}|${VERSION}` },
  { kind: "steward_upload", fields: [TENANT, DATASET, OBJECT], info: `steward-upload-v2|${TENANT}|${DATASET}|${OBJECT}` },
  { kind: "research_result", fields: [TENANT, QUERY], info: `research-result-v2|${TENANT}|${QUERY}` },
];
const PLAINTEXT = "synthetic cohort rows: site-a,42\nsite-b,17\n";

const seal = async (to, info, plaintext) => {
  const { ct, enc } = await suite.seal(
    { recipientPublicKey: recipients[to].pair.publicKey, info: new TextEncoder().encode(info) },
    new TextEncoder().encode(plaintext),
  );
  return new Uint8Array([...new TextEncoder().encode("HPK2"), ...new Uint8Array(enc), ...new Uint8Array(ct)]);
};

const envelopes = [];
for (const { kind, fields, info } of infos) {
  envelopes.push({ recipient: "a", kind, fields, info, aad_b64: "", plaintext: PLAINTEXT, envelope_b64: b64(await seal("a", info, PLAINTEXT)) });
}
envelopes.push({ recipient: "a", kind: "steward_upload", fields: infos[2].fields, info: infos[2].info, aad_b64: "", plaintext: "", envelope_b64: b64(await seal("a", infos[2].info, "")) });

const base = await seal("a", infos[2].info, PLAINTEXT);
const tampered = base.slice();
tampered[tampered.length - 1] ^= 0xff;
const hpk1 = JSON.parse(readFileSync(new URL("hpk1.json", fixtures), "utf8")).envelopes.find((e) => !e.error);
const negative = [
  { case: "wrong_info", recipient: "a", info: infos[3].info, envelope_b64: b64(base), expect: "open_failed" },
  { case: "tampered", recipient: "a", info: infos[2].info, envelope_b64: b64(tampered), expect: "open_failed" },
  { case: "wrong_recipient", recipient: "b", info: infos[2].info, envelope_b64: b64(base), expect: "open_failed" },
  { case: "hpk1_frame", recipient: "a", info: hpk1.info, envelope_b64: hpk1.envelope_b64, expect: "suite_mismatch" },
];

write("hpk2-js-sealed.json", {
  note: "Test-only. HPK2 frames sealed by hpke-js (@hpke/core + @hpke/hybridkem-x-wing); written by frontend/scripts/hpk2-vectors.mjs.",
  recipients: Object.entries(recipients).map(([name, r]) => ({ name, seed_b64: b64(r.seed), public_b64: b64(r.publicKey) })),
  envelopes,
  negative,
});
console.log(`wrote ${kemCases.length} KEM vectors, ${envelopes.length} envelopes, ${negative.length} negatives`);
