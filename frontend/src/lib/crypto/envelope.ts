// Tenant envelope seal and open in the crypto worker: the wasm32 build of
// the backend's own HPKE envelope code (backend/crates/envelope-wasm, built
// into ./wasm/ by scripts/build-wasm.sh). Only worker-side code imports this
// module, and ESLint refuses the wasm glue anywhere else.
//
// Sealing uses only the recipient's public key. Opening takes the device's
// raw private key, which devicekey.ts decrypts just before the call; this
// module overwrites the caller's copy with zeros and the wasm side
// zeroizes its own (ADR 0007, "Browser private-key storage"). The KEK and
// file keys never enter wasm memory.

import type { AttestationTrust } from "../../config/attestation";
import envelopeWasmUrl from "./wasm/envelope_bg.wasm?url";
import init, {
  connectorObjectInfo,
  openEnvelope,
  publicKeyFromPrivateKey,
  researchQueryBinding,
  researchQueryInfo,
  researchResultInfo,
  sealEnvelope,
  snapshotManifestInfo,
  stewardUploadInfo,
  verifyAttestation,
} from "./wasm/envelope";

let loading: Promise<void> | null = null;
let memory: WebAssembly.Memory | null = null;

/** Instantiate the module once. A failed load is not cached, so the next
 *  call retries; until one succeeds every seal is refused. */
export function loadEnvelopeModule(source: string | URL = envelopeWasmUrl): Promise<void> {
  loading ??= init({ module_or_path: source }).then(
    (exports) => {
      memory = exports.memory;
    },
    (err: unknown) => {
      loading = null;
      throw err;
    },
  );
  return loading;
}

/** The module's linear memory size in bytes, or null before it loads.
 *  Linear memory only grows, so after a seal this is the module's peak
 *  (docs/BENCHMARKS.md). */
export function envelopeMemoryBytes(): number | null {
  return memory ? memory.buffer.byteLength : null;
}

/** Seal `plaintext` to a tenant's raw public key under `info`. Returns the
 *  framed envelope; its magic names the suite. */
export async function sealToTenant(
  recipientPublicKeyRaw: ArrayBuffer,
  info: Uint8Array,
  plaintext: ArrayBuffer,
): Promise<ArrayBuffer> {
  await loadEnvelopeModule();
  const envelope = sealEnvelope(
    new Uint8Array(recipientPublicKeyRaw),
    info,
    new Uint8Array(plaintext),
  );
  // wasm-bindgen returns a fresh copy out of wasm memory, so the buffer is
  // exactly the envelope.
  return envelope.buffer as ArrayBuffer;
}

/** Open an `HPK1` envelope with a raw X25519 private key under `info`; an
 *  `HPK2` frame is refused until P36. `privateKey` is overwritten with zeros
 *  before this returns, whether or not the open succeeds. Rejects on
 *  tamper, wrong recipient, wrong `info` or an unknown frame. */
export async function openWithPrivateKey(
  privateKey: Uint8Array,
  info: Uint8Array,
  envelope: ArrayBuffer,
): Promise<ArrayBuffer> {
  try {
    await loadEnvelopeModule();
    // wasm-bindgen copies the key into wasm memory; Rust zeroizes that copy.
    const plaintext = openEnvelope(privateKey, info, new Uint8Array(envelope));
    return plaintext.buffer as ArrayBuffer;
  } finally {
    privateKey.fill(0);
  }
}

/** The raw public key of a raw private key, for enrollment. Leaves the
 *  caller's `privateKey` as it is: the caller still needs it. */
export async function publicKeyOf(privateKey: Uint8Array): Promise<ArrayBuffer> {
  await loadEnvelopeModule();
  return publicKeyFromPrivateKey(privateKey).buffer as ArrayBuffer;
}

/** What a verified attestation bundle vouches for. */
export interface VerifiedEnclave {
  keyId: string;
  /** Seconds since the epoch. */
  expiresAt: number;
  requestKey: { suite: string; publicKey: string };
  signingKeys: { ed25519: string; mlDsa65: string };
}

/** Run the five attestation checks (the wasm export does all of them) on a
 *  fetched bundle and key set against `challenge`. Rejects with the failed
 *  check's message; nothing is returned for a bundle that fails any. */
export async function verifyAttestationBundle(
  bundleJson: string,
  challenge: Uint8Array,
  jwksJson: string,
  trust: AttestationTrust,
): Promise<VerifiedEnclave> {
  await loadEnvelopeModule();
  const verified = JSON.parse(
    verifyAttestation(
      bundleJson,
      challenge,
      jwksJson,
      trust.issuer,
      trust.imageDigests,
      !trust.release,
    ),
  ) as {
    key_id: string;
    expires_at: number;
    request_key: { suite: string; public_key: string };
    signing_keys: { ed25519: string; ml_dsa_65: string };
  };
  return {
    keyId: verified.key_id,
    expiresAt: verified.expires_at,
    requestKey: { suite: verified.request_key.suite, publicKey: verified.request_key.public_key },
    signingKeys: {
      ed25519: verified.signing_keys.ed25519,
      mlDsa65: verified.signing_keys.ml_dsa_65,
    },
  };
}

/** HPKE `info` strings, defined once in the backend (`platform_crypto::info`)
 *  and pinned by fixtures/envelope/. A field that is empty or contains `|`
 *  is refused. */
export const envelopeInfo = {
  async stewardUpload(tenant: string, dataset: string, object: string): Promise<Uint8Array> {
    await loadEnvelopeModule();
    return stewardUploadInfo(tenant, dataset, object);
  },
  async connectorObject(tenant: string, connector: string, object: string): Promise<Uint8Array> {
    await loadEnvelopeModule();
    return connectorObjectInfo(tenant, connector, object);
  },
  async snapshotManifest(tenant: string, connector: string, version: string): Promise<Uint8Array> {
    await loadEnvelopeModule();
    return snapshotManifestInfo(tenant, connector, version);
  },
  async researchResult(researcherTenant: string, query: string): Promise<Uint8Array> {
    await loadEnvelopeModule();
    return researchResultInfo(researcherTenant, query);
  },
  async researchQuery(tenant: string, grantId: string): Promise<Uint8Array> {
    await loadEnvelopeModule();
    return researchQueryInfo(tenant, grantId);
  },
  /** The `query` field of `researchResult` for a request (ADR 0010). The
   *  request nonce is 32 bytes; an empty schema version is refused. */
  async researchQueryBinding(
    grantId: string,
    requestNonce: Uint8Array,
    sql: string,
    schemaVersion?: string,
  ): Promise<string> {
    await loadEnvelopeModule();
    return researchQueryBinding(grantId, requestNonce, sql, schemaVersion);
  },
};
