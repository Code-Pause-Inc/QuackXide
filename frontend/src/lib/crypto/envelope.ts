// Tenant envelope sealing in the crypto worker: the wasm32 build of the
// backend's own HPKE envelope code (backend/crates/envelope-wasm, built into
// ./wasm/ by scripts/build-wasm.sh). Only worker-side code imports this
// module, and ESLint refuses the wasm glue anywhere else.
//
// Sealing uses only the recipient's public key: no private key, KEK or file
// key enters wasm memory.

import envelopeWasmUrl from "./wasm/envelope_bg.wasm?url";
import init, {
  connectorObjectInfo,
  researchResultInfo,
  sealEnvelope,
  snapshotManifestInfo,
  stewardUploadInfo,
} from "./wasm/envelope";

let loading: Promise<void> | null = null;

/** Instantiate the module once. A failed load is not cached, so the next
 *  call retries; until one succeeds every seal is refused. */
export function loadEnvelopeModule(source: string | URL = envelopeWasmUrl): Promise<void> {
  loading ??= init({ module_or_path: source }).then(
    () => undefined,
    (err: unknown) => {
      loading = null;
      throw err;
    },
  );
  return loading;
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
};
