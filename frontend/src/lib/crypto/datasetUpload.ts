// A steward's dataset upload, sealed in the crypto worker (ADR 0012, ADR
// 0014). The UI thread sends the file with the schema and row cap the
// footer worker read; this module checks the recipient key, seals the
// Parquet object and the snapshot manifest, and sends the
// `PUT /api/v1/datasets/{dataset}` body. Imported only by worker-side code.
//
// * Recipient: the device's own HPKE key, which the steward's browser holds
//   (ADR 0004: "steward uploads are also wrapped to the steward's own
//   browser key"). Sealers must not trust the enrollment record, so the
//   seal uses the key held here, and the record is only checked against it:
//   an upload is refused before anything is sealed unless the tenant's
//   enrolled key is this key, since a query releases the enrolled key and
//   an upload sealed to any other could never be opened. #175 replaces the
//   byte comparison with its enrollment check.
// * Bindings: the session's `tid`, the dataset, and an object id and
//   snapshot version drawn here, in the `info` strings
//   `steward-upload-v1|{tid}|{dataset}|{object}` and
//   `tenant-snapshot-manifest-v1|{tid}|{dataset}|{version}`, both built by
//   the wasm module from the backend's own definitions.
// * Suite: `HPK1`, the browser's suite until #186. Production refuses it.
//
// Nothing is sealed until every check that does not need the plaintext has
// passed, and the worker's copy of the plaintext is zeroed once sealed.

import { fromB64 } from "../encoding";
import {
  ENVELOPE_OVERHEAD_BYTES,
  SNAPSHOT_VERSION,
  UPLOAD_DATASET,
  isDeclaredSchema,
  isRowCap,
  type DeclaredColumn,
} from "../datasets/schema";
import { envelopeInfo, sealToTenant } from "./envelope";
import type { DeviceKeys } from "./keystore";
import type { SessionClaims } from "./protocol";

/** Names the body format (`platform_connectors::upload::UPLOAD_MAGIC`). */
const UPLOAD_MAGIC = "DSU1";
/** Largest header and sealed manifest the route accepts. */
export const MAX_HEADER_BYTES = 128 * 1024;
export const MAX_MANIFEST_BYTES = 16 * 1024;
/** Raw X25519 public key length: the only recipient the module seals to. */
const HPK1_PUBLIC_KEY_BYTES = 32;

/** A tenant id as the API spells it; an `info` string binds this spelling. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface DatasetUploadRequest {
  file: File;
  /** The dataset id, in the upload namespace. */
  dataset: string;
  /** The schema the footer declares. */
  schema: DeclaredColumn[];
  /** The rows the footer reports: the declared row cap. */
  rowCap: number;
  /** The dataset's current snapshot version, from the listing; null for a
   *  dataset with none. The new version must be later. */
  currentVersion: string | null;
  /** The upload size limit, from the listing (`dataset_max_bytes`). */
  maxBytes: number;
}

/** What the upload route stored. */
export interface DatasetUploadResult {
  dataset: string;
  version: string;
  object: string;
  suite: string;
  ciphertextBytes: number;
}

export interface UploadContext {
  /** The device's stored keys, loaded and never created here: key setup
   *  happens in the drive, behind its first-run acknowledgement. */
  keys: DeviceKeys | null;
  /** The session, snapshotted when the upload starts. */
  session: { token: string; claims: SessionClaims } | null;
  apiBaseUrl: string;
  /** Milliseconds since the Unix epoch. */
  now?: () => number;
}

/** A refusal the steward can act on. Its message never carries key
 *  material or content. */
export class UploadRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UploadRefused";
  }
}

/** Whether `value` names a snapshot version. */
export function isSnapshotVersion(value: unknown): value is string {
  return typeof value === "string" && SNAPSHOT_VERSION.test(value);
}

/** A new snapshot version: this clock in nanoseconds, or one nanosecond
 *  after `current` if that is later (ADR 0012), with a random suffix. */
export function nextSnapshotVersion(current: string | null, nowMs: number, suffix: Uint8Array): string {
  const now = BigInt(Math.floor(nowMs)) * 1_000_000n;
  const after = current === null ? 0n : BigInt(current.slice(0, 20)) + 1n;
  const nanos = now > after ? now : after;
  const hex = [...suffix].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${nanos.toString().padStart(20, "0")}-${hex}`;
}

function u32be(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

const encoder = new TextEncoder();

/** The upload header as JSON, refused if it is over the route's limit. A
 *  declaration within its bounds can still exceed it when its names are
 *  long and need escaping. Nothing in it depends on the file's bytes, so it
 *  is built before the file is read. */
export function uploadHeader(header: {
  version: string;
  object: string;
  row_cap: number;
  schema: DeclaredColumn[];
}): Uint8Array<ArrayBuffer> {
  const json = encoder.encode(JSON.stringify(header)) as Uint8Array<ArrayBuffer>;
  if (json.length < 1 || json.length > MAX_HEADER_BYTES) {
    throw new UploadRefused("The declared schema is too large to upload.");
  }
  return json;
}

/** The upload body (`platform_connectors::upload`): magic, header length,
 *  header JSON, manifest length, sealed manifest, sealed object. */
export function uploadBody(header: Uint8Array<ArrayBuffer>, manifest: ArrayBuffer, object: ArrayBuffer): Blob {
  if (manifest.byteLength < 1 || manifest.byteLength > MAX_MANIFEST_BYTES) {
    throw new Error("sealed manifest out of bounds");
  }
  return new Blob([
    UPLOAD_MAGIC,
    u32be(header.length),
    header,
    u32be(manifest.byteLength),
    manifest,
    object,
  ]);
}

function sameBytes(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false;
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  return x.every((byte, i) => byte === y[i]);
}

function bearer(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

/** The message for a refusal the API answered with. Its `error` field is a
 *  fixed reason, never input. */
async function apiMessage(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { error?: unknown };
    return typeof body.error === "string" ? body.error : null;
  } catch {
    return null;
  }
}

async function refusalFor(response: Response, dataset: string): Promise<Error> {
  switch (response.status) {
    case 401:
      return new UploadRefused("Not authenticated: the session was rejected. Sign in again, then upload.");
    case 403:
      return new UploadRefused("Not authorized: this account may not upload datasets.");
    case 404:
      return new UploadRefused(`${dataset} is not a dataset name you can upload to.`);
    case 409:
      return new UploadRefused(
        "A newer snapshot of this dataset was stored first. Reload your datasets, then upload again.",
      );
    case 413:
      return new UploadRefused("The file is larger than this deployment's upload limit.");
    case 422: {
      const reason = await apiMessage(response);
      return new UploadRefused(`The upload was refused: ${reason ?? "malformed upload"}.`);
    }
    case 502:
    case 503:
      return new UploadRefused(`Storage is unavailable (${response.status}); try again later.`);
    default:
      return new Error(`upload failed (${response.status})`);
  }
}

/** Refuses unless the tenant's enrolled key is `publicKeyRaw`. */
async function checkEnrolledKey(
  apiBaseUrl: string,
  token: string,
  publicKeyRaw: ArrayBuffer,
): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/api/v1/drive/enrollment`, { headers: bearer(token) });
  if (response.status === 401 || response.status === 403) throw await refusalFor(response, "");
  if (response.status === 404) {
    // The drive enrolls this key on its next load wherever the deployment
    // accepts the key's suite; production accepts only the hybrid suite,
    // which this browser cannot create until P36.
    throw new UploadRefused(
      "This browser's data key is not enrolled for your tenant, so a query could never open an upload sealed here. Opening the Drive tab enrolls it if this deployment accepts the browser's key suite.",
    );
  }
  if (!response.ok) throw new UploadRefused(`Could not read the enrolled key (${response.status}); try again later.`);
  let enrolled: ArrayBuffer;
  try {
    const body = (await response.json()) as { hpke_public_key_b64?: unknown };
    if (typeof body.hpke_public_key_b64 !== "string") throw new Error("no key");
    enrolled = fromB64(body.hpke_public_key_b64.trim());
  } catch {
    throw new UploadRefused("The enrolled key record is malformed.");
  }
  if (!sameBytes(enrolled, publicKeyRaw)) {
    throw new UploadRefused(
      "The key enrolled for your tenant is not this browser's key, so a query could never open an upload sealed here. Upload from the browser that enrolled the key.",
    );
  }
}

/** Seal `request.file` to the device's key and upload it as the tenant's
 *  dataset `request.dataset`. Every refusal before the seal is an
 *  `UploadRefused`; when one is thrown nothing is sealed and no upload is
 *  sent, and every one but the read of the file itself comes before the
 *  file is read. */
export async function uploadDataset(
  ctx: UploadContext,
  request: DatasetUploadRequest,
): Promise<DatasetUploadResult> {
  const { file, dataset, schema, rowCap, currentVersion, maxBytes } = request;
  // The worker protocol has checked these; check again where they are used.
  if (!UPLOAD_DATASET.test(dataset)) throw new UploadRefused("The dataset name must start with upload_.");
  if (!isDeclaredSchema(schema) || !isRowCap(rowCap)) throw new UploadRefused("The declared schema is not valid.");
  if (currentVersion !== null && !isSnapshotVersion(currentVersion)) {
    throw new UploadRefused("The dataset's current version is malformed; reload your datasets.");
  }
  if (!ctx.session) throw new UploadRefused("no session token");
  const { token, claims } = ctx.session;
  if (!CANONICAL_UUID.test(claims.tid)) {
    throw new UploadRefused("The session's tenant id is not one the API issues.");
  }
  const key = ctx.keys?.hpke;
  if (!key) {
    throw new UploadRefused(
      "This browser has no data key yet. Open the Drive tab once to create and enroll it, then upload.",
    );
  }
  if (key.publicKeyRaw.byteLength !== HPK1_PUBLIC_KEY_BYTES) {
    throw new UploadRefused("This browser's data key is not one it can seal uploads to.");
  }
  if (!Number.isSafeInteger(maxBytes) || file.size + ENVELOPE_OVERHEAD_BYTES > maxBytes) {
    throw new UploadRefused("The file is larger than this deployment's upload limit.");
  }
  const tenant = claims.tid;
  const object = crypto.randomUUID();
  const version = nextSnapshotVersion(
    currentVersion,
    (ctx.now ?? Date.now)(),
    crypto.getRandomValues(new Uint8Array(16)),
  );
  const header = uploadHeader({ version, object, row_cap: rowCap, schema });
  await checkEnrolledKey(ctx.apiBaseUrl, token, key.publicKeyRaw);

  const plaintext = await file.arrayBuffer();
  let sealedObject: ArrayBuffer;
  try {
    if (plaintext.byteLength !== file.size) throw new UploadRefused("The file changed while it was read.");
    sealedObject = await sealToTenant(
      key.publicKeyRaw,
      await envelopeInfo.stewardUpload(tenant, dataset, object),
      plaintext,
    );
  } finally {
    new Uint8Array(plaintext).fill(0);
  }
  const manifest = await sealToTenant(
    key.publicKeyRaw,
    await envelopeInfo.snapshotManifest(tenant, dataset, version),
    encoder.encode(JSON.stringify({ version, objects: [object] })).buffer as ArrayBuffer,
  );
  const body = uploadBody(header, manifest, sealedObject);

  const response = await fetch(`${ctx.apiBaseUrl}/api/v1/datasets/${encodeURIComponent(dataset)}`, {
    method: "PUT",
    headers: { ...bearer(token), "Content-Type": "application/octet-stream" },
    body,
  });
  if (!response.ok) throw await refusalFor(response, dataset);
  const stored = (await response.json()) as Record<string, unknown>;
  if (stored.dataset !== dataset || stored.version !== version || stored.object !== object) {
    throw new Error("the API stored another upload than the one sent");
  }
  return {
    dataset,
    version,
    object,
    suite: String(stored.suite),
    ciphertextBytes: Number(stored.ciphertext_bytes),
  };
}
