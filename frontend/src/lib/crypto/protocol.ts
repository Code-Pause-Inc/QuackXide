// UI thread <-> crypto worker protocol. The worker owns keys and ciphertext;
// the UI sees only opaque ids, requested summaries, and download Blobs.

export interface InitResult {
  /** True when device keys were generated for the first time in this call. */
  created: boolean;
  tenantId: string;
  /** False while the envelope module cannot load on this device, so it has
   *  no HPKE key yet; the drive works without one. */
  hpkeKeyAvailable: boolean;
  /** Raw X25519 public key (base64); null without an HPKE key. */
  hpkePublicKeyB64: string | null;
  /** Fingerprint of the device public key; null without an HPKE key. */
  fingerprint: string | null;
}

export interface DriveFileSummary {
  objectId: string;
  name: string;
  mimeType: string;
  sizeBytes: number;
  chunkCount: number;
  createdAtIso: string;
}

export type WorkerRequest =
  | { id: number; op: "init" }
  | { id: number; op: "upload"; file: File }
  | { id: number; op: "list" }
  | { id: number; op: "download"; objectId: string }
  | { id: number; op: "remove"; objectId: string }
  /** Deliver or replace the session bearer token. Held in worker memory only. */
  | { id: number; op: "session"; token: string };

/** Validate an untrusted message as a `WorkerRequest`; anything else is null. */
export function parseWorkerRequest(data: unknown): WorkerRequest | null {
  if (typeof data !== "object" || data === null) return null;
  const req = data as Record<string, unknown>;
  if (!Number.isSafeInteger(req.id)) return null;
  const id = req.id as number;
  switch (req.op) {
    case "init":
    case "list":
      return { id, op: req.op };
    case "upload":
      return req.file instanceof File ? { id, op: "upload", file: req.file } : null;
    case "download":
    case "remove":
      return typeof req.objectId === "string" && req.objectId.length > 0
        ? { id, op: req.op, objectId: req.objectId }
        : null;
    case "session":
      return typeof req.token === "string" && req.token.length > 0
        ? { id, op: "session", token: req.token }
        : null;
    default:
      return null;
  }
}

/** Identity claims read from the session token. */
export interface SessionClaims {
  iss: string;
  sub: string;
  tid: string;
}

/**
 * Decode the `iss`, `sub` and `tid` claims from a JWT; anything malformed is
 * null. This does NOT verify the signature (the browser cannot check HS256):
 * the API verifies the token on every request, and the API accepting the same
 * token is what makes `tid` authoritative.
 */
export function decodeSessionClaims(token: string): SessionClaims | null {
  const parts = token.split(".");
  const encoded = parts[1];
  if (parts.length !== 3 || parts.some((part) => part.length === 0) || !encoded) return null;
  let payload: unknown;
  try {
    const b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null) return null;
  const { iss, sub, tid } = payload as Record<string, unknown>;
  const valid = (v: unknown): v is string => typeof v === "string" && v.length > 0;
  return valid(iss) && valid(sub) && valid(tid) ? { iss, sub, tid } : null;
}

export interface DownloadResult {
  summary: DriveFileSummary;
  blob: Blob;
}

export type WorkerResponse =
  | { id: number; type: "result"; result: unknown }
  | { id: number; type: "error"; message: string }
  | { id: number; type: "progress"; done: number; total: number };
