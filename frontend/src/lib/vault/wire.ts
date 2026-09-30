// Drive API wire format:
// * chunks are binary bodies framed [12-byte IV][ciphertext + tag];
// * manifests are JSON with base64 payload fields, snake_case to match the
//   backend's serde types.

import { GCM_IV_BYTES } from "../crypto/core";
import type { ChunkRecord, ManifestRecord } from "../crypto/types";
import { fromB64, toB64 } from "../encoding";

export const IV_BYTES = GCM_IV_BYTES;
const GCM_TAG_BYTES = 16;
const MIN_CHUNK_BODY_BYTES = IV_BYTES + GCM_TAG_BYTES;

interface EncPayloadB64 {
  iv_b64: string;
  data_b64: string;
}

export interface ManifestBody {
  wrapped_key: EncPayloadB64;
  manifest: EncPayloadB64;
  chunk_count: number;
  encrypted_size_bytes: number;
  created_at_iso: string;
}

export function encodeChunkBody(record: ChunkRecord): Uint8Array<ArrayBuffer> {
  const iv = new Uint8Array(record.iv);
  if (iv.length !== IV_BYTES) throw new Error("chunk record has invalid IV length");
  const data = new Uint8Array(record.data);
  const body = new Uint8Array(iv.length + data.length);
  body.set(iv, 0);
  body.set(data, iv.length);
  return body;
}

export function decodeChunkBody(
  objectId: string,
  chunkIndex: number,
  body: ArrayBuffer,
): ChunkRecord {
  if (body.byteLength < MIN_CHUNK_BODY_BYTES) {
    throw new Error("chunk body too small to be sealed data");
  }
  return {
    objectId,
    chunkIndex,
    iv: body.slice(0, IV_BYTES),
    data: body.slice(IV_BYTES),
  };
}

export function manifestRecordToBody(record: ManifestRecord): ManifestBody {
  return {
    wrapped_key: {
      iv_b64: toB64(record.wrappedKey.iv),
      data_b64: toB64(record.wrappedKey.data),
    },
    manifest: {
      iv_b64: toB64(record.manifest.iv),
      data_b64: toB64(record.manifest.data),
    },
    chunk_count: record.chunkCount,
    encrypted_size_bytes: record.encryptedSizeBytes,
    created_at_iso: record.createdAtIso,
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function b64Field(
  body: Record<string, unknown>,
  name: string,
  key: keyof EncPayloadB64,
): ArrayBuffer {
  const payload = body[name];
  const value = isObject(payload) ? payload[key] : undefined;
  if (typeof value !== "string") throw new Error(`manifest body is missing ${name}.${key}`);
  try {
    return fromB64(value);
  } catch {
    throw new Error(`manifest body has malformed ${name}.${key}`);
  }
}

function countField(body: Record<string, unknown>, name: string): number {
  const value = body[name];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`manifest body has invalid ${name}`);
  }
  return value;
}

/** Validates an untrusted body from the drive API; malformed bodies are
 *  refused rather than defaulted. */
export function bodyToManifestRecord(
  objectId: string,
  tenantId: string,
  body: ManifestBody,
): ManifestRecord {
  const raw: unknown = body;
  if (!isObject(raw)) throw new Error("manifest body is not an object");
  if (typeof raw.created_at_iso !== "string") {
    throw new Error("manifest body is missing created_at_iso");
  }
  return {
    objectId,
    tenantId,
    wrappedKey: {
      iv: b64Field(raw, "wrapped_key", "iv_b64"),
      data: b64Field(raw, "wrapped_key", "data_b64"),
    },
    manifest: {
      iv: b64Field(raw, "manifest", "iv_b64"),
      data: b64Field(raw, "manifest", "data_b64"),
    },
    chunkCount: countField(raw, "chunk_count"),
    encryptedSizeBytes: countField(raw, "encrypted_size_bytes"),
    createdAtIso: raw.created_at_iso,
  };
}
