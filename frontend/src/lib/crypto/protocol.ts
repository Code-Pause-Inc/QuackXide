// UI thread <-> crypto worker protocol. The worker owns keys and ciphertext;
// the UI sees only opaque ids, requested summaries, and download Blobs.

export interface InitResult {
  /** True when device keys were generated for the first time in this call. */
  created: boolean;
  tenantId: string;
  x25519Supported: boolean;
  /** Raw X25519 public key (base64); null without X25519 support. */
  hpkePublicKeyB64: string | null;
  /** Fingerprint of the device public key; null without X25519 support. */
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
  | { id: number; op: "remove"; objectId: string };

export interface DownloadResult {
  summary: DriveFileSummary;
  blob: Blob;
}

export type WorkerResponse =
  | { id: number; type: "result"; result: unknown }
  | { id: number; type: "error"; message: string }
  | { id: number; type: "progress"; done: number; total: number };
