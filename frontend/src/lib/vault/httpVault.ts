// Drive API vault. The server derives the tenant from the JWT; this client
// never asserts it.

import type { ChunkRecord, ManifestRecord } from "../crypto/types";
import type { VaultClient } from "./types";
import {
  bodyToManifestRecord,
  decodeChunkBody,
  encodeChunkBody,
  manifestRecordToBody,
  type ManifestBody,
} from "./wire";

export interface HttpVaultConfig {
  baseUrl: string;
  /** Without a token, requests go out unauthenticated and are rejected. */
  token: string | null;
  /** Local tenant id, used to rebuild records for client-side AAD checks. */
  tenantId: string;
}

interface ListEntry extends ManifestBody {
  object_id: string;
}

/** Object ids come from the server on list, so encode them as path segments. */
function objectPath(objectId: string): string {
  return `/objects/${encodeURIComponent(objectId)}`;
}

export class HttpVault implements VaultClient {
  constructor(private readonly config: HttpVaultConfig) {}

  private url(path: string): string {
    return `${this.config.baseUrl.replace(/\/$/, "")}/api/v1/drive${path}`;
  }

  private headers(contentType?: string): HeadersInit {
    const headers: Record<string, string> = {};
    if (this.config.token) headers.Authorization = `Bearer ${this.config.token}`;
    if (contentType) headers["Content-Type"] = contentType;
    return headers;
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const response = await fetch(this.url(path), init);
    if (response.status === 401) {
      throw new Error("vault rejected credentials — mint a fresh dev token (see README)");
    }
    return response;
  }

  async putManifest(record: ManifestRecord): Promise<void> {
    const response = await this.request(`${objectPath(record.objectId)}/manifest`, {
      method: "PUT",
      headers: this.headers("application/json"),
      body: JSON.stringify(manifestRecordToBody(record)),
    });
    if (!response.ok) throw new Error(`manifest upload failed (${response.status})`);
  }

  async getManifest(objectId: string): Promise<ManifestRecord | null> {
    const response = await this.request(`${objectPath(objectId)}/manifest`, {
      method: "GET",
      headers: this.headers(),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`manifest fetch failed (${response.status})`);
    const body = (await response.json()) as ManifestBody;
    return bodyToManifestRecord(objectId, this.config.tenantId, body);
  }

  async listManifests(): Promise<ManifestRecord[]> {
    const response = await this.request("/objects", {
      method: "GET",
      headers: this.headers(),
    });
    if (!response.ok) throw new Error(`list failed (${response.status})`);
    const entries = (await response.json()) as ListEntry[];
    return entries.map((entry) =>
      bodyToManifestRecord(entry.object_id, this.config.tenantId, entry),
    );
  }

  async putChunk(record: ChunkRecord): Promise<void> {
    const response = await this.request(
      `${objectPath(record.objectId)}/chunks/${record.chunkIndex}`,
      {
        method: "PUT",
        headers: this.headers("application/octet-stream"),
        body: encodeChunkBody(record),
      },
    );
    if (!response.ok) throw new Error(`chunk upload failed (${response.status})`);
  }

  async getChunk(objectId: string, chunkIndex: number): Promise<ChunkRecord | null> {
    const response = await this.request(`${objectPath(objectId)}/chunks/${chunkIndex}`, {
      method: "GET",
      headers: this.headers(),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`chunk fetch failed (${response.status})`);
    return decodeChunkBody(objectId, chunkIndex, await response.arrayBuffer());
  }

  async deleteObject(objectId: string): Promise<void> {
    const response = await this.request(objectPath(objectId), {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`delete failed (${response.status})`);
    }
  }

  async enrollTenantKey(publicKeyB64: string): Promise<void> {
    const response = await this.request("/enrollment", {
      method: "PUT",
      headers: this.headers("application/json"),
      body: JSON.stringify({ hpke_public_key_b64: publicKeyB64 }),
    });
    if (!response.ok) throw new Error(`enrollment failed (${response.status})`);
  }
}
