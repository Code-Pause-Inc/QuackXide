// The crypto worker: the only context that holds key handles or plaintext
// file bytes. The UI thread talks to it through protocol.ts and can neither
// reach the key store nor observe key material.

import { resolveBrand } from "../../config/brand";
import { resolveVaultConfig } from "../../config/vault";
import { toB64 } from "../encoding";
import { errorMessage } from "../format";
import { HttpVault } from "../vault/httpVault";
import { LocalVault } from "../vault/localVault";
import type { VaultClient } from "../vault/types";
import { generateMasterKey, keyFingerprint } from "./core";
import { createDeviceHpkeKey } from "./devicekey";
import { downloadFile, listFiles, removeFile, uploadFile, type DriveContext } from "./drive";
import { loadDeviceKeys, saveDeviceKeys, type DeviceKeys } from "./keystore";
import { decodeSessionClaims, parseWorkerRequest } from "./protocol";
import type { InitResult, SessionClaims, WorkerRequest, WorkerResponse } from "./protocol";

type WorkerScope = {
  addEventListener(type: "message", cb: (ev: MessageEvent) => void): void;
  postMessage(msg: unknown): void;
  location: { origin: string };
};

const scope = globalThis as unknown as WorkerScope;

let deviceKeys: DeviceKeys | null = null;
let vaultInstance: VaultClient | null = null;

/** The session bearer token and its decoded claims, in memory only: never
 *  written to localStorage or IndexedDB. Replaced by each session message. */
let session: { token: string; claims: SessionClaims } | null = null;

function handleSession(token: string): null {
  const claims = decodeSessionClaims(token);
  if (!claims) {
    // Clear rather than keep the previous session, so a broken refresh can
    // never leave stale credentials in use.
    session = null;
    throw new Error("malformed session token");
  }
  session = { token, claims };
  return null;
}

function vaultFor(keys: DeviceKeys): VaultClient {
  const vaultConfig = resolveVaultConfig(import.meta.env);
  // Refuse before any request leaves the worker.
  if (vaultConfig.mode === "http" && !session) throw new Error("no session token");
  if (!vaultInstance) {
    const brand = resolveBrand(import.meta.env);
    vaultInstance =
      vaultConfig.mode === "http"
        ? new HttpVault({
            baseUrl: brand.apiBaseUrl,
            getToken: () => session?.token ?? null,
            tenantId: keys.tenantId,
          })
        : new LocalVault();
  }
  return vaultInstance;
}

function respond(msg: WorkerResponse): void {
  scope.postMessage(msg);
}

/** Give `keys` an HPKE key if it has none: on first setup, after the
 *  envelope module failed to load before, or for a record saved before
 *  ADR 0007's key storage. Without the module the drive still works and
 *  the next call tries again. */
async function withHpkeKey(keys: DeviceKeys): Promise<DeviceKeys> {
  if (keys.hpke) return keys;
  let hpke;
  try {
    hpke = await createDeviceHpkeKey(keys.tenantId);
  } catch (err) {
    console.warn("envelope module unavailable; no device HPKE key yet", err);
    return keys;
  }
  const upgraded: DeviceKeys = { ...keys, hpke };
  await saveDeviceKeys(upgraded);
  return upgraded;
}

let ensuring: Promise<{ keys: DeviceKeys; created: boolean }> | null = null;

/** One key setup at a time: two requests arriving together must not each
 *  generate, and save, a different key. */
function ensureKeys(): Promise<{ keys: DeviceKeys; created: boolean }> {
  ensuring ??= loadOrCreateKeys().finally(() => {
    ensuring = null;
  });
  return ensuring;
}

async function loadOrCreateKeys(): Promise<{ keys: DeviceKeys; created: boolean }> {
  if (deviceKeys?.hpke) return { keys: deviceKeys, created: false };

  const existing = deviceKeys ?? (await loadDeviceKeys());
  if (existing) {
    deviceKeys = await withHpkeKey(existing);
    return { keys: deviceKeys, created: false };
  }

  const fresh: DeviceKeys = {
    tenantId: crypto.randomUUID(),
    kek: await generateMasterKey(),
    hpke: null,
    createdAtIso: new Date().toISOString(),
  };
  await saveDeviceKeys(fresh);
  deviceKeys = await withHpkeKey(fresh);
  return { keys: deviceKeys, created: true };
}

async function handleInit(): Promise<InitResult> {
  // ensureKeys loads the envelope module to create the HPKE key, so a
  // browser that cannot run it is reported here, not first on an upload.
  const { keys, created } = await ensureKeys();
  const publicKeyRaw = keys.hpke?.publicKeyRaw ?? null;
  const hpkePublicKeyB64 = publicKeyRaw ? toB64(publicKeyRaw) : null;

  // Enroll the public key so enclave pipelines can seal connector data to
  // this tenant. Best-effort: an unreachable backend must not block the drive.
  if (hpkePublicKeyB64) {
    try {
      await vaultFor(keys).enrollTenantKey?.(hpkePublicKeyB64);
    } catch (err) {
      console.warn("tenant key enrollment failed (will retry next init)", err);
    }
  }

  return {
    created,
    tenantId: keys.tenantId,
    hpkeKeyAvailable: publicKeyRaw !== null,
    hpkePublicKeyB64,
    fingerprint: publicKeyRaw ? await keyFingerprint(publicKeyRaw) : null,
  };
}

async function context(id?: number): Promise<DriveContext> {
  const { keys } = await ensureKeys();
  return {
    keys,
    vault: vaultFor(keys),
    session: session ? { ...session.claims } : null,
    onProgress:
      id === undefined
        ? undefined
        : (done, total) => respond({ id, type: "progress", done, total }),
  };
}

async function dispatch(req: WorkerRequest): Promise<unknown> {
  switch (req.op) {
    case "session":
      return handleSession(req.token);
    case "init":
      return handleInit();
    case "upload":
      return uploadFile(await context(req.id), req.file);
    case "list":
      return listFiles(await context());
    case "download":
      return downloadFile(await context(req.id), req.objectId);
    case "remove":
      return removeFile(await context(), req.objectId);
  }
}

scope.addEventListener("message", (ev: MessageEvent) => {
  // A dedicated worker only receives messages from the page that created it,
  // which arrive with an empty origin; refuse anything else.
  if (ev.origin !== "" && ev.origin !== scope.location.origin) return;
  const req = parseWorkerRequest(ev.data);
  if (!req) return;
  void dispatch(req)
    .then((result) => respond({ id: req.id, type: "result", result }))
    .catch((err: unknown) => {
      // Crypto failures surface as generic OperationErrors, so messages carry
      // no key material or content.
      respond({ id: req.id, type: "error", message: errorMessage(err, "operation failed") });
    });
});
