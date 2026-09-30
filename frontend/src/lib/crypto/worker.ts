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
import { generateHpkeKeypair, generateMasterKey, isX25519Supported, keyFingerprint } from "./core";
import { downloadFile, listFiles, removeFile, uploadFile, type DriveContext } from "./drive";
import { loadDeviceKeys, saveDeviceKeys, type DeviceKeys } from "./keystore";
import type { InitResult, WorkerRequest, WorkerResponse } from "./protocol";

type WorkerScope = {
  addEventListener(type: "message", cb: (ev: MessageEvent) => void): void;
  postMessage(msg: unknown): void;
};

const scope = globalThis as unknown as WorkerScope;

let deviceKeys: DeviceKeys | null = null;
let vaultInstance: VaultClient | null = null;

function vaultFor(keys: DeviceKeys): VaultClient {
  if (!vaultInstance) {
    const vaultConfig = resolveVaultConfig(import.meta.env);
    const brand = resolveBrand(import.meta.env);
    vaultInstance =
      vaultConfig.mode === "http"
        ? new HttpVault({
            baseUrl: brand.apiBaseUrl,
            token: vaultConfig.devJwt,
            tenantId: keys.tenantId,
          })
        : new LocalVault();
  }
  return vaultInstance;
}

function respond(msg: WorkerResponse): void {
  scope.postMessage(msg);
}

async function ensureKeys(): Promise<{ keys: DeviceKeys; created: boolean }> {
  if (deviceKeys) return { keys: deviceKeys, created: false };

  const existing = await loadDeviceKeys();
  if (existing) {
    deviceKeys = existing;
    return { keys: existing, created: false };
  }

  const kek = await generateMasterKey();
  const supported = await isX25519Supported();
  const hpke = supported ? await generateHpkeKeypair() : null;
  const fresh: DeviceKeys = {
    tenantId: crypto.randomUUID(),
    kek,
    hpkePrivateKey: hpke?.privateKey ?? null,
    hpkePublicKeyRaw: hpke?.publicKeyRaw ?? null,
    createdAtIso: new Date().toISOString(),
  };
  await saveDeviceKeys(fresh);
  deviceKeys = fresh;
  return { keys: fresh, created: true };
}

async function handleInit(): Promise<InitResult> {
  const { keys, created } = await ensureKeys();
  const x25519Supported = keys.hpkePublicKeyRaw !== null || (await isX25519Supported());
  const hpkePublicKeyB64 = keys.hpkePublicKeyRaw ? toB64(keys.hpkePublicKeyRaw) : null;

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
    x25519Supported,
    hpkePublicKeyB64,
    fingerprint: keys.hpkePublicKeyRaw ? await keyFingerprint(keys.hpkePublicKeyRaw) : null,
  };
}

async function context(id?: number): Promise<DriveContext> {
  const { keys } = await ensureKeys();
  return {
    keys,
    vault: vaultFor(keys),
    onProgress:
      id === undefined
        ? undefined
        : (done, total) => respond({ id, type: "progress", done, total }),
  };
}

async function dispatch(req: WorkerRequest): Promise<unknown> {
  switch (req.op) {
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
  const req = ev.data as WorkerRequest;
  void dispatch(req)
    .then((result) => respond({ id: req.id, type: "result", result }))
    .catch((err: unknown) => {
      // Crypto failures surface as generic OperationErrors, so messages carry
      // no key material or content.
      respond({ id: req.id, type: "error", message: errorMessage(err, "operation failed") });
    });
});
