// The crypto worker, Web Crypto keys and IndexedDB persistence in real
// browsers (vitest `browser` project, `npm run test:browser`). Nothing is
// mocked: the module worker and the local vault run as they do in the app,
// and the worker loads the wasm envelope module (nothing here seals with
// it). No backend is involved.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { LocalVault } from "../vault/localVault";
import { loadDeviceKeys } from "./keystore";
import { DriveWorkerClient } from "./workerClient";

const clients: DriveWorkerClient[] = [];

function client(): DriveWorkerClient {
  const c = new DriveWorkerClient();
  clients.push(c);
  return c;
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve();
    // A still-open connection only delays the delete (`blocked`); the hook
    // timeout bounds the wait.
    req.onerror = () => reject(req.error ?? new Error(`could not delete ${name}`));
  });
}

async function canGenerateX25519(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
}

beforeEach(async () => {
  // Every test starts from a browser that has never seen this app.
  await deleteDatabase("drive-keys");
  await deleteDatabase("drive-vault");
});

afterEach(() => {
  for (const c of clients.splice(0)) c.terminate();
});

describe("crypto worker in a real browser", () => {
  it("starts the module worker and creates device keys", async () => {
    const init = await client().init();
    expect(init.created).toBe(true);
    expect(init.tenantId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    // A device HPKE key exists exactly where the browser can make one.
    expect(init.hpkePublicKeyB64 !== null).toBe(await canGenerateX25519());
  });

  it("keeps the drive KEK non-extractable", async () => {
    await client().init();
    const keys = await loadDeviceKeys();
    expect(keys).not.toBeNull();
    expect(keys!.kek.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", keys!.kek)).rejects.toThrow();
    if (keys!.hpkePrivateKey instanceof CryptoKey) {
      expect(keys!.hpkePrivateKey.extractable).toBe(false);
    }
  });

  it("restores the same keys after a reload", async () => {
    const first = client();
    const before = await first.init();
    first.terminate();

    // A page reload recreates the worker; only IndexedDB carries the keys.
    const after = await client().init();
    expect(after.created).toBe(false);
    expect(after.tenantId).toBe(before.tenantId);
    expect(after.fingerprint).toBe(before.fingerprint);
  });

  it("round-trips a file through the drive", async () => {
    const drive = client();
    await drive.init();
    const bytes = new Uint8Array(64 * 1024);
    crypto.getRandomValues(bytes);

    const uploaded = await drive.upload(new File([bytes], "a.bin"));
    // The vault holds ciphertext: the stored chunk is not the plaintext.
    const stored = await new LocalVault().getChunk(uploaded.objectId, 0);
    expect(stored).not.toBeNull();
    expect(new Uint8Array(stored!.data)).not.toEqual(bytes);
    const listed = await drive.list();
    expect(listed.map((f) => f.objectId)).toContain(uploaded.objectId);

    const { blob } = await drive.download(uploaded.objectId);
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);
  });

  it("reports X25519 support truthfully", async () => {
    const init = await client().init();
    expect(init.x25519Supported).toBe(await canGenerateX25519());
  });
});
