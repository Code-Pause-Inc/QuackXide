// The crypto worker, Web Crypto keys and IndexedDB persistence in real
// browsers (vitest `browser` project, `npm run test:browser`). Nothing is
// mocked: the module worker and the local vault run as they do in the app,
// and the worker loads the wasm envelope module to create the device's HPKE
// key (nothing here seals or opens with it). No backend is involved.

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { LocalVault } from "../vault/localVault";
import { decryptPayload, privateKeyAad } from "./core";
import { LOCAL_IDENTITY, loadDeviceKeys } from "./keystore";
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

/** Whether `needle` occurs anywhere in `haystack`. */
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
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
    // Local mode has one fixed identity; its tid is the tenant id.
    expect(init.tenantId).toBe(LOCAL_IDENTITY.tid);
    // The envelope module loads in every supported browser, so the device
    // always gets an HPKE key.
    expect(init.hpkeKeyAvailable).toBe(true);
    expect(init.hpkePublicKeyB64).not.toBeNull();
  });

  it("keeps the KEK non-extractable and the HPKE private key sealed", async () => {
    const init = await client().init();
    const keys = await loadDeviceKeys(LOCAL_IDENTITY);
    expect(keys).not.toBeNull();
    expect(keys!.kek.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", keys!.kek)).rejects.toThrow();

    // ADR 0007: IndexedDB holds the private key only encrypted, under a
    // seed key that cannot be exported, bound to the tenant and public key.
    const hpke = keys!.hpke!;
    expect(hpke.seedKey.extractable).toBe(false);
    expect([...hpke.seedKey.usages].sort()).toEqual(["decrypt", "encrypt"]);
    await expect(crypto.subtle.exportKey("raw", hpke.seedKey)).rejects.toThrow();
    const aad = await privateKeyAad(init.tenantId, hpke.publicKeyRaw);
    const raw = await decryptPayload(hpke.seedKey, aad, hpke.sealedPrivateKey);
    expect(raw.byteLength).toBe(32); // a raw X25519 private key (HPK1)
    const otherTenant = await privateKeyAad(crypto.randomUUID(), hpke.publicKeyRaw);
    await expect(decryptPayload(hpke.seedKey, otherTenant, hpke.sealedPrivateKey)).rejects.toThrow();
  });

  it("restores the same keys after a reload", async () => {
    const first = client();
    const before = await first.init();
    first.terminate();

    // A page reload recreates the worker; only IndexedDB carries the keys.
    const after = await client().init();
    expect(after.created).toBe(false);
    expect(after.tenantId).toBe(before.tenantId);
    expect(after.fingerprint).not.toBeNull();
    expect(after.fingerprint).toBe(before.fingerprint);
  });

  it("round-trips a file through the drive", async () => {
    const drive = client();
    await drive.init();
    const bytes = new Uint8Array(64 * 1024);
    crypto.getRandomValues(bytes);

    const uploaded = await drive.upload(new File([bytes], "a.bin"));
    // The vault holds ciphertext: no 1 KiB window of the plaintext appears in
    // the stored chunk, so a prefixed nonce or header would not hide it.
    const stored = await new LocalVault().getChunk(uploaded.objectId, 0);
    expect(stored).not.toBeNull();
    const data = new Uint8Array(stored!.data);
    for (const offset of [0, 32 * 1024, bytes.length - 1024]) {
      expect(contains(data, bytes.subarray(offset, offset + 1024))).toBe(false);
    }
    const listed = await drive.list();
    expect(listed.map((f) => f.objectId)).toContain(uploaded.objectId);

    const { blob } = await drive.download(uploaded.objectId);
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);
  });
});
