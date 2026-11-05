import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { idbRequest, openDb, txDone } from "../idb";
import { generateMasterKey, generateSeedKey } from "./core";
import { loadDeviceKeys, saveDeviceKeys, type DeviceKeys } from "./keystore";

const TENANT = "6f2c8a2e-1111-4222-8333-444455556666";

describe("device key store", () => {
  it("round-trips device keys with an encrypted HPKE private key", async () => {
    const keys: DeviceKeys = {
      tenantId: TENANT,
      kek: await generateMasterKey(),
      hpke: {
        seedKey: await generateSeedKey(),
        publicKeyRaw: new Uint8Array(32).fill(3).buffer,
        sealedPrivateKey: { iv: new Uint8Array(12).buffer, data: new Uint8Array(48).buffer },
      },
      createdAtIso: "2026-11-04T00:00:00.000Z",
    };
    await saveDeviceKeys(keys);
    const loaded = await loadDeviceKeys();
    expect(loaded?.tenantId).toBe(TENANT);
    expect(loaded?.hpke?.publicKeyRaw.byteLength).toBe(32);
  });

  it("loads a record from before ADR 0007's key storage with no HPKE key", async () => {
    // The old shape held a non-extractable Web Crypto X25519 key, which can
    // never open an envelope; the worker replaces it.
    const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const legacy = {
      tenantId: TENANT,
      kek: await generateMasterKey(),
      hpkePrivateKey: pair.privateKey,
      hpkePublicKeyRaw: await crypto.subtle.exportKey("raw", pair.publicKey),
      createdAtIso: "2026-01-01T00:00:00.000Z",
    };
    const db = await openDb("drive-keys", 1, (d) => {
      if (!d.objectStoreNames.contains("keys")) d.createObjectStore("keys", { keyPath: "name" });
    });
    const tx = db.transaction("keys", "readwrite");
    const done = txDone(tx);
    await idbRequest(tx.objectStore("keys").put({ name: "device", value: legacy }));
    await done;
    db.close();

    const loaded = await loadDeviceKeys();
    expect(loaded).toEqual({
      tenantId: TENANT,
      kek: legacy.kek,
      hpke: null,
      createdAtIso: legacy.createdAtIso,
    });
  });
});
