import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";
import { idbRequest, openDb, txDone } from "../idb";
import { generateMasterKey, generateSeedKey } from "./core";
import {
  LEGACY_STORE,
  identityKey,
  loadDeviceKeys,
  saveDeviceKeys,
  type DeviceKeys,
  type KeyIdentity,
} from "./keystore";

const alice: KeyIdentity = { iss: "https://issuer.example", sub: "alice", tid: "tenant-a" };
const bob: KeyIdentity = { iss: "https://issuer.example", sub: "bob", tid: "tenant-b" };

function keysFor(identity: KeyIdentity): DeviceKeys {
  return {
    identity,
    tenantId: identity.tid,
    // Stand-in handle: the store keeps whatever structured clone it is given.
    kek: { stand_in: identity.sub } as unknown as CryptoKey,
    hpke: null,
    createdAtIso: "2026-11-21T00:00:00.000Z",
  };
}

/** Write a row straight into the identity store, bypassing saveDeviceKeys. */
async function writeRaw(name: string, value: unknown): Promise<void> {
  const db = await openDb("drive-keys", 2, (fresh) => {
    fresh.createObjectStore("identity-keys", { keyPath: "name" });
  });
  try {
    const tx = db.transaction("identity-keys", "readwrite");
    const done = txDone(tx);
    tx.objectStore("identity-keys").put({ name, value });
    await done;
  } finally {
    db.close();
  }
}

beforeEach(() => {
  globalThis.indexedDB = new IDBFactory();
});

describe("keystore", () => {
  it("round-trips device keys with an encrypted HPKE private key", async () => {
    const keys: DeviceKeys = {
      identity: alice,
      tenantId: alice.tid,
      kek: await generateMasterKey(),
      hpke: {
        seedKey: await generateSeedKey(),
        publicKeyRaw: new Uint8Array(32).fill(3).buffer,
        sealedPrivateKey: { iv: new Uint8Array(12).buffer, data: new Uint8Array(48).buffer },
      },
      createdAtIso: "2026-11-04T00:00:00.000Z",
    };
    await saveDeviceKeys(keys);
    const loaded = await loadDeviceKeys(alice);
    expect(loaded?.tenantId).toBe(alice.tid);
    expect(loaded?.hpke?.publicKeyRaw.byteLength).toBe(32);
  });

  it("stores keys per verified identity", async () => {
    await saveDeviceKeys(keysFor(alice));
    expect(await loadDeviceKeys(alice)).toEqual(keysFor(alice));
    // Another account on the same browser has no keys, and never sees Alice's.
    expect(await loadDeviceKeys(bob)).toBeNull();
    expect(await loadDeviceKeys({ ...alice, iss: "https://other.example" })).toBeNull();
  });

  it("uses the session's tid as the tenant id", async () => {
    await expect(saveDeviceKeys({ ...keysFor(alice), tenantId: crypto.randomUUID() })).rejects.toThrow(
      /tid/,
    );
  });

  it("refuses a stored row that does not match the session", async () => {
    // A row under Alice's name that belongs to another identity.
    await writeRaw(identityKey(alice), keysFor(bob));
    await expect(loadDeviceKeys(alice)).rejects.toThrow(/do not match/);

    // A row whose tenant id is not the session's tid (e.g. a local UUID).
    await writeRaw(identityKey(alice), { ...keysFor(alice), tenantId: "random-uuid" });
    await expect(loadDeviceKeys(alice)).rejects.toThrow(/do not match/);

    // A row with no identity at all.
    await writeRaw(identityKey(alice), { ...keysFor(alice), identity: undefined });
    await expect(loadDeviceKeys(alice)).rejects.toThrow(/do not match/);
  });

  it("upgrades a version 1 database without using its device row", async () => {
    // Version 1: one `device` row with a random local tenant id.
    const v1 = await openDb("drive-keys", 1, (db) => {
      db.createObjectStore(LEGACY_STORE, { keyPath: "name" });
    });
    const legacy = { ...keysFor(alice), tenantId: crypto.randomUUID() };
    const tx = v1.transaction(LEGACY_STORE, "readwrite");
    const done = txDone(tx);
    tx.objectStore(LEGACY_STORE).put({ name: "device", value: legacy });
    await done;
    v1.close();

    // After the upgrade the signed-in identity has no keys: the legacy row
    // is unsupported pre-v1 data and is never used for it.
    expect(await loadDeviceKeys(alice)).toBeNull();
    await saveDeviceKeys(keysFor(alice));
    expect(await loadDeviceKeys(alice)).toEqual(keysFor(alice));

    // The upgrade left the legacy row in place rather than deleting it.
    const v2 = await openDb("drive-keys", 2, () => undefined);
    try {
      expect(v2.version).toBe(2);
      const read = v2.transaction(LEGACY_STORE, "readonly");
      const row = (await idbRequest(read.objectStore(LEGACY_STORE).get("device"))) as
        | { value: DeviceKeys }
        | undefined;
      expect(row?.value.tenantId).toBe(legacy.tenantId);
    } finally {
      v2.close();
    }
  });
});
