// Device key persistence. Imported only by the crypto worker, so key handles
// never reach code that touches the DOM. A non-extractable CryptoKey stays
// non-extractable in IndexedDB: the browser persists an opaque handle, not
// script-readable key bytes. The HPKE private key is stored only encrypted
// under the seed key (devicekey.ts).
//
// Keys are stored per verified identity (issuer, subject, tenant id), so a
// different account signed in on the same browser never reuses another
// account's keys, and the tenant id bound into every AAD is the session's
// `tid`, never a locally generated id.
//
// Version 1 kept one `device` row whose tenant id was a random UUID. Its
// data is unsupported pre-v1 data: the upgrade leaves the old store in
// place, untouched, and nothing reads it.

import { idbRequest, openDb, txDone } from "../idb";
import type { DeviceHpkeKey } from "./devicekey";

const DB_NAME = "drive-keys";
const DB_VERSION = 2;
/** Version 1's store, holding the legacy `device` row. Never read. */
export const LEGACY_STORE = "keys";
const STORE = "identity-keys";

/** The verified identity keys belong to: the session's `iss`, `sub`, `tid`. */
export interface KeyIdentity {
  iss: string;
  sub: string;
  tid: string;
}

/** The one identity of local mode (development without a server), which has
 *  no session to take an identity from. */
export const LOCAL_IDENTITY: KeyIdentity = { iss: "local", sub: "local", tid: "local" };

export interface DeviceKeys {
  identity: KeyIdentity;
  /** Always `identity.tid`; kept as a field because the AADs use it. */
  tenantId: string;
  kek: CryptoKey;
  /** Null until the envelope module has loaded once on this device. */
  hpke: DeviceHpkeKey | null;
  createdAtIso: string;
}

/** Records saved before ADR 0007's key storage held a non-extractable Web
 *  Crypto X25519 key, which can never open an envelope. They load with no
 *  HPKE key, so the worker generates one in the new form. */
function normalize(record: Record<string, unknown>): DeviceKeys {
  const { identity, tenantId, kek, hpke, createdAtIso } = record as Partial<DeviceKeys>;
  return {
    identity: identity!,
    tenantId: tenantId!,
    kek: kek!,
    hpke: hpke ?? null,
    createdAtIso: createdAtIso!,
  };
}

interface KeyRow {
  name: string;
  value: unknown;
}

/** The row name for an identity. JSON keeps the three parts unambiguous. */
export function identityKey(identity: KeyIdentity): string {
  return JSON.stringify([identity.iss, identity.sub, identity.tid]);
}

export function sameIdentity(a: KeyIdentity, b: KeyIdentity): boolean {
  return a.iss === b.iss && a.sub === b.sub && a.tid === b.tid;
}

function open(): Promise<IDBDatabase> {
  return openDb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE)) {
      db.createObjectStore(STORE, { keyPath: "name" });
    }
  });
}

/**
 * The keys stored for `identity`, or null when there are none. A stored row
 * that does not belong to `identity` (another identity, or a tenant id that
 * is not the session's `tid`) is refused, never used.
 */
export async function loadDeviceKeys(identity: KeyIdentity): Promise<DeviceKeys | null> {
  const db = await open();
  try {
    const tx = db.transaction(STORE, "readonly");
    const row = (await idbRequest(tx.objectStore(STORE).get(identityKey(identity)))) as
      | KeyRow
      | undefined;
    const record = row?.value as Record<string, unknown> | undefined;
    if (!record) return null;
    const keys = normalize(record);
    if (!keys.identity || !sameIdentity(keys.identity, identity) || keys.tenantId !== identity.tid) {
      throw new Error("stored keys do not match the signed-in identity");
    }
    return keys;
  } finally {
    db.close();
  }
}

export async function saveDeviceKeys(keys: DeviceKeys): Promise<void> {
  if (keys.tenantId !== keys.identity.tid) {
    throw new Error("tenant id must be the session's tid");
  }
  const db = await open();
  try {
    const tx = db.transaction(STORE, "readwrite");
    const done = txDone(tx);
    tx.objectStore(STORE).put({ name: identityKey(keys.identity), value: keys } satisfies KeyRow);
    await done;
  } finally {
    db.close();
  }
}
