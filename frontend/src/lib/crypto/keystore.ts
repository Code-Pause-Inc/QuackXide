// Device key persistence. Imported only by the crypto worker, so key handles
// never reach code that touches the DOM. A non-extractable CryptoKey stays
// non-extractable in IndexedDB: the browser persists an opaque handle, not
// script-readable key bytes.

import { idbRequest, openDb, txDone } from "../idb";

const DB_NAME = "drive-keys";
const DB_VERSION = 1;
const STORE = "keys";
const DEVICE_ROW = "device";

export interface DeviceKeys {
  tenantId: string;
  kek: CryptoKey;
  hpkePrivateKey: CryptoKey | null;
  hpkePublicKeyRaw: ArrayBuffer | null;
  createdAtIso: string;
}

interface KeyRow {
  name: string;
  value: unknown;
}

function open(): Promise<IDBDatabase> {
  return openDb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE)) {
      db.createObjectStore(STORE, { keyPath: "name" });
    }
  });
}

async function readRow(db: IDBDatabase, name: string): Promise<unknown> {
  const tx = db.transaction(STORE, "readonly");
  const row = (await idbRequest(tx.objectStore(STORE).get(name))) as KeyRow | undefined;
  return row?.value;
}

export async function loadDeviceKeys(): Promise<DeviceKeys | null> {
  const db = await open();
  try {
    const record = (await readRow(db, DEVICE_ROW)) as DeviceKeys | undefined;
    return record ?? null;
  } finally {
    db.close();
  }
}

export async function saveDeviceKeys(keys: DeviceKeys): Promise<void> {
  const db = await open();
  try {
    const tx = db.transaction(STORE, "readwrite");
    const done = txDone(tx);
    tx.objectStore(STORE).put({ name: DEVICE_ROW, value: keys } satisfies KeyRow);
    await done;
  } finally {
    db.close();
  }
}
