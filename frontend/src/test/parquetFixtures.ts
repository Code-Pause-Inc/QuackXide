// The Parquet schema vectors in fixtures/parquet/ (ADR 0014), for tests.
// Node cannot fetch files by URL and the frontend has no Node types, so the
// files are inlined by Vite as data URLs.

import { fromB64 } from "../lib/encoding";

const files = import.meta.glob<string>("../../../fixtures/parquet/*.parquet", {
  query: "?url&inline",
  import: "default",
  eager: true,
});

/** The bytes of `fixtures/parquet/{name}`, a fresh copy each call. */
export function parquetFixture(name: string): Uint8Array<ArrayBuffer> {
  const url = files[`../../../fixtures/parquet/${name}`];
  if (!url) throw new Error(`no fixture ${name}`);
  return new Uint8Array(fromB64(url.slice(url.indexOf(",") + 1)));
}
