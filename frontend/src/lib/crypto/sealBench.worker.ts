// Benchmark worker for the wasm envelope seal (docs/BENCHMARKS.md, "Browser
// envelope seal"). Loaded only by seal.browser.bench.ts, never by the app:
// it is a dedicated module worker running envelope.ts as the crypto worker
// does, without the crypto worker's keys, vault or protocol. It seals
// synthetic data to a throwaway key.

import { envelopeInfo, envelopeMemoryBytes, loadEnvelopeModule, publicKeyOf, sealToTenant } from "./envelope";

export type SealBenchRequest =
  | { op: "load" }
  | { op: "seal"; url: string; iterations: number };

export interface LoadResult {
  /** Fetch, compile and instantiate the module, in milliseconds. */
  loadMs: number;
  memoryBytes: number;
}

export interface SealResult {
  plaintextBytes: number;
  envelopeBytes: number;
  /** One entry per seal, in milliseconds. */
  sealMs: number[];
  memoryAtLoad: number;
  /** Linear memory after the first seal: its peak, since memory only grows. */
  memoryAfterFirstSeal: number;
  memoryAfterAllSeals: number;
}

export type SealBenchResponse =
  | { ok: true; result: LoadResult | SealResult }
  | { ok: false; message: string };

type WorkerScope = {
  addEventListener(type: "message", cb: (ev: MessageEvent<SealBenchRequest>) => void): void;
  postMessage(msg: SealBenchResponse): void;
};

const scope = globalThis as unknown as WorkerScope;

function memoryBytes(): number {
  const bytes = envelopeMemoryBytes();
  if (bytes === null) throw new Error("envelope module not loaded");
  return bytes;
}

async function load(): Promise<LoadResult> {
  const start = performance.now();
  await loadEnvelopeModule();
  return { loadMs: performance.now() - start, memoryBytes: memoryBytes() };
}

async function seal(url: string, iterations: number): Promise<SealResult> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch ${url}: ${response.status}`);
  const plaintext = await response.arrayBuffer();

  await loadEnvelopeModule();
  // Test-only recipient: any 32 bytes are an X25519 private key.
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const recipient = await publicKeyOf(privateKey);
  const info = await envelopeInfo.stewardUpload("bench-tenant", "bench-dataset", "object-0");
  const memoryAtLoad = memoryBytes();

  const sealMs: number[] = [];
  let envelopeBytes = 0;
  let memoryAfterFirstSeal = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    const envelope = await sealToTenant(recipient, info, plaintext);
    sealMs.push(performance.now() - start);
    envelopeBytes = envelope.byteLength;
    if (i === 0) memoryAfterFirstSeal = memoryBytes();
  }
  return {
    plaintextBytes: plaintext.byteLength,
    envelopeBytes,
    sealMs,
    memoryAtLoad,
    memoryAfterFirstSeal,
    memoryAfterAllSeals: memoryBytes(),
  };
}

scope.addEventListener("message", (ev) => {
  const req = ev.data;
  const run = req.op === "load" ? load() : seal(req.url, req.iterations);
  run.then(
    (result) => scope.postMessage({ ok: true, result }),
    (err: unknown) =>
      scope.postMessage({ ok: false, message: err instanceof Error ? `${err.name}: ${err.message}` : String(err) }),
  );
});
