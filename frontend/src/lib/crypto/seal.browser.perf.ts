// Wasm envelope seal in a real browser: module load time, seal time and
// the module's peak memory, on synthetic Parquet from synth-data
// (docs/BENCHMARKS.md, "Browser envelope seal"). Run through
// scripts/bench-wasm-seal.sh, which generates the data into bench-data/ and
// writes bench-data/manifest.json; `npm test` and `npm run test:browser`
// never run this file.

import { commands } from "vitest/browser";
import { afterAll, describe, expect, it } from "vitest";

import type { LoadResult, SealBenchRequest, SealBenchResponse, SealResult } from "./sealBench.worker";

interface ManifestFile {
  label: string;
  /** Served by the test server from frontend/bench-data/. */
  url: string;
  schema: string;
  seed: number;
  rows: number;
  iterations: number;
}

interface Manifest {
  loads: number;
  files: ManifestFile[];
}

const MANIFEST_URL = "/bench-data/manifest.json";
// Relative to the project root (frontend/).
const RESULTS_PATH = "bench-data/results.json";

const results: {
  userAgent: string;
  loads: LoadResult[];
  seals: (ManifestFile & SealResult)[];
} = { userAgent: navigator.userAgent, loads: [], seals: [] };

/** Run one request in a fresh worker, so each measurement starts from a
 *  new module instance with its own linear memory. */
function inFreshWorker<T>(req: SealBenchRequest): Promise<T> {
  const worker = new Worker(new URL("./sealBench.worker.ts", import.meta.url), { type: "module" });
  return new Promise<T>((resolve, reject) => {
    worker.onmessage = (ev: MessageEvent<SealBenchResponse>) => {
      if (ev.data.ok) resolve(ev.data.result as T);
      else reject(new Error(ev.data.message));
    };
    worker.onerror = (ev) => reject(new Error(ev.message || "worker error"));
    worker.postMessage(req);
  }).finally(() => worker.terminate());
}

async function manifest(): Promise<Manifest> {
  const response = await fetch(MANIFEST_URL);
  if (!response.ok) throw new Error(`no ${MANIFEST_URL}: run scripts/bench-wasm-seal.sh`);
  return (await response.json()) as Manifest;
}

const { loads, files } = await manifest();

afterAll(async () => {
  await commands.writeFile(RESULTS_PATH, JSON.stringify(results, null, 2));
});

describe("wasm envelope seal in the browser", () => {
  it("loads the module in a fresh worker", async () => {
    for (let i = 0; i < loads; i++) {
      results.loads.push(await inFreshWorker<LoadResult>({ op: "load" }));
    }
    expect(results.loads).toHaveLength(loads);
  });

  for (const file of files) {
    it(
      `seals ${file.label}`,
      async () => {
        const result = await inFreshWorker<SealResult>({
          op: "seal",
          url: file.url,
          iterations: file.iterations,
        });
        // HPK1: 4-byte magic, 32-byte encapsulated key, 16-byte tag.
        expect(result.envelopeBytes).toBe(result.plaintextBytes + 52);
        expect(result.sealMs).toHaveLength(file.iterations);
        results.seals.push({ ...file, ...result });
      },
      30 * 60 * 1000,
    );
  }
});
