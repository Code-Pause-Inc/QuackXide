// Browser timings for #185, report only (`npm run bench:browser`): chunk
// encryption with `encryptPayload` and loading the wasm envelope module, in
// real browsers. Vitest cannot run `bench` in browser mode, so each timing is
// the median and p95 of repeated `performance.now()` samples; nothing here
// asserts a speed. Browsers coarsen `performance.now()` (0.1 ms in Chromium,
// up to 1 ms in Firefox), so each sample times a batch and divides.
// Recorded numbers: docs/TESTING.md, "Browser timings".

import { describe, expect, it } from "vitest";
import { server } from "vitest/browser";

import { CHUNK_SIZE_BYTES, chunkAad, encryptPayload, generateFileKey } from "./core";
import { loadEnvelopeModule } from "./envelope";

interface Timing {
  medianMs: number;
  p95Ms: number;
  samples: number;
  batch: number;
}

/** Per-operation time: `samples` samples, each `batch` calls of `fn`. */
async function time(samples: number, batch: number, fn: () => Promise<unknown>): Promise<Timing> {
  for (let i = 0; i < 3; i += 1) await fn(); // warm-up
  const perOp: number[] = [];
  for (let s = 0; s < samples; s += 1) {
    const start = performance.now();
    for (let i = 0; i < batch; i += 1) await fn();
    perOp.push((performance.now() - start) / batch);
  }
  perOp.sort((a, b) => a - b);
  const at = (q: number) => perOp[Math.min(perOp.length - 1, Math.floor(q * perOp.length))]!;
  return { medianMs: at(0.5), p95Ms: at(0.95), samples, batch };
}

function report(name: string, t: Timing): void {
  // One line per timing, picked out of the run log by the browser workflow.
  console.log(
    `TIMING ${server.browser} ${name}: median ${t.medianMs.toFixed(3)} ms, p95 ${t.p95Ms.toFixed(3)} ms (${t.samples} × ${t.batch})`,
  );
  expect(Number.isFinite(t.medianMs) && t.medianMs >= 0).toBe(true);
}

describe("browser timings", () => {
  it("encryptPayload", async () => {
    const key = await generateFileKey();
    const aad = chunkAad("timing-tenant", "timing-object", 0);
    for (const [label, size, batch] of [
      ["4KiB", 4 * 1024, 200],
      ["4MiB", CHUNK_SIZE_BYTES, 5],
    ] as const) {
      const plaintext = new Uint8Array(size);
      crypto.getRandomValues(plaintext.subarray(0, Math.min(size, 65536)));
      report(`encryptPayload/${label}`, await time(20, batch, () => encryptPayload(key, aad, plaintext.buffer)));
    }
  });

  it("wasm envelope module", async () => {
    // Only the first load is cold: wasm-bindgen keeps its instance, and
    // browsers cache compiled modules, so this is one sample per run.
    const start = performance.now();
    await loadEnvelopeModule();
    const once = performance.now() - start;
    report("wasm/first-load", { medianMs: once, p95Ms: once, samples: 1, batch: 1 });
  });
});
