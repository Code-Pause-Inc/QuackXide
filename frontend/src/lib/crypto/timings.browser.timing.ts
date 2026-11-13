// Browser timings for #185, report only (`npm run bench:browser`): chunk
// encryption with `encryptPayload` and loading the wasm envelope module, in
// real browsers. Vitest cannot run `bench` in browser mode, so each timing is
// the median and p95 of repeated `performance.now()` samples; nothing here
// asserts a speed. Browsers coarsen `performance.now()` (0.1 ms in Chromium,
// up to 1 ms in Firefox and WebKit), so each sample times a batch of calls
// sized to last at least 50 ms, and divides.
// Recorded numbers: docs/TESTING.md, "Browser timings".

import { describe, expect, it } from "vitest";
import { server } from "vitest/browser";

import { CHUNK_SIZE_BYTES, chunkAad, encryptPayload, generateFileKey } from "./core";
import { loadEnvelopeModule } from "./envelope";

interface Timing {
  medianUs: number;
  p95Us: number;
  samples: number;
  batch: number;
}

const SAMPLES = 20;
const MIN_SAMPLE_MS = 50;

/** Nearest-rank value at quantile `q` of ascending `sorted`. */
function quantile(sorted: number[], q: number): number {
  return sorted[Math.max(0, Math.ceil(q * sorted.length) - 1)]!;
}

/** Per-operation time over SAMPLES samples, each a batch lasting MIN_SAMPLE_MS or more. */
async function time(fn: () => Promise<unknown>): Promise<Timing> {
  for (let i = 0; i < 3; i += 1) await fn(); // warm-up
  let batch = 0;
  const calibrate = performance.now();
  while (performance.now() - calibrate < MIN_SAMPLE_MS) {
    await fn();
    batch += 1;
  }
  const perOpUs: number[] = [];
  for (let s = 0; s < SAMPLES; s += 1) {
    const start = performance.now();
    for (let i = 0; i < batch; i += 1) await fn();
    perOpUs.push(((performance.now() - start) * 1000) / batch);
  }
  perOpUs.sort((a, b) => a - b);
  return { medianUs: quantile(perOpUs, 0.5), p95Us: quantile(perOpUs, 0.95), samples: SAMPLES, batch };
}

/** Three significant figures, in µs below 1 ms and in ms above. */
function format(us: number): string {
  return us < 1000 ? `${us.toPrecision(3)} µs` : `${(us / 1000).toPrecision(3)} ms`;
}

// One line per timing, picked out of the run log by the browser workflow.
function report(name: string, t: Timing): void {
  console.log(
    `TIMING ${server.browser} ${name}: median ${format(t.medianUs)}, p95 ${format(t.p95Us)} (${t.samples} samples × ${t.batch})`,
  );
  expect(Number.isFinite(t.medianUs) && t.medianUs > 0).toBe(true);
}

describe("browser timings", () => {
  it("uses nearest-rank quantiles", () => {
    const sorted = Array.from({ length: 20 }, (_, i) => i + 1);
    expect(quantile(sorted, 0.5)).toBe(10);
    expect(quantile(sorted, 0.95)).toBe(19);
  });

  it("encryptPayload", async () => {
    const key = await generateFileKey();
    const aad = chunkAad("timing-tenant", "timing-object", 0);
    for (const [label, size] of [
      ["4KiB", 4 * 1024],
      ["4MiB", CHUNK_SIZE_BYTES],
    ] as const) {
      const plaintext = new Uint8Array(size);
      // getRandomValues fills at most 64 KiB; AES-GCM's speed does not depend on the data.
      crypto.getRandomValues(plaintext.subarray(0, Math.min(size, 65536)));
      report(`encryptPayload/${label}`, await time(() => encryptPayload(key, aad, plaintext.buffer)));
    }
  });

  it("wasm envelope module", async () => {
    // Only the first load is cold: wasm-bindgen keeps its instance, and
    // browsers cache compiled modules, so this is one sample per run.
    const start = performance.now();
    await loadEnvelopeModule();
    const onceUs = (performance.now() - start) * 1000;
    console.log(`TIMING ${server.browser} wasm/first-load: ${format(onceUs)} (1 sample)`);
    expect(onceUs).toBeGreaterThan(0);
  });
});
