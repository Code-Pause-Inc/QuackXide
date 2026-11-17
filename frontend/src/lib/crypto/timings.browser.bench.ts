// Browser timings for #185, report only (`npm run bench:browser`): chunk
// encryption with `encryptPayload` and the wasm envelope module's cold
// start, as Vitest benches in real browsers. Nothing here asserts a speed.
// Browsers coarsen `performance.now()` (0.1 ms in Chromium, up to 1 ms in
// Firefox and WebKit), so each sample is a batch of calls lasting at least
// MIN_SAMPLE_MS, reported as its per-call mean. Percentiles are therefore
// over batch means, not over single calls.

import { test } from "vitest";

import vectors from "../../../../fixtures/envelope/hpk1.json";
import { fromB64 } from "../encoding";
import { CHUNK_SIZE_BYTES, chunkAad, encryptPayload, generateFileKey } from "./core";
import { sealToTenant } from "./envelope";

const MIN_SAMPLE_MS = 50;

/** One tinybench sample: `fn` repeated until MIN_SAMPLE_MS has passed, timed per call. */
function batch(fn: () => Promise<unknown>) {
  return async () => {
    const start = performance.now();
    let calls = 0;
    do {
      await fn();
      calls += 1;
    } while (performance.now() - start < MIN_SAMPLE_MS);
    const total = performance.now() - start;
    // overriddenIterationCost keeps tinybench's time budget at the batch's real length.
    return { overriddenDuration: total / calls, overriddenIterationCost: total };
  };
}

// Must stay first: the wasm module is loaded once per page.
test("wasm cold start", async ({ bench }) => {
  const recipient = fromB64(vectors.recipients[0]!.public_b64);
  const info = new Uint8Array([105]); // any info: the seal only has to run
  const plaintext = new Uint8Array(4 * 1024).buffer;
  // Wasm functions compile on their first call in V8, so a load alone misses that cost.
  const cold = bench("wasm cold start (load + first seal)", async () => {
    const start = performance.now();
    await sealToTenant(recipient, info, plaintext);
    return { overriddenDuration: performance.now() - start };
  });
  await cold.run({ iterations: 1, time: 0, warmup: false });
});

test("encryptPayload", async ({ bench }) => {
  const key = await generateFileKey();
  const aad = chunkAad("timing-tenant", "timing-object", 0);
  for (const [label, size] of [
    ["4KiB", 4 * 1024],
    ["4MiB", CHUNK_SIZE_BYTES],
  ] as const) {
    const plaintext = new Uint8Array(size);
    // getRandomValues fills at most 64 KiB; AES-GCM's speed does not depend on the data.
    crypto.getRandomValues(plaintext.subarray(0, Math.min(size, 65536)));
    await bench(`encryptPayload ${label}`, batch(() => encryptPayload(key, aad, plaintext.buffer))).run();
  }
});
