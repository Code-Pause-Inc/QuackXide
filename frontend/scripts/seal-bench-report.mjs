// Markdown report for scripts/bench-wasm-seal.sh: the module's size in the
// built bundle, and the load and seal figures seal.browser.bench.ts wrote.
//
//   node scripts/seal-bench-report.mjs <bench-data dir> <dist dir>

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const [dataDir, distDir] = process.argv.slice(2);
if (!dataDir || !distDir) {
  console.error("usage: seal-bench-report.mjs <bench-data dir> <dist dir>");
  process.exit(2);
}

const results = JSON.parse(readFileSync(join(dataDir, "results.json"), "utf8"));
const machine = readFileSync(join(dataDir, "machine.txt"), "utf8").trim();

const MiB = 1024 * 1024;
const KiB = 1024;
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
};
const ms = (x) => (x >= 100 ? x.toFixed(0) : x.toPrecision(3)) + " ms";
const size = (bytes) =>
  bytes >= MiB ? `${(bytes / MiB).toFixed(1)} MiB` : `${(bytes / KiB).toFixed(1)} KiB`;

const lines = [];
lines.push("## Browser envelope seal", "", "```", machine, results.userAgent, "```", "");

// Bundle size: the module as shipped, and the worker chunk that loads it.
const assets = join(distDir, "assets");
const files = readdirSync(assets);
const wasm = files.filter((f) => f.endsWith(".wasm"));
if (wasm.length !== 1) throw new Error(`expected one .wasm in ${assets}, found ${wasm.length}`);
lines.push("| Bundle file | Size | gzip -9 | brotli -11 |", "| --- | --- | --- | --- |");
for (const name of [...wasm, ...files.filter((f) => /^worker-.*\.js$/.test(f))]) {
  const bytes = readFileSync(join(assets, name));
  const gz = gzipSync(bytes, { level: 9 }).length;
  const br = brotliCompressSync(bytes, {
    params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
  }).length;
  lines.push(`| \`${name.replace(/-[\w-]{8}\./, "-*.")}\` | ${size(bytes.length)} | ${size(gz)} | ${size(br)} |`);
}
lines.push("");

// Load: the first worker compiles the module; later ones may reuse the
// browser's compiled-code cache.
const loads = results.loads.map((l) => l.loadMs);
lines.push(
  `Module load (fetch, compile, instantiate) in a fresh worker: first ${ms(loads[0])}, ` +
    `median of the next ${loads.length - 1} ${ms(median(loads.slice(1)))}. ` +
    `Linear memory after load: ${size(results.loads[0].memoryBytes)}.`,
  "",
);

lines.push(
  "| Payload | Rows | Seals | Median | Fastest | Throughput | Module peak | Peak / payload |",
  "| --- | --- | --- | --- | --- | --- | --- | --- |",
);
for (const s of results.seals) {
  const mid = median(s.sealMs);
  lines.push(
    `| ${size(s.plaintextBytes)} (${s.plaintextBytes} B) | ${s.rows} | ${s.sealMs.length} | ${ms(mid)} | ` +
      `${ms(Math.min(...s.sealMs))} | ${(s.plaintextBytes / MiB / (mid / 1000)).toFixed(0)} MiB/s | ` +
      `${size(s.memoryAfterFirstSeal)} | ${(s.memoryAfterFirstSeal / s.plaintextBytes).toFixed(2)} |`,
  );
}
console.log(lines.join("\n"));
