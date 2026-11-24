// Loads the release preview in Chromium and runs one wasm-backed operation in
// the crypto worker under the page's CSP. Fails on any CSP violation or
// console error, or if the operation does not complete. The `init` op creates
// the device keys and instantiates the wasm envelope module for the HPKE key,
// with no server needed.
//
// Run by scripts/check-page-headers.sh --smoke:
//   node scripts/csp-smoke.mjs <base url> <worker script URL path>

import { chromium } from "playwright";

const [base, workerPath] = process.argv.slice(2);
if (!base || !workerPath) {
  console.error("usage: node scripts/csp-smoke.mjs <base url> <worker script path>");
  process.exit(2);
}

const problems = [];
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  page.on("console", (msg) => {
    if (msg.type() === "error") problems.push(`console error: ${msg.text()}`);
  });
  page.on("pageerror", (err) => problems.push(`page error: ${err.message}`));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (ev) => {
      console.error(`CSP violation: ${ev.violatedDirective} blocked ${ev.blockedURI}`);
    });
  });
  await page.goto(`${base}/`, { waitUntil: "networkidle" });

  // Same worker script the app starts; its own response header is its policy.
  const result = await page.evaluate(
    ([url]) =>
      new Promise((resolve, reject) => {
        const worker = new Worker(url, { type: "module" });
        const timer = setTimeout(() => reject(new Error("worker init timed out")), 30_000);
        worker.onerror = (ev) => {
          clearTimeout(timer);
          reject(new Error(`worker failed to load: ${ev.message || "no detail"}`));
        };
        worker.onmessage = (ev) => {
          clearTimeout(timer);
          worker.terminate();
          ev.data.type === "result" ? resolve(ev.data.result) : reject(new Error(ev.data.message));
        };
        worker.postMessage({ id: 1, op: "init" });
      }),
    [workerPath],
  );
  if (result.hpkeKeyAvailable !== true) problems.push("the wasm module did not load: no device HPKE key");
} catch (err) {
  problems.push(String(err));
} finally {
  await browser.close();
}

if (problems.length > 0) {
  console.error(`csp smoke FAILED:\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log("csp smoke ok: worker created its keys and loaded the wasm module under the page CSP");
