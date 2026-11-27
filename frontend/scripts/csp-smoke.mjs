// Loads the release preview in Chromium and runs one wasm-backed operation in
// the crypto worker under the page's CSP. Fails on any CSP violation or
// console error, or if the operation does not complete. In http mode the
// worker refuses every op until it has a session (#175), so the smoke first
// sends a `session` with an unsigned placeholder token: the worker reads only
// its `iss`, `sub` and `tid` claims and never checks the signature. The `init`
// op then creates the device keys and instantiates the wasm envelope module
// for the HPKE key. Its key enrollment finds no API behind the preview server
// and only warns, so no backend is needed.
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
          // Wait for init's result; an error from either op fails the smoke.
          if (ev.data.type === "result" && ev.data.id !== 2) return;
          clearTimeout(timer);
          worker.terminate();
          ev.data.type === "result" ? resolve(ev.data.result) : reject(new Error(ev.data.message));
        };
        const b64url = (v) =>
          btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
        const token = `${b64url({ alg: "none" })}.${b64url({ iss: "csp-smoke", sub: "smoke", tid: "smoke" })}.x`;
        worker.postMessage({ id: 1, op: "session", token });
        worker.postMessage({ id: 2, op: "init" });
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
