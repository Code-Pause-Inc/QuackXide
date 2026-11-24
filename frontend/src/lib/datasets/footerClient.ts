// UI-side access to the footer worker (`footer.worker.ts`): one worker per
// file, terminated after its answer or a timeout.

import type { FooterReading } from "./footer";

/** How long a footer read may take before the worker is stopped. A footer
 *  is at most 16 MiB, which parses in well under a second. */
export const FOOTER_TIMEOUT_MS = 30_000;

/** Reads `file`'s footer in a fresh worker. Rejects if the file cannot be
 *  read or the worker does not answer in time; a malformed file resolves
 *  with a refusal. */
export function readFooterInWorker(file: File, timeoutMs = FOOTER_TIMEOUT_MS): Promise<FooterReading> {
  const worker = new Worker(new URL("./footer.worker.ts", import.meta.url), { type: "module" });
  return new Promise<FooterReading>((resolve, reject) => {
    const done = () => {
      clearTimeout(timer);
      worker.terminate();
    };
    const timer = setTimeout(() => {
      done();
      reject(new Error("reading the file's footer took too long"));
    }, timeoutMs);
    worker.onmessage = (ev: MessageEvent) => {
      done();
      const msg = ev.data as { type?: string; reading?: FooterReading } | null;
      if (msg?.type === "result" && msg.reading) resolve(msg.reading);
      else reject(new Error("the file could not be read"));
    };
    worker.onerror = () => {
      done();
      reject(new Error("the file could not be read"));
    };
    worker.postMessage({ file });
  });
}
