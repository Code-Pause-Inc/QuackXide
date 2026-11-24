// Reads an upload's Parquet footer in a worker of its own (ADR 0014), so the
// footer is parsed only here: its column statistics, decoded with the rest
// of it, never reach the UI thread, and the key-holding crypto worker reads
// the file only to seal it. The UI starts one per file (`footerClient.ts`),
// posts the File and terminates the worker after one answer, which discards
// everything it read. Only the declaration (column names, type families,
// row count) or a refusal code comes back.

import { readFooter } from "./footer";

type WorkerScope = {
  addEventListener(type: "message", cb: (ev: MessageEvent) => void): void;
  postMessage(msg: unknown): void;
  location: { origin: string };
};

const scope = globalThis as unknown as WorkerScope;

scope.addEventListener("message", (ev: MessageEvent) => {
  // A dedicated worker only receives messages from the page that created it.
  if (ev.origin !== "" && ev.origin !== scope.location.origin) return;
  const file = (ev.data as { file?: unknown } | null)?.file;
  if (!(file instanceof Blob)) return;
  readFooter(file).then(
    (reading) => scope.postMessage({ type: "result", reading }),
    // The file itself could not be read (for example, it changed on disk).
    () => scope.postMessage({ type: "unreadable" }),
  );
});
