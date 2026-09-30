// Main-thread promise API over the crypto worker; correlates requests with
// responses so UI code never touches postMessage.

import type {
  DownloadResult,
  DriveFileSummary,
  InitResult,
  WorkerRequest,
  WorkerResponse,
} from "./protocol";

type ProgressHandler = (done: number, total: number) => void;

/** Omit distributed over a union (plain Omit collapses union members). */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  onProgress?: ProgressHandler;
}

export class DriveWorkerClient {
  private readonly worker: Worker;
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;

  constructor() {
    this.worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = (ev: MessageEvent) => this.onMessage(ev.data as WorkerResponse);
  }

  terminate(): void {
    this.worker.terminate();
    for (const entry of this.pending.values()) {
      entry.reject(new Error("crypto worker terminated"));
    }
    this.pending.clear();
  }

  private onMessage(msg: WorkerResponse): void {
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    if (msg.type === "progress") {
      entry.onProgress?.(msg.done, msg.total);
      return;
    }
    this.pending.delete(msg.id);
    if (msg.type === "result") {
      entry.resolve(msg.result);
    } else {
      entry.reject(new Error(msg.message));
    }
  }

  private call<T>(
    req: DistributiveOmit<WorkerRequest, "id">,
    onProgress?: ProgressHandler,
  ): Promise<T> {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, onProgress });
      this.worker.postMessage({ ...req, id } as WorkerRequest);
    });
  }

  init(): Promise<InitResult> {
    return this.call<InitResult>({ op: "init" });
  }

  upload(file: File, onProgress?: ProgressHandler): Promise<DriveFileSummary> {
    return this.call<DriveFileSummary>({ op: "upload", file }, onProgress);
  }

  list(): Promise<DriveFileSummary[]> {
    return this.call<DriveFileSummary[]>({ op: "list" });
  }

  download(objectId: string, onProgress?: ProgressHandler): Promise<DownloadResult> {
    return this.call<DownloadResult>({ op: "download", objectId }, onProgress);
  }

  remove(objectId: string): Promise<{ objectId: string }> {
    return this.call<{ objectId: string }>({ op: "remove", objectId });
  }
}
