import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DriveFileSummary, InitResult } from "../lib/crypto/protocol";
import DrivePanel from "./DrivePanel";

const worker = vi.hoisted(() => ({
  init: vi.fn(),
  list: vi.fn(),
  upload: vi.fn(),
  download: vi.fn(),
  remove: vi.fn(),
  terminate: vi.fn(),
}));

vi.mock("../lib/crypto/workerClient", () => ({
  DriveWorkerClient: class {
    init = worker.init;
    list = worker.list;
    upload = worker.upload;
    download = worker.download;
    remove = worker.remove;
    terminate = worker.terminate;
  },
}));

const ready: InitResult = {
  created: false,
  tenantId: "6f2c8a2e-1111-4222-8333-444455556666",
  x25519Supported: true,
  hpkePublicKeyB64: "AAAA",
  fingerprint: "ab12-cd34-ef56-7890",
};

const file: DriveFileSummary = {
  objectId: "obj-1",
  name: "enrollment.csv",
  mimeType: "text/csv",
  sizeBytes: 2048,
  chunkCount: 1,
  createdAtIso: "2026-07-30T10:00:00.000Z",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("DrivePanel", () => {
  beforeEach(() => {
    worker.init.mockResolvedValue(ready);
    worker.list.mockResolvedValue([]);
  });

  it("shows a loading state until the keys are ready", async () => {
    const init = deferred<InitResult>();
    worker.init.mockReturnValue(init.promise);
    render(<DrivePanel />);

    expect(screen.getByText(/preparing your keys/i)).toBeInTheDocument();
    init.resolve(ready);
    expect(await screen.findByText(/no files yet/i)).toBeInTheDocument();
    expect(screen.getByText(ready.fingerprint!)).toBeInTheDocument();
  });

  it("reports an initialization failure with the worker's message", async () => {
    worker.init.mockRejectedValue(new Error("X25519 unavailable"));
    render(<DrivePanel />);
    expect(
      await screen.findByText(/could not initialize device keys: X25519 unavailable/i),
    ).toBeInTheDocument();
    expect(worker.list).not.toHaveBeenCalled();
  });

  it("gates freshly generated keys behind the acknowledgement, once", async () => {
    const user = userEvent.setup();
    worker.init.mockResolvedValue({ ...ready, created: true });
    const { unmount } = render(<DrivePanel />);

    await user.click(await screen.findByRole("checkbox"));
    await user.click(screen.getByRole("button", { name: /open my encrypted drive/i }));
    expect(await screen.findByText(/no files yet/i)).toBeInTheDocument();

    unmount();
    render(<DrivePanel />);
    expect(await screen.findByText(/no files yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("uploads dropped files with progress and refreshes the list", async () => {
    const user = userEvent.setup();
    const upload = deferred<DriveFileSummary>();
    worker.upload.mockImplementation((_file: File, onProgress: (d: number, t: number) => void) => {
      onProgress(1, 3);
      return upload.promise;
    });
    const { container } = render(<DrivePanel />);
    await screen.findByText(/no files yet/i);

    const picked = new File(["a,b\n1,2\n"], "enrollment.csv", { type: "text/csv" });
    await user.upload(container.querySelector<HTMLInputElement>("input[type=file]")!, picked);

    expect(worker.upload).toHaveBeenCalledWith(picked, expect.any(Function));
    expect(await screen.findByText("encrypting 1/3")).toBeInTheDocument();

    worker.list.mockResolvedValue([file]);
    upload.resolve(file);
    await waitFor(() => expect(screen.queryByText(/encrypting/)).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Download" })).toBeInTheDocument();
    expect(screen.getByText("enrollment.csv")).toBeInTheDocument();
  });

  it("surfaces download and delete failures", async () => {
    const user = userEvent.setup();
    worker.list.mockResolvedValue([file]);
    worker.download.mockRejectedValue(
      new Error("chunk count does not match the authenticated manifest"),
    );
    worker.remove.mockRejectedValue("not an error");
    render(<DrivePanel />);
    const row = within((await screen.findByText("enrollment.csv")).closest("li")!);

    await user.click(row.getByRole("button", { name: "Download" }));
    expect(await screen.findByText(/chunk count does not match/)).toBeInTheDocument();
    expect(worker.download).toHaveBeenCalledWith("obj-1");

    await user.click(row.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("delete failed")).toBeInTheDocument();
    expect(screen.queryByText(/chunk count does not match/)).not.toBeInTheDocument();
  });

  it("deletes a file and refreshes the list", async () => {
    const user = userEvent.setup();
    worker.list.mockResolvedValueOnce([file]).mockResolvedValue([]);
    worker.remove.mockResolvedValue({ objectId: "obj-1" });
    render(<DrivePanel />);

    await user.click(await screen.findByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByText("enrollment.csv")).not.toBeInTheDocument());
    expect(worker.remove).toHaveBeenCalledWith("obj-1");
    expect(screen.getByText(/no files yet/i)).toBeInTheDocument();
  });

  it("terminates the worker on unmount", async () => {
    const { unmount } = render(<DrivePanel />);
    await screen.findByText(/no files yet/i);
    unmount();
    expect(worker.terminate).toHaveBeenCalled();
  });
});
