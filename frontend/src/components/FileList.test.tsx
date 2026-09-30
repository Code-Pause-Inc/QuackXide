import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DriveFileSummary } from "../lib/crypto/protocol";
import FileList from "./FileList";

const files: DriveFileSummary[] = [
  {
    objectId: "obj-1",
    name: "enrollment.csv",
    mimeType: "text/csv",
    sizeBytes: 1730,
    chunkCount: 1,
    createdAtIso: "2026-07-30T10:00:00.000Z",
  },
  {
    objectId: "obj-2",
    name: "imaging.zip",
    mimeType: "application/zip",
    sizeBytes: 5 * 1024 * 1024,
    chunkCount: 2,
    createdAtIso: "2026-07-30T11:00:00.000Z",
  },
];

function renderList(busyIds: ReadonlySet<string> = new Set()) {
  const onDownload = vi.fn();
  const onDelete = vi.fn();
  render(<FileList files={files} busyIds={busyIds} onDownload={onDownload} onDelete={onDelete} />);
  const row = (name: string) => within(screen.getByText(name).closest("li")!);
  return { onDownload, onDelete, row };
}

describe("FileList", () => {
  it("shows the empty state", () => {
    render(<FileList files={[]} busyIds={new Set()} onDownload={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText(/no files yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument();
  });

  it("lists each file with its size and chunk count", () => {
    const { row } = renderList();
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(row("enrollment.csv").getByText(/1\.7 KB · 1 chunk ·/)).toBeInTheDocument();
    expect(row("imaging.zip").getByText(/5 MB · 2 chunks ·/)).toBeInTheDocument();
  });

  it("passes the object id to download and delete", async () => {
    const user = userEvent.setup();
    const { onDownload, onDelete, row } = renderList();
    await user.click(row("imaging.zip").getByRole("button", { name: "Download" }));
    await user.click(row("enrollment.csv").getByRole("button", { name: "Delete" }));
    expect(onDownload).toHaveBeenCalledExactlyOnceWith("obj-2");
    expect(onDelete).toHaveBeenCalledExactlyOnceWith("obj-1");
  });

  it("disables only the busy row", () => {
    const { row } = renderList(new Set(["obj-1"]));
    expect(row("enrollment.csv").getByRole("button", { name: "Working…" })).toBeDisabled();
    expect(row("enrollment.csv").getByRole("button", { name: "Delete" })).toBeDisabled();
    expect(row("imaging.zip").getByRole("button", { name: "Download" })).toBeEnabled();
  });
});
