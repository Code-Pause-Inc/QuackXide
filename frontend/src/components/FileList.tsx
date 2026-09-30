import type { DriveFileSummary } from "../lib/crypto/protocol";
import { formatBytes } from "../lib/format";

interface FileListProps {
  files: DriveFileSummary[];
  busyIds: ReadonlySet<string>;
  onDownload: (objectId: string) => void;
  onDelete: (objectId: string) => void;
}

export default function FileList({ files, busyIds, onDownload, onDelete }: FileListProps) {
  if (files.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-slate-500">
        No files yet — everything you add is end-to-end encrypted.
      </p>
    );
  }

  return (
    <ul className="divide-y divide-slate-800">
      {files.map((file) => {
        const busy = busyIds.has(file.objectId);
        return (
          <li key={file.objectId} className="flex items-center gap-4 py-3">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm text-slate-200">{file.name}</p>
              <p className="text-xs text-slate-500">
                {formatBytes(file.sizeBytes)} · {file.chunkCount}{" "}
                {file.chunkCount === 1 ? "chunk" : "chunks"} ·{" "}
                {new Date(file.createdAtIso).toLocaleString()}
              </p>
            </div>
            <button
              type="button"
              disabled={busy}
              onClick={() => onDownload(file.objectId)}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-200 hover:border-emerald-400 hover:text-emerald-300 disabled:opacity-40"
            >
              {busy ? "Working…" : "Download"}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => onDelete(file.objectId)}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 hover:border-rose-400 hover:text-rose-300 disabled:opacity-40"
            >
              Delete
            </button>
          </li>
        );
      })}
    </ul>
  );
}
