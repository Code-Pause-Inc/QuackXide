import { formatBytes } from "../../lib/format";
import type { DatasetView } from "../../lib/research/client";
import { quietBtnCls } from "./styles";

/** A snapshot's write time as UTC, to the minute. */
function writtenAt(iso: string): string {
  return `${iso.slice(0, 16).replace("T", " ")} UTC`;
}

/** The steward's stored datasets, as storage holds them: ids, sizes and
 *  suites of ciphertext, never contents (`GET /api/v1/datasets`). */
export default function DatasetList({
  datasets,
  onReupload,
}: {
  datasets: DatasetView[];
  /** Opens the upload form for an uploaded dataset. */
  onReupload?: (dataset: string) => void;
}) {
  if (datasets.length === 0) {
    return (
      <p className="mt-3 text-sm text-slate-500">
        No stored datasets. Upload a Parquet file: it is sealed on this device, and only the
        ciphertext is stored.
      </p>
    );
  }
  return (
    <ul className="mt-3 divide-y divide-slate-100" aria-label="Stored datasets">
      {datasets.map((d) => (
        <li key={d.dataset} className="flex items-center gap-6 py-3">
          <div className="min-w-0 flex-1">
            <p className="truncate font-mono text-sm font-medium">{d.dataset}</p>
            <p className="mt-0.5 text-xs text-slate-500">
              {d.object_count} {d.object_count === 1 ? "object" : "objects"} ·{" "}
              {formatBytes(d.ciphertext_bytes)} ciphertext · {d.suite ?? "record unreadable"} ·{" "}
              written {writtenAt(d.written_at)}
            </p>
          </div>
          {onReupload && d.dataset.startsWith("upload_") && (
            <button
              type="button"
              onClick={() => onReupload(d.dataset)}
              aria-label={`Re-upload ${d.dataset}`}
              className={quietBtnCls}
            >
              Re-upload
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}
