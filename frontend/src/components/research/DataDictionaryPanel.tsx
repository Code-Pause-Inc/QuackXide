import { useRef, useState } from "react";
import type { DataDictionaryView } from "../../lib/research/client";
import { exampleQuery } from "../../lib/research/dictionary";
import { quietBtnCls } from "./styles";

/** A listed dataset's data dictionary: the columns its steward described
 *  and an example query over its table name, ready to copy. Schema
 *  metadata only, never rows. */
export default function DataDictionaryPanel({
  dictionary,
  withdrawn = false,
}: {
  dictionary: DataDictionaryView;
  /** No listing names the dataset any more: only its table name is known. */
  withdrawn?: boolean;
}) {
  const [copied, setCopied] = useState<"done" | "failed" | null>(null);
  const queryRef = useRef<HTMLElement>(null);
  const query = exampleQuery(dictionary.table);
  const count = dictionary.columns.length;
  const summary = withdrawn
    ? "listing withdrawn"
    : count === 0
      ? "columns not described"
      : `${count} ${count === 1 ? "column" : "columns"}`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(query);
      setCopied("done");
    } catch {
      // Copying can be refused (no permission, an insecure origin): select
      // the query so the keyboard can copy it.
      if (queryRef.current) window.getSelection()?.selectAllChildren(queryRef.current);
      setCopied("failed");
    }
  };

  return (
    <details className="mt-2 rounded-lg bg-slate-50 px-3 py-2 ring-1 ring-slate-100">
      <summary className="cursor-pointer text-xs font-medium text-slate-600">
        Data dictionary · {summary}
      </summary>
      <div className="mt-2 space-y-3">
        {withdrawn ? (
          <p className="text-xs text-slate-500">
            The steward withdrew this listing, so its column descriptions are no longer
            published.
          </p>
        ) : count === 0 ? (
          <p className="text-xs text-slate-500">
            The steward has not described this dataset’s columns.
          </p>
        ) : (
          <table className="w-full text-left text-xs">
            <caption className="sr-only">Columns of {dictionary.table}</caption>
            <thead className="text-[11px] uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="py-1 pr-3 font-medium">
                  Column
                </th>
                <th scope="col" className="py-1 pr-3 font-medium">
                  Type
                </th>
                <th scope="col" className="py-1 font-medium">
                  Description
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {dictionary.columns.map((column, index) => (
                <tr key={`${index}:${column.name}`}>
                  <td className="py-1 pr-3 align-top font-mono break-all text-slate-800">
                    {column.name}
                  </td>
                  <td className="py-1 pr-3 align-top font-mono text-slate-500">{column.type}</td>
                  <td className="py-1 align-top break-words text-slate-600">
                    {column.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-slate-400">
            Example query
          </p>
          <div className="mt-1 flex items-start gap-2">
            <code
              ref={queryRef}
              className="flex-1 rounded bg-white px-2 py-1.5 font-mono text-xs break-all text-slate-800 select-all ring-1 ring-slate-200"
            >
              {query}
            </code>
            <button
              type="button"
              onClick={copy}
              aria-label="Copy example query"
              className={quietBtnCls}
            >
              Copy
            </button>
          </div>
          {copied === "done" && (
            <p role="status" className="mt-1 text-[11px] text-slate-500">
              Copied.
            </p>
          )}
          {copied === "failed" && (
            <p role="alert" className="mt-1 text-[11px] text-rose-600">
              Copying failed. The query is selected: copy it with your keyboard.
            </p>
          )}
        </div>
      </div>
    </details>
  );
}
