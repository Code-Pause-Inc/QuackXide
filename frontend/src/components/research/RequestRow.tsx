import type { ReactNode } from "react";
import { shortId } from "../../lib/research/client";

/** An access request on one of my datasets: title, researcher and date,
 *  an optional note, then the actions passed as children. */
export default function RequestRow({
  title,
  researcher,
  when,
  note,
  children,
}: {
  title: string;
  researcher: string;
  when: string;
  note?: string;
  children: ReactNode;
}) {
  return (
    <li className="flex items-center gap-4 py-4">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{title}</p>
        <p className="mt-0.5 text-xs text-slate-500">
          researcher {shortId(researcher)} · {when}
        </p>
        {note !== undefined && (
          <p className="mt-1 text-xs italic text-slate-600">{note}</p>
        )}
      </div>
      {children}
    </li>
  );
}
