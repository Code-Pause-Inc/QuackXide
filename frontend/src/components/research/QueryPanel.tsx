import { useState } from "react";
import { errorMessage } from "../../lib/format";
import type { ResearchResultView } from "../../lib/research/client";
import { inputCls, primaryBtnCls } from "./styles";

/** Query box and result table for one granted dataset. Every run, refused or
 *  not, may spend a unit, so the caller reloads the allowance afterwards. */
export default function QueryPanel({
  initialSql,
  run,
  onRan,
}: {
  initialSql: string;
  run: (sql: string) => Promise<ResearchResultView>;
  onRan: () => void;
}) {
  const [sql, setSql] = useState(initialSql);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ResearchResultView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      setResult(await run(sql));
    } catch (err) {
      setError(errorMessage(err, "query failed"));
    } finally {
      setRunning(false);
      onRan();
    }
  };

  const columns = result?.rows[0] ? Object.keys(result.rows[0]) : [];

  return (
    <div className="mt-3 space-y-2 rounded-lg bg-slate-50 p-3 ring-1 ring-slate-100">
      <textarea
        aria-label="SQL query"
        value={sql}
        onChange={(ev) => setSql(ev.target.value)}
        rows={3}
        spellCheck={false}
        className={`${inputCls} w-full font-mono`}
      />
      <button
        type="button"
        onClick={submit}
        disabled={running || !sql.trim()}
        className={primaryBtnCls}
      >
        {running ? "Running…" : "Run query"}
      </button>
      {error && (
        <p role="alert" className="text-xs text-rose-600">
          {error}
        </p>
      )}
      {result && (
        <div className="space-y-1.5">
          {result.rows.length > 0 ? (
            <table className="w-full text-left text-xs tabular-nums">
              <thead>
                <tr className="text-slate-500">
                  {columns.map((c) => (
                    <th key={c} className="py-1 pr-4 font-medium">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i} className="border-t border-slate-200">
                    {columns.map((c) => (
                      <td key={c} className="py-1 pr-4">
                        {row[c] === null ? "—" : String(row[c])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-xs text-slate-500">No groups released.</p>
          )}
          <p className="text-[11px] text-slate-500">
            {result.suppressed_rows} group{result.suppressed_rows === 1 ? "" : "s"} suppressed
            below {result.min_cohort} · {result.budget_remaining} queries left · TEE:{" "}
            {result.tee_platform}
          </p>
        </div>
      )}
    </div>
  );
}
