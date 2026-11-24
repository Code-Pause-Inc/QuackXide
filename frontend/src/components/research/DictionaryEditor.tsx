import { COLUMN_TYPES, type ColumnType } from "../../lib/datasets/schema";
import {
  type DictionaryColumn,
  MAX_COLUMN_DESCRIPTION_CHARS,
  MAX_DICTIONARY_COLUMNS,
  dictionaryProblem,
} from "../../lib/research/dictionary";
import { inputCls, quietBtnCls } from "./styles";

/** Edits the columns a listing's data dictionary describes. Names are kept
 *  exactly as typed, since they must match the dataset's. */
export default function DictionaryEditor({
  columns,
  onChange,
  source,
  onUseSource,
}: {
  columns: DictionaryColumn[];
  onChange: (columns: DictionaryColumn[]) => void;
  /** Where the columns can start from, as a phrase ("the QuickBooks
   *  connector", "the uploaded file"), if the dataset has such columns. */
  source: string | null;
  /** Puts those columns back; shown once the columns differ. */
  onUseSource?: () => void;
}) {
  const problem = dictionaryProblem(columns);
  const update = (index: number, change: Partial<DictionaryColumn>) =>
    onChange(columns.map((column, i) => (i === index ? { ...column, ...change } : column)));

  return (
    <fieldset className="space-y-2 rounded-md border border-slate-200 bg-white p-3">
      <legend className="px-1 text-xs font-medium text-slate-600">Data dictionary</legend>
      <p className="text-xs text-slate-500">
        Researchers see the dataset’s table name and these columns, never its rows.{" "}
        {source && !onUseSource
          ? `Pre-filled from ${source}; edit as needed.`
          : "Describe the columns researchers can query."}
      </p>
      {columns.length > 0 && (
        <ul className="space-y-1.5">
          {columns.map((column, index) => (
            <li key={index} className="grid grid-cols-[1fr_7rem_2fr_auto] gap-2">
              <input
                aria-label={`Column ${index + 1} name`}
                className={`${inputCls} font-mono`}
                value={column.name}
                onChange={(ev) => update(index, { name: ev.target.value })}
                placeholder="column name"
              />
              <select
                aria-label={`Column ${index + 1} type`}
                className={inputCls}
                value={column.type}
                onChange={(ev) => update(index, { type: ev.target.value as ColumnType })}
              >
                {COLUMN_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
              <input
                aria-label={`Column ${index + 1} description`}
                className={inputCls}
                value={column.description}
                maxLength={MAX_COLUMN_DESCRIPTION_CHARS}
                onChange={(ev) => update(index, { description: ev.target.value })}
                placeholder="description — optional"
              />
              <button
                type="button"
                aria-label={`Remove column ${index + 1}`}
                onClick={() => onChange(columns.filter((_, i) => i !== index))}
                className={quietBtnCls}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => onChange([...columns, { name: "", type: "string", description: "" }])}
          disabled={columns.length >= MAX_DICTIONARY_COLUMNS}
          className={quietBtnCls}
        >
          Add column
        </button>
        {source && onUseSource && (
          <button type="button" onClick={onUseSource} className={quietBtnCls}>
            Use {source}’s columns
          </button>
        )}
      </div>
      {problem && (
        <p role="alert" className="text-xs text-rose-600">
          {problem}
        </p>
      )}
    </fieldset>
  );
}
