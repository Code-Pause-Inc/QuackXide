// The schema a steward declares for an uploaded dataset (ADR 0012), as the
// upload header carries it: column names and type families, in order. The
// bounds are `platform_core::DeclaredSchema`'s, so a declaration the
// browser builds is one the upload route accepts. No DOM or worker globals:
// the footer worker, the crypto worker and the UI all use it.

/** A column's type family (`platform_core::ColumnType`). */
export const COLUMN_TYPES = [
  "boolean",
  "int8",
  "int16",
  "int32",
  "int64",
  "uint8",
  "uint16",
  "uint32",
  "uint64",
  "float32",
  "float64",
  "string",
  "date",
  "timestamp",
  "decimal",
] as const;

export type ColumnType = (typeof COLUMN_TYPES)[number];

export interface DeclaredColumn {
  name: string;
  type: ColumnType;
}

/** An upload's dataset id: a slug in the `upload_` namespace (ADR 0012),
 *  at most 64 bytes of `[a-z0-9_-]` in all. */
export const UPLOAD_DATASET = /^upload_[a-z0-9_-]{1,57}$/;

/** A snapshot version (`platform_core::SnapshotVersion`): 20 digits of
 *  Unix nanoseconds, a hyphen, then 32 lowercase hex digits. */
export const SNAPSHOT_VERSION = /^\d{20}-[0-9a-f]{32}$/;

/** What the browser's envelope suite (`HPK1`, until #186) adds to a file it
 *  seals: the magic, the encapsulated X25519 key and the AES-GCM tag
 *  (`docs/BENCHMARKS.md`). An upload's sealed object, not the file, must
 *  fit the upload limit. */
export const ENVELOPE_OVERHEAD_BYTES = 4 + 32 + 16;

/** Most columns a declaration may list (`MAX_DECLARED_COLUMNS`). */
export const MAX_DECLARED_COLUMNS = 512;
/** Longest column name, in UTF-8 bytes (`MAX_COLUMN_NAME_BYTES`). */
export const MAX_COLUMN_NAME_BYTES = 128;
/** Largest row cap an upload may declare: the largest integer a JSON
 *  number holds exactly, 2^53 - 1 (`MAX_ROW_CAP`). */
export const MAX_ROW_CAP = Number.MAX_SAFE_INTEGER;

const utf8 = new TextEncoder();

/** Rust's `char::is_control`: the Unicode `Cc` category. */
function hasControl(name: string): boolean {
  for (const ch of name) {
    const code = ch.codePointAt(0)!;
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/** Whether `name` is a column name a declaration may hold: 1 to 128 UTF-8
 *  bytes and no control characters. */
export function isColumnName(name: string): boolean {
  const bytes = utf8.encode(name).length;
  return bytes >= 1 && bytes <= MAX_COLUMN_NAME_BYTES && !hasControl(name);
}

export type DeclarationProblem =
  | { code: "no_columns" }
  | { code: "too_many_columns" }
  | { code: "column_name"; column: string }
  | { code: "duplicate_column"; column: string };

/** The first reason `columns` is not a valid declaration, or null. */
export function declarationProblem(columns: readonly DeclaredColumn[]): DeclarationProblem | null {
  if (columns.length === 0) return { code: "no_columns" };
  if (columns.length > MAX_DECLARED_COLUMNS) return { code: "too_many_columns" };
  const seen = new Set<string>();
  for (const { name } of columns) {
    if (!isColumnName(name)) return { code: "column_name", column: name };
    if (seen.has(name)) return { code: "duplicate_column", column: name };
    seen.add(name);
  }
  return null;
}

/** Whether `value` is a well-formed declaration: a JSON value of the shape
 *  the upload header carries, within its bounds. */
export function isDeclaredSchema(value: unknown): value is DeclaredColumn[] {
  if (!Array.isArray(value)) return false;
  const shaped = value.every(
    (column: unknown) =>
      typeof column === "object" &&
      column !== null &&
      Object.keys(column).length === 2 &&
      typeof (column as DeclaredColumn).name === "string" &&
      (COLUMN_TYPES as readonly string[]).includes((column as DeclaredColumn).type),
  );
  return shaped && declarationProblem(value as DeclaredColumn[]) === null;
}

/** Whether two declarations are the same: the same names and types in the
 *  same order, which is what the upload route compares. */
export function sameSchema(a: readonly DeclaredColumn[], b: readonly DeclaredColumn[]): boolean {
  return (
    a.length === b.length && a.every((col, i) => col.name === b[i]!.name && col.type === b[i]!.type)
  );
}

/** Whether `rows` can be declared as an upload's row cap: 1 to 2^53 - 1. */
export function isRowCap(rows: number): boolean {
  return Number.isSafeInteger(rows) && rows >= 1 && rows <= MAX_ROW_CAP;
}
