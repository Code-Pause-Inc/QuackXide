// A listing's data dictionary: the SQL table name a research query uses and
// the columns the steward describes. The bounds are the API's
// (`platform-api/src/research.rs`), so a dictionary the form accepts is one
// the API accepts.

import type { ConnectorView } from "./client";

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

export interface DictionaryColumn {
  name: string;
  type: ColumnType;
  /** The steward's note on the column; empty when there is none. */
  description: string;
}

/** Most columns a dictionary may describe (`MAX_DICTIONARY_COLUMNS`). */
export const MAX_DICTIONARY_COLUMNS = 512;
/** Longest column name, in UTF-8 bytes (`MAX_COLUMN_NAME_BYTES`). */
export const MAX_COLUMN_NAME_BYTES = 128;
/** Longest column description, in characters (`MAX_COLUMN_DESCRIPTION_CHARS`). */
export const MAX_COLUMN_DESCRIPTION_CHARS = 500;

const utf8 = new TextEncoder();

/** Rust's `char::is_control`: the Unicode `Cc` category. */
function hasControl(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/** Whether `name` is a column name a dictionary may hold: 1 to 128 UTF-8
 *  bytes and no control characters (`platform_core::is_column_name`). */
export function isColumnName(name: string): boolean {
  const bytes = utf8.encode(name).length;
  return bytes >= 1 && bytes <= MAX_COLUMN_NAME_BYTES && !hasControl(name);
}

/** Characters as Rust counts them (Unicode scalar values), not UTF-16 units. */
function charCount(text: string): number {
  return [...text].length;
}

/** The first reason the API would refuse `columns`, or null. Names are
 *  compared exactly, since they must match the dataset's. */
export function dictionaryProblem(columns: readonly DictionaryColumn[]): string | null {
  if (columns.length > MAX_DICTIONARY_COLUMNS) {
    return `A data dictionary describes at most ${MAX_DICTIONARY_COLUMNS} columns.`;
  }
  const seen = new Set<string>();
  for (const [index, column] of columns.entries()) {
    if (!isColumnName(column.name)) {
      return `Column ${index + 1} needs a name of 1 to ${MAX_COLUMN_NAME_BYTES} bytes without control characters.`;
    }
    if (seen.has(column.name)) {
      return `Column ${index + 1} repeats the name “${column.name}”.`;
    }
    seen.add(column.name);
    if (charCount(column.description.trim()) > MAX_COLUMN_DESCRIPTION_CHARS) {
      return `Column ${index + 1}'s description is over ${MAX_COLUMN_DESCRIPTION_CHARS} characters.`;
    }
  }
  return null;
}

/** What a dataset's dictionary starts from: the columns its connector's
 *  mapper writes, undescribed, and the connector's name. Null for a dataset
 *  no connector maps (an upload, or a connector with no mapper), whose
 *  columns the steward enters. */
export function connectorPrefill(
  connectors: readonly ConnectorView[],
  dataset: string,
): { source: string; columns: DictionaryColumn[] } | null {
  const connector = connectors.find((c) => c.slug === dataset && c.columns.length > 0);
  if (!connector) return null;
  return {
    source: connector.display_name,
    columns: connector.columns.map(({ name, type }) => ({ name, type, description: "" })),
  };
}

/** Whether two column lists say the same thing, in the same order. */
export function sameColumns(a: readonly DictionaryColumn[], b: readonly DictionaryColumn[]) {
  return (
    a.length === b.length &&
    a.every(
      (column, i) =>
        column.name === b[i]!.name &&
        column.type === b[i]!.type &&
        column.description === b[i]!.description,
    )
  );
}

/** A dataset slug's table name, always double-quoted: correct for every
 *  slug, for when no listing names the table (the steward withdrew it). A
 *  published listing's `data_dictionary.table` quotes only where needed. */
export function quotedTableName(slug: string): string {
  return `"${slug.replace(/"/g, '""')}"`;
}

/** The smallest query the disclosure gate accepts: a genuine
 *  `COUNT(*) AS n` over the whole table. */
export function exampleQuery(table: string): string {
  return `SELECT COUNT(*) AS n FROM ${table}`;
}
