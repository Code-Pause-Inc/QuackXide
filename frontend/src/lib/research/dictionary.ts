// A listing's data dictionary: the SQL table name a research query uses and
// the columns the steward describes. The bounds are the API's
// (`platform-api/src/research.rs`), so a dictionary the form accepts is one
// the API accepts.

import type { ColumnType, DeclaredColumn } from "../datasets/schema";
import type { ConnectorView } from "./client";

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

/** Columns a dictionary can start from, undescribed, and where they came
 *  from, as a phrase ("the QuickBooks connector"). */
export interface Prefill {
  source: string;
  columns: DictionaryColumn[];
}

/** What a connector dataset's dictionary starts from: the columns its
 *  connector's mapper writes. Null for a dataset no connector maps (an
 *  upload, or a connector with no mapper). */
export function connectorPrefill(connectors: readonly ConnectorView[], dataset: string): Prefill | null {
  const connector = connectors.find((c) => c.slug === dataset && c.columns.length > 0);
  if (!connector) return null;
  return {
    source: `the ${connector.display_name} connector`,
    columns: connector.columns.map(({ name, type }) => ({ name, type, description: "" })),
  };
}

/** What an uploaded dataset's dictionary starts from: the schema its
 *  upload declared, which the browser read from the file's footer before
 *  sealing it (ADR 0014) and the dataset listing gives back. Null without a
 *  declared schema: a connector's dataset, or an unreadable record. */
export function uploadPrefill(
  datasets: readonly { dataset: string; schema: readonly DeclaredColumn[] | null }[],
  dataset: string,
): Prefill | null {
  const schema = datasets.find((d) => d.dataset === dataset)?.schema;
  if (!schema || schema.length === 0) return null;
  return {
    source: "the uploaded file",
    columns: schema.map(({ name, type }) => ({ name, type, description: "" })),
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
