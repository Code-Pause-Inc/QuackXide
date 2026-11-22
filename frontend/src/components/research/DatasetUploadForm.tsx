import { useId, useRef, useState } from "react";
import type { DatasetUploadResult } from "../../lib/crypto/datasetUpload";
import type { DatasetUploadFields } from "../../lib/crypto/protocol";
import type { FooterReading, FooterRefusal } from "../../lib/datasets/footer";
import {
  ENVELOPE_OVERHEAD_BYTES,
  MAX_DECLARED_COLUMNS,
  UPLOAD_DATASET,
  sameSchema,
} from "../../lib/datasets/schema";
import { errorMessage, formatBytes } from "../../lib/format";
import type { DatasetView } from "../../lib/research/client";
import { inputCls, primaryBtnCls } from "./styles";

/** Why the footer reader refused a file, in words. */
export function refusalMessage(refusal: FooterRefusal): string {
  switch (refusal.code) {
    case "not_parquet":
      return "This is not a Parquet file.";
    case "encrypted":
      return "This Parquet file is encrypted. Upload it unencrypted: it is sealed on this device before upload.";
    case "footer_length":
      return "This file is truncated: its Parquet footer is longer than the file.";
    case "footer_too_large":
      return "This file's Parquet footer is larger than 16 MiB.";
    case "malformed_footer":
      return "This file's Parquet footer is malformed.";
    case "arrow_schema":
      return "The Arrow schema embedded in this file is malformed or does not match its columns.";
    case "nested_column":
      return `Column “${refusal.column}” is nested (a list, map or struct). Only flat columns can be uploaded.`;
    case "unsupported_type":
      return `Column “${refusal.column}” has a type that cannot be declared, such as binary, time of day, duration, interval or UUID.`;
    case "no_columns":
      return "This file has no columns.";
    case "too_many_columns":
      return `This file has more than ${MAX_DECLARED_COLUMNS} columns.`;
    case "column_name":
      return `Column name “${refusal.column}” is empty, longer than 128 bytes, or contains control characters.`;
    case "duplicate_column":
      return `Column name “${refusal.column}” appears more than once.`;
    case "no_rows":
      return "This file has no rows.";
    case "too_many_rows":
      return "This file has more rows than an upload can declare.";
  }
}

/** The first reason the upload cannot go ahead, checked before anything is
 *  sealed; the crypto worker and the API check again. */
export function uploadProblem({
  dataset,
  file,
  reading,
  datasets,
  maxBytes,
}: {
  dataset: string;
  file: File | null;
  reading: FooterReading | null;
  datasets: DatasetView[];
  maxBytes: number;
}): string | null {
  if (dataset !== "" && !UPLOAD_DATASET.test(dataset)) {
    return "A dataset name starts with upload_ and uses only lowercase letters, digits, _ and -, 64 characters in all.";
  }
  if (!file || !reading) return null;
  if (!reading.ok) return refusalMessage(reading.refusal);
  if (file.size + ENVELOPE_OVERHEAD_BYTES > maxBytes) {
    return `This file is ${formatBytes(file.size)} and the upload limit is ${formatBytes(maxBytes)} of ciphertext.`;
  }
  const current = datasets.find((d) => d.dataset === dataset);
  if (current) {
    if (!current.schema) {
      return `The record of ${dataset}'s current snapshot is unreadable, so a new upload cannot be checked against its schema.`;
    }
    if (!sameSchema(current.schema, reading.schema)) {
      return `This file's columns differ from the schema recorded for ${dataset}. A dataset keeps the columns of its first upload.`;
    }
  }
  return null;
}

/** Seals a Parquet file on this device and uploads it as a dataset. The
 *  footer is read in a worker of its own (`readFooter`); the seal and the
 *  upload run in the crypto worker (`onUpload`). */
export default function DatasetUploadForm({
  datasets,
  maxBytes,
  initialDataset = "",
  readFooter,
  onUpload,
  onUploaded,
}: {
  datasets: DatasetView[];
  maxBytes: number;
  initialDataset?: string;
  readFooter: (file: File) => Promise<FooterReading>;
  onUpload: (fields: DatasetUploadFields) => Promise<DatasetUploadResult>;
  onUploaded: (result: DatasetUploadResult) => void;
}) {
  const nameId = useId();
  const fileId = useId();
  const [dataset, setDataset] = useState(initialDataset);
  const [file, setFile] = useState<File | null>(null);
  const [reading, setReading] = useState<FooterReading | null>(null);
  const [readingFile, setReadingFile] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stored, setStored] = useState<DatasetUploadResult | null>(null);

  // The latest choice. A footer read that finishes after another file was
  // chosen is dropped, so a file is never uploaded with another's schema.
  const choice = useRef(0);

  const choose = async (chosen: File | null) => {
    const id = ++choice.current;
    setFile(chosen);
    setReading(null);
    setError(null);
    setStored(null);
    setReadingFile(chosen !== null);
    if (!chosen) return;
    try {
      const read = await readFooter(chosen);
      if (id === choice.current) setReading(read);
    } catch (err) {
      if (id === choice.current) setError(errorMessage(err, "the file could not be read"));
    } finally {
      if (id === choice.current) setReadingFile(false);
    }
  };

  const problem = uploadProblem({ dataset, file, reading, datasets, maxBytes });
  const declared = reading?.ok ? reading : null;
  const ready = file !== null && declared !== null && dataset !== "" && problem === null && !uploading;

  const upload = async () => {
    if (!file || !declared) return;
    setUploading(true);
    setError(null);
    setStored(null);
    try {
      const result = await onUpload({
        file,
        dataset,
        schema: declared.schema,
        rowCap: declared.rows,
        currentVersion: datasets.find((d) => d.dataset === dataset)?.version ?? null,
        maxBytes,
      });
      setStored(result);
      onUploaded(result);
    } catch (err) {
      setError(errorMessage(err, "the upload failed"));
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="mt-3 space-y-3 rounded-lg bg-slate-50 p-3 ring-1 ring-slate-100">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor={nameId} className="block text-xs font-medium text-slate-600">
            Dataset name
          </label>
          <input
            id={nameId}
            className={`${inputCls} w-full font-mono`}
            value={dataset}
            onChange={(ev) => setDataset(ev.target.value.trim())}
            placeholder="upload_cohorts"
            list={`${nameId}-stored`}
            maxLength={64}
            autoComplete="off"
          />
          <datalist id={`${nameId}-stored`}>
            {datasets
              .filter((d) => d.dataset.startsWith("upload_"))
              .map((d) => (
                <option key={d.dataset} value={d.dataset} />
              ))}
          </datalist>
        </div>
        <div className="space-y-1">
          <label htmlFor={fileId} className="block text-xs font-medium text-slate-600">
            Parquet file
          </label>
          <input
            id={fileId}
            type="file"
            accept=".parquet"
            className="block w-full text-xs text-slate-600"
            onChange={(ev) => void choose(ev.target.files?.[0] ?? null)}
          />
        </div>
      </div>

      {readingFile && <p className="text-xs text-slate-500">Reading the file's footer…</p>}

      {declared && (
        <div className="text-xs text-slate-600">
          <p>
            {declared.schema.length} {declared.schema.length === 1 ? "column" : "columns"},{" "}
            {declared.rows.toLocaleString("en-US")} {declared.rows === 1 ? "row" : "rows"}:
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5" aria-label="Columns to declare">
            {declared.schema.map((col) => (
              <li key={col.name} className="rounded bg-white px-1.5 py-0.5 font-mono ring-1 ring-slate-200">
                {col.name} <span className="text-slate-400">{col.type}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-xs text-slate-500">
        The rows are sealed on this device. Column names and types are stored in plaintext beside
        them, where the operator can see them.
      </p>

      {(problem || error) && (
        <p role="alert" className="rounded-md bg-rose-50 p-2 text-xs text-rose-700 ring-1 ring-rose-200">
          {error ?? problem}
        </p>
      )}
      {stored && (
        <p role="status" className="text-xs text-teal-700">
          Stored {stored.dataset} as {formatBytes(stored.ciphertextBytes)} of ciphertext ({stored.suite}).
        </p>
      )}

      <div className="flex justify-end">
        <button type="button" disabled={!ready} onClick={() => void upload()} className={primaryBtnCls}>
          {uploading ? "Sealing and uploading…" : "Seal and upload"}
        </button>
      </div>
    </div>
  );
}
