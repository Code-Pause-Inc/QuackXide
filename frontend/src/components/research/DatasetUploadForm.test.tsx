import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { DatasetUploadResult } from "../../lib/crypto/datasetUpload";
import { FOOTER_MAX_BYTES, readFooter } from "../../lib/datasets/footer";
import type { DatasetView } from "../../lib/research/client";
import { parquetFixture } from "../../test/parquetFixtures";
import DatasetList from "./DatasetList";
import DatasetUploadForm from "./DatasetUploadForm";

const COHORT_SCHEMA = [
  { name: "condition", type: "string" as const },
  { name: "age", type: "int64" as const },
];
const VERSION = `01763116830123456789-${"0".repeat(32)}`;

function stored(overrides: Partial<DatasetView> = {}): DatasetView {
  return {
    dataset: "upload_cohorts",
    version: VERSION,
    written_at: "2025-11-14T10:40:30.123Z",
    suite: "HPK1",
    row_cap: 7,
    schema: COHORT_SCHEMA,
    object_count: 1,
    ciphertext_bytes: 1932,
    objects: ["00000000-aaaa-4bbb-8ccc-000000000001"],
    ...overrides,
  };
}

const RESULT: DatasetUploadResult = {
  dataset: "upload_cohorts",
  version: `01800000000000000000-${"1".repeat(32)}`,
  object: "00000000-aaaa-4bbb-8ccc-000000000002",
  suite: "HPK1",
  ciphertextBytes: 1932,
};

function cohortFile(): File {
  return new File([parquetFixture("upload-cohort.parquet")], "cohort.parquet");
}

function setup({
  datasets = [] as DatasetView[],
  maxBytes = 64 * 1024 * 1024,
  upload = vi.fn(async () => RESULT),
} = {}) {
  const user = userEvent.setup();
  const onUploaded = vi.fn();
  render(
    <DatasetUploadForm
      datasets={datasets}
      maxBytes={maxBytes}
      readFooter={readFooter}
      onUpload={upload}
      onUploaded={onUploaded}
    />,
  );
  const name = screen.getByLabelText("Dataset name");
  const file = screen.getByLabelText("Parquet file");
  const button = () => screen.getByRole("button", { name: /seal and upload/i });
  const choose = async (dataset: string, chosen: File) => {
    await user.clear(name);
    await user.type(name, dataset);
    await user.upload(file, chosen);
  };
  return { user, upload, onUploaded, choose, button };
}

describe("DatasetUploadForm", () => {
  it("labels its controls and says, before any upload, what the operator sees", () => {
    setup();
    expect(screen.getByLabelText("Dataset name")).toBeInTheDocument();
    expect(screen.getByLabelText("Parquet file")).toHaveAttribute("type", "file");
    expect(screen.getByText(/column names and types are stored in plaintext/i)).toBeInTheDocument();
  });

  it("declares the footer's schema and uploads it with the current version", async () => {
    const datasets = [stored()];
    const { user, choose, button, upload, onUploaded } = setup({ datasets });
    const chosen = cohortFile();
    await choose("upload_cohorts", chosen);
    expect(await screen.findByText(/2 columns, 7 rows/)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Columns to declare" })).toHaveTextContent("condition string");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(button());
    expect(upload).toHaveBeenCalledExactlyOnceWith({
      file: chosen,
      dataset: "upload_cohorts",
      schema: COHORT_SCHEMA,
      rowCap: 7,
      currentVersion: VERSION,
      maxBytes: 64 * 1024 * 1024,
    });
    expect(await screen.findByRole("status")).toHaveTextContent("Stored upload_cohorts");
    expect(onUploaded).toHaveBeenCalledWith(RESULT);
  });

  it("uploads a new dataset with no current version", async () => {
    const { user, choose, button, upload } = setup();
    await choose("upload_new", cohortFile());
    await screen.findByText(/2 columns/);
    await user.click(button());
    expect(upload).toHaveBeenCalledWith(expect.objectContaining({ dataset: "upload_new", currentVersion: null }));
  });

  const bytes = (...parts: Array<string | Uint8Array>) => new File(parts as BlobPart[], "data.parquet");
  const trailer = (length: number) => {
    const view = new DataView(new ArrayBuffer(8));
    view.setUint32(0, length, true);
    new Uint8Array(view.buffer).set(new TextEncoder().encode("PAR1"), 4);
    return new Uint8Array(view.buffer);
  };
  const cohort = parquetFixture("upload-cohort.parquet");
  const footerLength = new DataView(cohort.buffer).getUint32(cohort.length - 8, true);

  it.each<[string, () => File, RegExp]>([
    ["a file that is not Parquet", () => bytes("condition,n\nflu,6\n"), /not a Parquet file/],
    ["a footer longer than the file", () => bytes(cohort.subarray(0, cohort.length - 8), trailer(cohort.length)), /truncated/],
    ["a footer longer than the cap", () => bytes(new Uint8Array(FOOTER_MAX_BYTES + 1), trailer(FOOTER_MAX_BYTES + 1)), /larger than 16 MiB/],
    [
      "a truncated footer",
      () =>
        bytes(
          cohort.subarray(0, cohort.length - 8 - footerLength + Math.floor(footerLength / 2)),
          trailer(Math.floor(footerLength / 2)),
        ),
      /footer is malformed/,
    ],
    ["an unsupported column", () => new File([parquetFixture("binary.parquet")], "b.parquet"), /“payload” has a type/],
  ])("refuses %s before sealing", async (_what, file, message) => {
    const { choose, button, upload } = setup();
    await choose("upload_cohorts", file());
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(button()).toBeDisabled();
    expect(upload).not.toHaveBeenCalled();
  });

  it("refuses a file over the upload limit before sealing", async () => {
    const { choose, button, upload } = setup({ maxBytes: cohort.length + 51 });
    await choose("upload_cohorts", cohortFile());
    expect(await screen.findByRole("alert")).toHaveTextContent(/upload limit/);
    expect(button()).toBeDisabled();
    expect(upload).not.toHaveBeenCalled();
  });

  it("refuses columns unlike the dataset's recorded schema before sealing", async () => {
    const datasets = [stored({ schema: [{ name: "condition", type: "string" }] })];
    const { choose, button, upload } = setup({ datasets });
    await choose("upload_cohorts", cohortFile());
    expect(await screen.findByRole("alert")).toHaveTextContent(/differ from the schema recorded for upload_cohorts/);
    expect(button()).toBeDisabled();
    expect(upload).not.toHaveBeenCalled();
  });

  it("refuses a re-upload when the recorded schema is unreadable", async () => {
    const { choose, button } = setup({ datasets: [stored({ schema: null, suite: null })] });
    await choose("upload_cohorts", cohortFile());
    expect(await screen.findByRole("alert")).toHaveTextContent(/unreadable/);
    expect(button()).toBeDisabled();
  });

  it("refuses a dataset name outside the upload namespace", async () => {
    const { user, button } = setup();
    await user.type(screen.getByLabelText("Dataset name"), "health");
    expect(screen.getByRole("alert")).toHaveTextContent(/starts with upload_/);
    expect(button()).toBeDisabled();
  });

  it.each([
    ["401", "Not authenticated: the session was rejected. Sign in again, then upload."],
    ["403", "Not authorized: this account may not upload datasets."],
  ])("shows a %s refusal clearly", async (_status, message) => {
    const upload = vi.fn(async () => {
      throw new Error(message);
    });
    const { user, choose, button, onUploaded } = setup({ upload });
    await choose("upload_cohorts", cohortFile());
    await screen.findByText(/2 columns/);
    await user.click(button());
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(onUploaded).not.toHaveBeenCalled();
    await waitFor(() => expect(button()).toHaveTextContent("Seal and upload"));
  });
});

describe("DatasetList", () => {
  it("shows each stored dataset as ciphertext", () => {
    render(
      <DatasetList
        datasets={[stored(), stored({ dataset: "health", suite: null, object_count: 2, ciphertext_bytes: 2048 })]}
      />,
    );
    const items = screen.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("upload_cohorts");
    expect(items[0]).toHaveTextContent("1 object · 1.9 KB ciphertext · HPK1 · written 2025-11-14 10:40 UTC");
    expect(items[1]).toHaveTextContent("2 objects · 2 KB ciphertext · record unreadable");
  });

  it("offers a re-upload of uploaded datasets only", async () => {
    const onReupload = vi.fn();
    render(<DatasetList datasets={[stored(), stored({ dataset: "health" })]} onReupload={onReupload} />);
    const buttons = screen.getAllByRole("button", { name: /re-upload/i });
    expect(buttons).toHaveLength(1);
    await userEvent.setup().click(buttons[0]!);
    expect(onReupload).toHaveBeenCalledWith("upload_cohorts");
  });

  it("says when nothing is stored", () => {
    render(<DatasetList datasets={[]} />);
    expect(screen.getByText(/no stored datasets/i)).toBeInTheDocument();
  });
});
