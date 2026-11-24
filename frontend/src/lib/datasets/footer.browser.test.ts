// The footer worker in real browsers (vitest `browser` project,
// `npm run test:browser`): the module worker starts, receives a File,
// reads its footer and answers with the declaration, as in the app. The
// shared vectors (fixtures/parquet/) read here as they do under Node.

import { describe, expect, it } from "vitest";

import vectors from "../../../../fixtures/parquet/schema-vectors.json";
import { parquetFixture } from "../../test/parquetFixtures";
import { readFooterInWorker } from "./footerClient";

function file(name: string): File {
  return new File([parquetFixture(name)], name);
}

describe("footer worker in a real browser", () => {
  it("declares the cohort a steward uploads", async () => {
    expect(await readFooterInWorker(file("upload-cohort.parquet"))).toEqual({
      ok: true,
      schema: [
        { name: "condition", type: "string" },
        { name: "age", type: "int64" },
      ],
      rows: 7,
      footerBytes: expect.any(Number),
    });
  });

  it("refuses a file that is not Parquet", async () => {
    const csv = new File(["condition,n\nflu,6\n"], "cohort.csv");
    expect(await readFooterInWorker(csv)).toEqual({ ok: false, refusal: { code: "not_parquet" } });
  });

  it("reads every shared vector as the enclave's side records", async () => {
    for (const vector of vectors.vectors) {
      const reading = await readFooterInWorker(file(vector.file));
      if (vector.browser === "declares") {
        expect(reading, vector.file).toMatchObject({ ok: true, schema: vector.declared, rows: vector.rows });
      } else {
        expect(reading, vector.file).toMatchObject({ ok: false, refusal: { code: vector.browser } });
      }
    }
  });
});
