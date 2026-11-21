// The Parquet footer reader: the cross-implementation vectors the enclave
// also checks (fixtures/parquet/, ADR 0014), the refusals of malformed
// files, and that only the tail of a file is read.

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import vectors from "../../../../fixtures/parquet/schema-vectors.json";
import { parquetFixture } from "../../test/parquetFixtures";
import { FOOTER_MAX_BYTES, readFooter, type FooterReading } from "./footer";

const fixture = parquetFixture;

function blob(...parts: BlobPart[]): Blob {
  return new Blob(parts);
}

async function refusal(file: Blob): Promise<string> {
  const reading = await readFooter(file);
  if (reading.ok) throw new Error(`declared ${JSON.stringify(reading.schema)}`);
  return reading.refusal.code;
}

// ── A Thrift compact-protocol writer, to build footers byte by byte ──

type T =
  | { t: "i32"; v: number }
  | { t: "i64"; v: bigint }
  | { t: "bin"; v: string | Uint8Array }
  | { t: "bool"; v: boolean }
  | { t: "struct"; v: Record<number, T> }
  | { t: "list"; v: T[] };

const i32 = (v: number): T => ({ t: "i32", v });
const i64 = (v: bigint | number): T => ({ t: "i64", v: BigInt(v) });
const bin = (v: string | Uint8Array): T => ({ t: "bin", v });
const bool = (v: boolean): T => ({ t: "bool", v });
const st = (v: Record<number, T>): T => ({ t: "struct", v });
const ls = (v: T[]): T => ({ t: "list", v });

const TYPE = { true: 1, false: 2, i32: 5, i64: 6, bin: 8, list: 9, struct: 12 } as const;

function varint(out: number[], value: bigint): void {
  let v = value;
  do {
    const byte = Number(v & 0x7fn);
    v >>= 7n;
    out.push(v ? byte | 0x80 : byte);
  } while (v);
}

const zigzag = (v: bigint): bigint => (v >= 0n ? v << 1n : (-v << 1n) - 1n);

function typeOf(value: T): number {
  if (value.t === "bool") return value.v ? TYPE.true : TYPE.false;
  return TYPE[value.t];
}

function writeValue(out: number[], value: T): void {
  switch (value.t) {
    case "i32":
      varint(out, zigzag(BigInt(value.v)));
      return;
    case "i64":
      varint(out, zigzag(value.v));
      return;
    case "bin": {
      const bytes = typeof value.v === "string" ? new TextEncoder().encode(value.v) : value.v;
      varint(out, BigInt(bytes.length));
      out.push(...bytes);
      return;
    }
    case "bool":
      return;
    case "list": {
      const elem = value.v[0] ? TYPE[value.v[0].t as "struct"] : TYPE.struct;
      if (value.v.length < 15) out.push((value.v.length << 4) | elem);
      else {
        out.push(0xf0 | elem);
        varint(out, BigInt(value.v.length));
      }
      for (const item of value.v) writeValue(out, item);
      return;
    }
    case "struct": {
      let last = 0;
      for (const [key, field] of Object.entries(value.v).sort((a, b) => Number(a[0]) - Number(b[0]))) {
        const id = Number(key);
        const delta = id - last;
        if (delta > 0 && delta <= 15) out.push((delta << 4) | typeOf(field));
        else {
          out.push(typeOf(field));
          varint(out, zigzag(BigInt(id)));
        }
        last = id;
        writeValue(out, field);
      }
      out.push(0);
      return;
    }
  }
}

/** A SchemaElement (parquet-format). */
function element(name: string, fields: Record<number, T>): T {
  return st({ 4: bin(name), ...fields });
}

const REQUIRED = i32(0);
const REPEATED = i32(2);
const root = (children: number) => element("schema", { 5: i32(children) });
const column = (name: string, physical: number, extra: Record<number, T> = {}) =>
  element(name, { 1: i32(physical), 3: REQUIRED, ...extra });
const logical = (member: number, value: Record<number, T> = {}) => ({ 10: st({ [member]: st(value) }) });

/** A FileMetaData footer over `schema` with `rows` rows in one row group. */
function metadata(schema: T[], rows: bigint | number = 3, extra: Record<number, T> = {}): T {
  return st({
    1: i32(2),
    2: ls(schema),
    3: i64(rows),
    4: ls([st({ 1: ls([]), 2: i64(0), 3: i64(rows) })]),
    ...extra,
  });
}

/** A Parquet file whose footer is `footer`; the pages are left out, since
 *  nothing reads them. */
function parquet(footer: T | Uint8Array, magic = "PAR1"): Blob {
  const bytes: number[] = [];
  if (footer instanceof Uint8Array) bytes.push(...footer);
  else writeValue(bytes, footer);
  const trailer = new DataView(new ArrayBuffer(4));
  trailer.setUint32(0, bytes.length, true);
  return blob("PAR1", new Uint8Array(bytes), trailer, magic);
}

const INT64 = 2;
const INT32 = 1;
const BYTE_ARRAY = 6;

describe("the schema vectors the enclave also reads", () => {
  for (const vector of vectors.vectors) {
    it(`${vector.file}: ${vector.browser}`, async () => {
      const reading = await readFooter(blob(fixture(vector.file)));
      if (vector.browser === "declares") {
        expect(reading).toEqual({
          ok: true,
          schema: vector.declared,
          rows: vector.rows,
          footerBytes: expect.any(Number),
        });
      } else {
        expect(reading).toMatchObject({ ok: false, refusal: { code: vector.browser } });
      }
    });
  }

  it("declares only what the enclave declares too", () => {
    for (const vector of vectors.vectors) {
      if (vector.browser === "declares") expect(vector.enclave, vector.file).toBe("declares");
    }
  });
});

describe("files that are not Parquet the enclave reads", () => {
  it("refuses a file too short to hold a footer", async () => {
    expect(await refusal(blob(""))).toBe("not_parquet");
    expect(await refusal(blob("PAR1"))).toBe("not_parquet");
  });

  it("refuses a file without the Parquet magic", async () => {
    expect(await refusal(blob("condition,n\nflu,12\ncold,40\n"))).toBe("not_parquet");
    const valid = fixture("families.parquet");
    valid[valid.length - 1] = "2".charCodeAt(0);
    expect(await refusal(blob(valid))).toBe("not_parquet");
  });

  it("refuses an encrypted file", async () => {
    expect(await refusal(parquet(metadata([root(1), column("n", INT64)]), "PARE"))).toBe("encrypted");
    const withEncryption = metadata([root(1), column("n", INT64)], 3, { 8: st({ 1: st({}) }) });
    expect(await refusal(parquet(withEncryption))).toBe("encrypted");
  });

  it("refuses a footer longer than the file", async () => {
    const valid = fixture("families.parquet");
    const view = new DataView(valid.buffer);
    view.setUint32(valid.length - 8, valid.length - 7, true);
    expect(await refusal(blob(valid))).toBe("footer_length");
    view.setUint32(valid.length - 8, 0xffffffff, true);
    expect(await refusal(blob(valid))).toBe("footer_length");
  });

  it("refuses a footer longer than the cap, without reading it", async () => {
    const trailer = new DataView(new ArrayBuffer(8));
    trailer.setUint32(0, FOOTER_MAX_BYTES + 1, true);
    new Uint8Array(trailer.buffer).set(new TextEncoder().encode("PAR1"), 4);
    const big = blob(new Uint8Array(FOOTER_MAX_BYTES + 16), trailer);
    expect(await refusal(big)).toBe("footer_too_large");
  });

  it("refuses a truncated footer", async () => {
    const valid = fixture("families.parquet");
    const length = new DataView(valid.buffer).getUint32(valid.length - 8, true);
    const start = valid.length - 8 - length;
    const half = Math.floor(length / 2);
    const trailer = new DataView(new ArrayBuffer(4));
    trailer.setUint32(0, half, true);
    const truncated = blob(valid.subarray(0, start + half), trailer, "PAR1");
    expect(await refusal(truncated)).toBe("malformed_footer");
  });

  it("refuses a footer that is not Thrift", async () => {
    expect(await refusal(parquet(new Uint8Array([0xff, 0xee, 0xdd])))).toBe("malformed_footer");
    expect(await refusal(parquet(new Uint8Array(0)))).toBe("malformed_footer");
  });

  it("never throws on arbitrary footer bytes", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 512 }), async (bytes) => {
        const reading = await readFooter(parquet(bytes));
        expect(typeof reading.ok).toBe("boolean");
      }),
      { numRuns: 300 },
    );
  });
});

describe("footers parquet-rs would not read", () => {
  const cases: Array<[string, T]> = [
    ["no version", st({ 2: ls([root(1), column("n", INT64)]), 3: i64(3), 4: ls([]) })],
    ["no row count", st({ 1: i32(2), 2: ls([root(1), column("n", INT64)]), 4: ls([]) })],
    ["no schema", st({ 1: i32(2), 3: i64(3), 4: ls([]) })],
    ["a negative row count", metadata([root(1), column("n", INT64)], -1)],
    ["a column with no name", metadata([root(1), st({ 1: i32(INT64), 3: REQUIRED })])],
    ["a name that is not UTF-8", metadata([root(1), column("x", INT64, { 4: bin(new Uint8Array([0xc3, 0x28])) })])],
    ["an unknown physical type", metadata([root(1), column("n", 8)])],
    ["an unknown converted type", metadata([root(1), column("n", INT64, { 6: i32(22) })])],
    ["no repetition", metadata([root(1), element("n", { 1: i32(INT64) })])],
    ["a missing child", metadata([root(2), column("n", INT64)])],
    ["a second root", metadata([root(1), column("n", INT64), column("extra", INT64)])],
    ["an empty logical type", metadata([root(1), column("n", INT64, { 10: st({}) })])],
    ["two logical types", metadata([root(1), column("n", INT32, { 10: st({ 6: st({}), 1: st({}) }) })])],
    ["an unknown logical type on an integer", metadata([root(1), column("n", INT64, logical(40))])],
    ["a logical type unlike the converted one", metadata([root(1), column("n", INT32, { 6: i32(17), ...logical(6) })])],
    ["a string annotation on an integer", metadata([root(1), column("n", INT64, logical(1))])],
    ["an integer of 24 bits", metadata([root(1), column("n", INT32, logical(10, { 1: i32(24), 2: bool(true) }))])],
    ["a millisecond time on INT64", metadata([root(1), column("n", INT64, logical(7, { 1: bool(true), 2: st({ 1: st({}) }) }))])],
    ["a decimal without its scale and precision", metadata([root(1), column("n", INT64, logical(5, { 1: i32(2), 2: i32(10) }))])],
    ["a converted decimal without a precision", metadata([root(1), column("n", INT64, { 6: i32(5) })])],
    ["a fixed-length column without a length", metadata([root(1), column("n", 7)])],
    ["a MAP annotation on a primitive", metadata([root(1), column("n", BYTE_ARRAY, { 6: i32(1) })])],
  ];
  for (const [what, footer] of cases) {
    it(`refuses ${what}`, async () => {
      expect(await refusal(parquet(footer))).toBe("malformed_footer");
    });
  }

  it("refuses an integer annotation of 24 bits even on a nested column", async () => {
    const footer = metadata([
      root(1),
      element("group", { 3: REQUIRED, 5: i32(1), ...logical(10, { 1: i32(24), 2: bool(true) }) }),
      column("n", INT64),
    ]);
    expect(await refusal(parquet(footer))).toBe("malformed_footer");
  });
});

describe("declarations", () => {
  it("reads converted and logical annotations alike", async () => {
    const footer = metadata([
      root(4),
      column("plain", INT32),
      column("small", INT32, { 6: i32(15) }),
      column("text", BYTE_ARRAY, logical(1)),
      column("day", INT32, { 6: i32(6), ...logical(6) }),
    ]);
    expect(await readFooter(parquet(footer))).toEqual({
      ok: true,
      schema: [
        { name: "plain", type: "int32" },
        { name: "small", type: "int8" },
        { name: "text", type: "string" },
        { name: "day", type: "date" },
      ],
      rows: 3,
      footerBytes: expect.any(Number),
    });
  });

  it("counts rows as the enclave does: the larger of the file's and its row groups'", async () => {
    const schema = [root(1), column("n", INT64)];
    const groups = (...rows: number[]) => ls(rows.map((n) => st({ 1: ls([]), 2: i64(0), 3: i64(n) })));
    const read = (fileRows: number, ...groupRows: number[]) =>
      readFooter(parquet(st({ 1: i32(2), 2: ls(schema), 3: i64(fileRows), 4: groups(...groupRows) })));
    expect(await read(5, 2, 2)).toMatchObject({ ok: true, rows: 5 });
    expect(await read(1, 2, 2)).toMatchObject({ ok: true, rows: 4 });
    expect(await read(0)).toMatchObject({ ok: false, refusal: { code: "no_rows" } });
  });

  it("refuses more rows than a row cap holds", async () => {
    const footer = metadata([root(1), column("n", INT64)], 2n ** 53n);
    expect(await refusal(parquet(footer))).toBe("too_many_rows");
    const max = metadata([root(1), column("n", INT64)], 2n ** 53n - 1n);
    expect(await readFooter(parquet(max))).toMatchObject({ ok: true, rows: Number.MAX_SAFE_INTEGER });
  });

  it("refuses an empty schema", async () => {
    expect(await refusal(parquet(metadata([root(0)])))).toBe("no_columns");
  });

  it("names the column it refuses", async () => {
    const footer = metadata([root(2), column("n", INT64), column("blob", BYTE_ARRAY)]);
    expect(await readFooter(parquet(footer))).toEqual({
      ok: false,
      refusal: { code: "unsupported_type", column: "blob" },
    });
    const nested = metadata([root(1), element("tags", { 3: REPEATED, 1: i32(INT64) })]);
    expect(await readFooter(parquet(nested))).toEqual({
      ok: false,
      refusal: { code: "nested_column", column: "tags" },
    });
  });

  it("reads a column of 128-byte name and refuses a longer one", async () => {
    const at = (name: string) => readFooter(parquet(metadata([root(1), column(name, INT64)])));
    expect(await at("x".repeat(128))).toMatchObject({ ok: true });
    expect(await at("é".repeat(64))).toMatchObject({ ok: true });
    expect(await at("é".repeat(65))).toMatchObject({ ok: false, refusal: { code: "column_name" } });
  });
});

describe("what is read", () => {
  it("reads only the trailer and the footer", async () => {
    const bytes = fixture("families.parquet");
    const file = blob(bytes);
    const length = new DataView(bytes.buffer).getUint32(bytes.length - 8, true);
    const reads: Array<[number, number]> = [];
    const spy = {
      size: file.size,
      slice: (start?: number, end?: number) => {
        reads.push([start ?? 0, end ?? file.size]);
        return file.slice(start, end);
      },
    };
    const reading: FooterReading = await readFooter(spy);
    expect(reading.ok).toBe(true);
    expect(reads).toEqual([
      [file.size - 8, file.size],
      [file.size - 8 - length, file.size - 8],
    ]);
  });
});
