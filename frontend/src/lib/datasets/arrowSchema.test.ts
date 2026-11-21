// The embedded Arrow schema reader: real schemas from the fixtures, and
// flatbuffers built byte by byte for each refusal.

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { deserializeTCompactProtocol } from "hyparquet/src/thrift.js";

import { parquetFixture } from "../../test/parquetFixtures";
import { ArrowSchemaError, ArrowType, readArrowSchema } from "./arrowSchema";

/** The `ARROW:schema` value embedded in a fixture's footer. */
function embedded(name: string): string {
  const bytes = parquetFixture(name);
  const view = new DataView(bytes.buffer);
  const length = view.getUint32(bytes.length - 8, true);
  const footer = new DataView(bytes.buffer, bytes.length - 8 - length, length);
  const metadata = deserializeTCompactProtocol({ view: footer, offset: 0 });
  const decode = (b: Uint8Array) => new TextDecoder().decode(b);
  const kv = (metadata.field_5 as Array<Record<string, Uint8Array>>).find(
    (entry) => decode(entry.field_1!) === "ARROW:schema",
  );
  return decode(kv!.field_2!);
}

// ── A flatbuffer writer, laid out front to back: every table's vtable
//    precedes it and every child follows its parent. ──

type Scalar = { size: 1 | 2 | 4; value: number };
type Child = () => number;
type Slot = Scalar | { child: Child };

class Writer {
  readonly bytes: number[] = [0, 0, 0, 0];

  pad(n: number): void {
    while (this.bytes.length % n) this.bytes.push(0);
  }

  put(size: number, value: number): void {
    for (let i = 0; i < size; i += 1) this.bytes.push((value >>> (8 * i)) & 0xff);
  }

  set32(at: number, value: number): void {
    for (let i = 0; i < 4; i += 1) this.bytes[at + i] = (value >>> (8 * i)) & 0xff;
  }

  table(slots: Array<Slot | undefined>): number {
    this.pad(2);
    const vtable = this.bytes.length;
    const vtableSize = 4 + 2 * slots.length;
    this.bytes.push(...new Array<number>(vtableSize).fill(0));
    this.pad(4);
    const table = this.bytes.length;
    this.put(4, table - vtable);
    const offsets: number[] = [];
    const children: Array<[number, Child]> = [];
    slots.forEach((slot, i) => {
      if (!slot) return;
      const size = "child" in slot ? 4 : slot.size;
      this.pad(size);
      offsets[i] = this.bytes.length - table;
      if ("child" in slot) {
        children.push([this.bytes.length, slot.child]);
        this.put(4, 0);
      } else {
        this.put(size, slot.value);
      }
    });
    this.pad(4);
    const write16 = (at: number, v: number) => {
      this.bytes[at] = v & 0xff;
      this.bytes[at + 1] = (v >> 8) & 0xff;
    };
    write16(vtable, vtableSize);
    write16(vtable + 2, this.bytes.length - table);
    offsets.forEach((offset, i) => write16(vtable + 4 + 2 * i, offset ?? 0));
    for (const [at, child] of children) this.set32(at, child() - at);
    return table;
  }

  string(text: string, terminator = 0): number {
    this.pad(4);
    const at = this.bytes.length;
    const bytes = new TextEncoder().encode(text);
    this.put(4, bytes.length);
    this.bytes.push(...bytes, terminator);
    return at;
  }

  vector(children: Child[]): number {
    this.pad(4);
    const at = this.bytes.length;
    this.put(4, children.length);
    const slots = children.map(() => {
      const slot = this.bytes.length;
      this.put(4, 0);
      return slot;
    });
    children.forEach((child, i) => this.set32(slots[i]!, child() - slots[i]!));
    return at;
  }
}

interface FieldSpec {
  name?: string;
  tag: number;
  /** The type table's slots; omitted means no table. */
  type?: Array<Slot | undefined>;
  /** The dictionary's index type slots, for a dictionary-encoded field. */
  dictionaryIndex?: Array<Slot | undefined>;
}

const u8 = (value: number): Scalar => ({ size: 1, value });
const i16 = (value: number): Scalar => ({ size: 2, value });
const i32 = (value: number): Scalar => ({ size: 4, value });

/** A base64 Arrow IPC schema message over `fields`. */
function schema(
  fields: FieldSpec[],
  { header = 1, endianness = 0, continuation = false } = {},
): string {
  const w = new Writer();
  const field = (spec: FieldSpec) => () =>
    w.table([
      spec.name === undefined ? undefined : { child: () => w.string(spec.name!) },
      undefined,
      u8(spec.tag),
      spec.type ? { child: () => w.table(spec.type!) } : undefined,
      spec.dictionaryIndex
        ? { child: () => w.table([undefined, { child: () => w.table(spec.dictionaryIndex!) }]) }
        : undefined,
    ]);
  const message = w.table([
    i16(4),
    u8(header),
    {
      child: () =>
        w.table([i16(endianness), { child: () => w.vector(fields.map(field)) }]),
    },
  ]);
  w.set32(0, message);
  let bytes = Uint8Array.from(w.bytes);
  if (continuation) {
    const prefixed = new Uint8Array(bytes.length + 8);
    prefixed.set([0xff, 0xff, 0xff, 0xff], 0);
    new DataView(prefixed.buffer).setUint32(4, bytes.length, true);
    prefixed.set(bytes, 8);
    bytes = prefixed;
  }
  return btoa(String.fromCharCode(...bytes));
}

const int64: FieldSpec = { name: "n", tag: ArrowType.Int, type: [i32(64), u8(1)] };

describe("schemas Arrow writers embed", () => {
  it("reads every field's name and what its type can refine", () => {
    const fields = readArrowSchema(embedded("families.parquet"));
    const kinds = Object.fromEntries(fields.map((f) => [f.name, f.kind]));
    expect(fields).toHaveLength(28);
    expect(kinds).toMatchObject({
      flag: "other",
      i64: "other",
      name: "string",
      large_name: "string",
      view_name: "string",
      // Dictionary-encoded: the value type counts.
      category: "string",
      codes: "other",
      day: "date32",
      day_ms: "date64",
      at_s: "timestamp",
      at_ms_utc: "timestamp",
      huge: "other",
      größe: "other",
      名前: "string",
    });
  });

  it("reads time and duration fields", () => {
    expect(readArrowSchema(embedded("time32-seconds.parquet"))[1]).toEqual({ name: "at", kind: "time32" });
    expect(readArrowSchema(embedded("time64.parquet"))[1]).toEqual({ name: "at", kind: "time64" });
    expect(readArrowSchema(embedded("duration.parquet"))[1]).toEqual({ name: "took", kind: "duration" });
  });

  it("reads a message with or without the continuation marker", () => {
    for (const continuation of [false, true]) {
      expect(readArrowSchema(schema([int64], { continuation }))).toEqual([{ name: "n", kind: "other" }]);
    }
  });

  it("reads a field without a name as the enclave does, as an empty name", () => {
    expect(readArrowSchema(schema([{ tag: ArrowType.Utf8 }]))).toEqual([{ name: "", kind: "string" }]);
  });

  it("reads the default date unit as milliseconds", () => {
    expect(readArrowSchema(schema([{ name: "d", tag: ArrowType.Date, type: [] }]))).toEqual([
      { name: "d", kind: "date64" },
    ]);
  });
});

describe("refusals", () => {
  const refuses = (encoded: string) => () => readArrowSchema(encoded);
  const cases: Array<[string, string]> = [
    ["text that is not base64", "%%%"],
    ["base64 without padding", btoa("ABCD").replace(/=+$/, "")],
    ["base64 with stray bits", "QR=="],
    ["an empty buffer", ""],
    ["a message that is not a schema", schema([int64], { header: 3 })],
    ["a message with no header", schema([int64], { header: 0 })],
    ["an unknown type", schema([{ name: "x", tag: 99 }])],
    ["no type at all", schema([{ name: "x", tag: 0 }])],
    ["an integer without its table", schema([{ name: "x", tag: ArrowType.Int }])],
    ["an integer of 24 bits", schema([{ name: "x", tag: ArrowType.Int, type: [i32(24), u8(1)] }])],
    ["a float of unknown precision", schema([{ name: "x", tag: ArrowType.FloatingPoint, type: [i16(3)] }])],
    ["a date of unknown unit", schema([{ name: "x", tag: ArrowType.Date, type: [i16(2)] }])],
    ["a time of 32 bits in microseconds", schema([{ name: "x", tag: ArrowType.Time, type: [i16(2), i32(32)] }])],
    ["a time of 64 bits in seconds", schema([{ name: "x", tag: ArrowType.Time, type: [i16(0), i32(64)] }])],
    ["a timestamp of unknown unit", schema([{ name: "x", tag: ArrowType.Timestamp, type: [i16(4)] }])],
    ["a duration of unknown unit", schema([{ name: "x", tag: ArrowType.Duration, type: [i16(-1)] }])],
    ["a decimal of 100 bits", schema([{ name: "x", tag: ArrowType.Decimal, type: [i32(10), i32(2), i32(100)] }])],
    ["a decimal of 300 digits", schema([{ name: "x", tag: ArrowType.Decimal, type: [i32(300), i32(2)] }])],
    [
      "a big-endian decimal",
      schema([{ name: "x", tag: ArrowType.Decimal, type: [i32(10), i32(2)] }], { endianness: 1 }),
    ],
    [
      "a dictionary with a 24-bit index",
      schema([{ name: "x", tag: ArrowType.Utf8, dictionaryIndex: [i32(24), u8(1)] }]),
    ],
  ];
  for (const [what, encoded] of cases) {
    it(`refuses ${what}`, () => {
      expect(refuses(encoded)).toThrow(ArrowSchemaError);
    });
  }

  it("refuses a string without its terminator or not UTF-8", () => {
    const valid = Uint8Array.from(atob(schema([{ name: "abc", tag: ArrowType.Utf8 }])), (c) => c.charCodeAt(0));
    const name = valid.findIndex((_, i) => valid[i] === 0x61 && valid[i + 1] === 0x62 && valid[i + 2] === 0x63);
    const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
    const unterminated = valid.slice();
    unterminated[name + 3] = 0x21;
    expect(refuses(encode(unterminated))).toThrow(ArrowSchemaError);
    const notUtf8 = valid.slice();
    notUtf8[name] = 0xc3;
    notUtf8[name + 1] = 0x28;
    expect(refuses(encode(notUtf8))).toThrow(ArrowSchemaError);
  });

  it("refuses an offset out of bounds or unaligned", () => {
    const valid = Uint8Array.from(atob(schema([int64])), (c) => c.charCodeAt(0));
    const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
    const out = valid.slice();
    new DataView(out.buffer).setUint32(0, valid.length + 4, true);
    expect(refuses(encode(out))).toThrow(ArrowSchemaError);
    const unaligned = valid.slice();
    new DataView(unaligned.buffer).setUint32(0, new DataView(valid.buffer).getUint32(0, true) + 1, true);
    expect(refuses(encode(unaligned))).toThrow(ArrowSchemaError);
    expect(refuses(encode(valid.subarray(0, valid.length - 8)))).toThrow(ArrowSchemaError);
  });

  it("throws nothing but its own error on arbitrary bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 256 }), (bytes) => {
        try {
          readArrowSchema(btoa(String.fromCharCode(...bytes)));
        } catch (err) {
          expect(err).toBeInstanceOf(ArrowSchemaError);
        }
      }),
      { numRuns: 500 },
    );
  });
});
