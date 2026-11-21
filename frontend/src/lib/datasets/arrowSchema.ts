// The Arrow schema that Arrow writers embed in a Parquet footer, under the
// `ARROW:schema` key: a base64 Arrow IPC message whose header is a Schema
// flatbuffer (Arrow's Message.fbs and Schema.fbs). The enclave's Parquet
// reader uses it to refine some columns' types (parquet-rs `apply_hint`),
// and a few refinements change a column's type family, so the browser reads
// the top-level fields' names and types the same way before it declares a
// schema (ADR 0014). It reads nothing else.
//
// The reader refuses rather than guesses. The enclave cannot open a file
// whose embedded schema it cannot decode (parquet-rs fails the whole file),
// so anything malformed, out of bounds, unaligned or of a type the enclave
// would not accept throws an `ArrowSchemaError`, and the upload is refused
// before anything is sealed.

/** Arrow `Type` union tags (Schema.fbs). */
export const ArrowType = {
  Null: 1,
  Int: 2,
  FloatingPoint: 3,
  Binary: 4,
  Utf8: 5,
  Bool: 6,
  Decimal: 7,
  Date: 8,
  Time: 9,
  Timestamp: 10,
  Interval: 11,
  List: 12,
  Struct: 13,
  Union: 14,
  FixedSizeBinary: 15,
  FixedSizeList: 16,
  Map: 17,
  Duration: 18,
  LargeBinary: 19,
  LargeUtf8: 20,
  LargeList: 21,
  RunEndEncoded: 22,
  BinaryView: 23,
  Utf8View: 24,
  ListView: 25,
  LargeListView: 26,
} as const;

/** What a field's type can change about a column's family. Every other
 *  type is `other`: no hint of it changes a family. */
export type HintKind =
  | "timestamp"
  | "date32"
  | "date64"
  | "time32"
  | "time64"
  | "duration"
  | "string"
  | "other";

export interface HintField {
  /** The field's name; an absent name reads as "", as the enclave reads it. */
  name: string;
  /** The field's type, or its value type when dictionary-encoded. */
  kind: HintKind;
}

export class ArrowSchemaError extends Error {
  constructor(what: string) {
    super(`embedded Arrow schema: ${what}`);
    this.name = "ArrowSchemaError";
  }
}

const MESSAGE_HEADER_SCHEMA = 1;
const ENDIANNESS_BIG = 1;
// Arrow enums (Schema.fbs).
const DATE_DAY = 0;
const DATE_MILLISECOND = 1;
const UNIT_SECOND = 0;
const UNIT_MILLISECOND = 1;
const UNIT_MICROSECOND = 2;
const UNIT_NANOSECOND = 3;

/** Strict standard base64, padded and canonical, as the enclave's reader
 *  requires (`base64` crate, `STANDARD` engine). */
function decodeBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new ArrowSchemaError("not base64");
  }
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new ArrowSchemaError("not base64");
  }
  // Re-encoding gives back the input only when no bits trail the last byte.
  if (btoa(binary) !== text) throw new ArrowSchemaError("not canonical base64");
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

interface Table {
  pos: number;
  vtable: number;
  vtableSize: number;
  tableSize: number;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Bounds- and alignment-checked reads of one flatbuffer. */
class Flatbuffer {
  private readonly view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  private at(pos: number, size: number): number {
    if (!Number.isSafeInteger(pos) || pos < 0 || pos + size > this.bytes.length) {
      throw new ArrowSchemaError("out of bounds");
    }
    if (pos % size !== 0) throw new ArrowSchemaError("unaligned");
    return pos;
  }

  u8(pos: number): number {
    return this.view.getUint8(this.at(pos, 1));
  }

  i16(pos: number): number {
    return this.view.getInt16(this.at(pos, 2), true);
  }

  u16(pos: number): number {
    return this.view.getUint16(this.at(pos, 2), true);
  }

  i32(pos: number): number {
    return this.view.getInt32(this.at(pos, 4), true);
  }

  u32(pos: number): number {
    return this.view.getUint32(this.at(pos, 4), true);
  }

  table(pos: number): Table {
    const vtable = pos - this.i32(pos);
    const vtableSize = this.u16(vtable);
    const tableSize = this.u16(vtable + 2);
    if (vtableSize < 4 || vtableSize % 2 !== 0 || tableSize < 4) {
      throw new ArrowSchemaError("malformed table");
    }
    // Both lie inside the buffer: their last bytes are readable.
    this.u8(vtable + vtableSize - 1);
    this.u8(pos + tableSize - 1);
    return { pos, vtable, vtableSize, tableSize };
  }

  /** The offset of field `slot` inside table `t`, or 0 when it is absent. */
  private field(t: Table, slot: number, size: number): number {
    const entry = 4 + 2 * slot;
    if (entry + 2 > t.vtableSize) return 0;
    const offset = this.u16(t.vtable + entry);
    if (offset !== 0 && offset + size > t.tableSize) throw new ArrowSchemaError("field outside its table");
    return offset;
  }

  scalarU8(t: Table, slot: number, fallback: number): number {
    const offset = this.field(t, slot, 1);
    return offset === 0 ? fallback : this.u8(t.pos + offset);
  }

  scalarI16(t: Table, slot: number, fallback: number): number {
    const offset = this.field(t, slot, 2);
    return offset === 0 ? fallback : this.i16(t.pos + offset);
  }

  scalarI32(t: Table, slot: number, fallback: number): number {
    const offset = this.field(t, slot, 4);
    return offset === 0 ? fallback : this.i32(t.pos + offset);
  }

  /** Where field `slot`'s offset points, or null when it is absent. */
  private target(t: Table, slot: number): number | null {
    const offset = this.field(t, slot, 4);
    if (offset === 0) return null;
    const pos = t.pos + offset;
    const relative = this.u32(pos);
    if (relative === 0) throw new ArrowSchemaError("null offset");
    return pos + relative;
  }

  childTable(t: Table, slot: number): Table | null {
    const pos = this.target(t, slot);
    return pos === null ? null : this.table(pos);
  }

  string(t: Table, slot: number): string | null {
    const pos = this.target(t, slot);
    if (pos === null) return null;
    const length = this.u32(pos);
    const start = pos + 4;
    // The string is followed by a NUL, which the enclave's verifier requires.
    if (start + length >= this.bytes.length || this.bytes[start + length] !== 0) {
      throw new ArrowSchemaError("malformed string");
    }
    try {
      return utf8.decode(this.bytes.subarray(start, start + length));
    } catch {
      throw new ArrowSchemaError("string is not UTF-8");
    }
  }

  tables(t: Table, slot: number): Table[] | null {
    const pos = this.target(t, slot);
    if (pos === null) return null;
    const count = this.u32(pos);
    // Every element is a 4-byte offset, all inside the buffer.
    if (pos + 4 + 4 * count > this.bytes.length) throw new ArrowSchemaError("malformed vector");
    const out: Table[] = [];
    for (let i = 0; i < count; i += 1) {
      const at = pos + 4 + 4 * i;
      const relative = this.u32(at);
      if (relative === 0) throw new ArrowSchemaError("null offset");
      out.push(this.table(at + relative));
    }
    return out;
  }
}

/** An `Int` type table (Schema.fbs `Int`): a bit width the enclave reads. */
function checkInt(fb: Flatbuffer, int: Table | null): void {
  if (!int) throw new ArrowSchemaError("integer type without its table");
  const bitWidth = fb.scalarI32(int, 0, 0);
  if (![8, 16, 32, 64].includes(bitWidth)) throw new ArrowSchemaError("integer bit width");
}

/** A field's type, as far as the type families need it. Throws on a type
 *  the enclave's Arrow reader would not accept (arrow-ipc panics or
 *  refuses on each of these). */
function fieldKind(fb: Flatbuffer, field: Table, bigEndian: boolean): HintKind {
  const dictionary = fb.childTable(field, 4);
  if (dictionary) checkInt(fb, fb.childTable(dictionary, 1));
  const tag = fb.scalarU8(field, 2, 0);
  const type = fb.childTable(field, 3);
  const unit = (fallback: number) => {
    if (!type) throw new ArrowSchemaError("type without its table");
    return fb.scalarI16(type, 0, fallback);
  };
  const timeUnit = (value: number) => {
    if (value < UNIT_SECOND || value > UNIT_NANOSECOND) throw new ArrowSchemaError("time unit");
    return value;
  };
  switch (tag) {
    case ArrowType.Int:
      checkInt(fb, type);
      return "other";
    case ArrowType.FloatingPoint: {
      const precision = unit(0);
      if (precision < 0 || precision > 2) throw new ArrowSchemaError("float precision");
      return "other";
    }
    case ArrowType.Decimal: {
      if (!type) throw new ArrowSchemaError("decimal type without its table");
      const precision = fb.scalarI32(type, 0, 0);
      const scale = fb.scalarI32(type, 1, 0);
      const bitWidth = fb.scalarI32(type, 2, 128);
      if (precision < 0 || precision > 255 || scale < -128 || scale > 127) {
        throw new ArrowSchemaError("decimal precision or scale");
      }
      if (![32, 64, 128, 256].includes(bitWidth)) throw new ArrowSchemaError("decimal bit width");
      if (bigEndian) throw new ArrowSchemaError("big-endian decimal");
      return "other";
    }
    case ArrowType.Date: {
      const value = unit(DATE_MILLISECOND);
      if (value === DATE_DAY) return "date32";
      if (value === DATE_MILLISECOND) return "date64";
      throw new ArrowSchemaError("date unit");
    }
    case ArrowType.Time: {
      const value = unit(UNIT_MILLISECOND);
      const bitWidth = fb.scalarI32(type!, 1, 32);
      if (bitWidth === 32 && (value === UNIT_SECOND || value === UNIT_MILLISECOND)) return "time32";
      if (bitWidth === 64 && (value === UNIT_MICROSECOND || value === UNIT_NANOSECOND)) return "time64";
      throw new ArrowSchemaError("time unit or bit width");
    }
    case ArrowType.Timestamp:
      timeUnit(unit(UNIT_SECOND));
      return "timestamp";
    case ArrowType.Duration:
      timeUnit(unit(UNIT_MILLISECOND));
      return "duration";
    case ArrowType.Utf8:
    case ArrowType.LargeUtf8:
    case ArrowType.Utf8View:
      return "string";
    default:
      if (tag < ArrowType.Null || tag > ArrowType.LargeListView) {
        throw new ArrowSchemaError("unknown type");
      }
      return "other";
  }
}

/** The top-level fields of the Arrow schema embedded as `encoded`. Throws
 *  an `ArrowSchemaError` when it is not one the enclave's reader decodes. */
export function readArrowSchema(encoded: string): HintField[] {
  let bytes = decodeBase64(encoded);
  // An IPC message may start with the 0xFFFFFFFF continuation marker and
  // its length, which the enclave's reader skips the same way.
  if (bytes.length > 8 && bytes[0] === 0xff && bytes[1] === 0xff && bytes[2] === 0xff && bytes[3] === 0xff) {
    bytes = bytes.subarray(8);
  }
  // The flatbuffer's offsets and alignment count from its own start.
  const fb = new Flatbuffer(bytes.slice());
  const message = fb.table(fb.u32(0));
  if (fb.scalarU8(message, 1, 0) !== MESSAGE_HEADER_SCHEMA) {
    throw new ArrowSchemaError("message is not a schema");
  }
  const schema = fb.childTable(message, 2);
  if (!schema) throw new ArrowSchemaError("schema message without a schema");
  const bigEndian = fb.scalarI16(schema, 0, 0) === ENDIANNESS_BIG;
  const fields = fb.tables(schema, 1);
  if (!fields) throw new ArrowSchemaError("schema without fields");
  return fields.map((field) => ({
    name: fb.string(field, 0) ?? "",
    kind: fieldKind(fb, field, bigEndian),
  }));
}
