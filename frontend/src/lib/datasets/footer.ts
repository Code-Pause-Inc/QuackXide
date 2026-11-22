// The schema and row count an upload declares, read from its Parquet footer
// before anything is sealed (ADR 0014).
//
// Only the tail of the file is read (`Blob.slice`): the 8-byte trailer, then
// the footer it points to, at most FOOTER_MAX_BYTES. The footer's Thrift
// encoding is decoded by hyparquet's compact-protocol reader; this module
// interprets the result itself and reads only the schema, the row counts and
// the embedded Arrow schema. Column statistics, which hold plaintext values,
// are never decoded.
//
// The enclave checks an upload's Parquet against what the browser declares
// (`QueryScope::register_parquet_declared`): its Parquet reader (parquet-rs)
// turns the footer's schema into Arrow types, refined by the embedded Arrow
// schema, and `quackxide_engine::column_type_of` maps each to a family. A
// declaration they disagree on makes every query of the dataset fail, and
// the first upload fixes a dataset's schema (ADR 0012), so this module
// follows the same rules and refuses whatever parquet-rs would refuse or map
// to no family. `fixtures/parquet/schema-vectors.json` holds files both
// sides must read alike. The check is advisory all the same: the enclave
// checks the decrypted data again.
//
// No DOM or worker globals: it runs in the footer worker and under tests.

import { deserializeTCompactProtocol } from "hyparquet/src/thrift.js";

import { ArrowSchemaError, readArrowSchema, type HintField, type HintKind } from "./arrowSchema";
import {
  declarationProblem,
  isRowCap,
  type ColumnType,
  type DeclarationProblem,
  type DeclaredColumn,
} from "./schema";

/** Largest footer the browser reads. Footers of real files are kilobytes
 *  to a few megabytes; a larger length is a corrupt file. */
export const FOOTER_MAX_BYTES = 16 * 1024 * 1024;

/** The 8-byte trailer: the footer's length, then the magic. */
const TRAILER_BYTES = 8;
const MAGIC = "PAR1";
const MAGIC_ENCRYPTED_FOOTER = "PARE";

/** Why a file cannot be uploaded as it is. Each is refused before sealing. */
export type FooterRefusal =
  | { code: "not_parquet" }
  | { code: "encrypted" }
  | { code: "footer_length" }
  | { code: "footer_too_large" }
  | { code: "malformed_footer" }
  | { code: "arrow_schema" }
  | { code: "nested_column"; column: string }
  | { code: "unsupported_type"; column: string }
  | DeclarationProblem
  | { code: "no_rows" }
  | { code: "too_many_rows" };

export type FooterReading =
  | {
      ok: true;
      /** The declared schema: every column's name and type family. */
      schema: DeclaredColumn[];
      /** The rows the footer reports: the larger of the file's count and
       *  its row groups' sum, as the enclave counts them. */
      rows: number;
      /** The footer's length in bytes. */
      footerBytes: number;
    }
  | { ok: false; refusal: FooterRefusal };

/** Thrown inside this module for a footer parquet-rs would not read. */
class Malformed extends Error {}

/** Thrown inside this module for any other refusal. */
class Refused extends Error {
  constructor(readonly refusal: FooterRefusal) {
    super(refusal.code);
  }
}

// ── Thrift values, as hyparquet's decoder returns them ──

type Thrift = Record<string, unknown>;

function struct(value: unknown): Thrift {
  if (typeof value !== "object" || value === null || Array.isArray(value) || value instanceof Uint8Array) {
    throw new Malformed();
  }
  return value as Thrift;
}

function list(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Malformed();
  return value;
}

function int(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Malformed();
  return value;
}

function optionalInt(value: unknown): number | undefined {
  return value === undefined ? undefined : int(value);
}

function long(value: unknown): bigint {
  if (typeof value !== "bigint") throw new Malformed();
  return value;
}

function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Malformed();
  return value;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/** A Thrift string, which parquet-rs requires to be UTF-8. */
function text(value: unknown): string {
  if (!(value instanceof Uint8Array)) throw new Malformed();
  try {
    return strictUtf8.decode(value);
  } catch {
    throw new Malformed();
  }
}

// ── The Parquet schema (parquet-format `SchemaElement`, `LogicalType`) ──

const enum Physical {
  BOOLEAN = 0,
  INT32 = 1,
  INT64 = 2,
  INT96 = 3,
  FLOAT = 4,
  DOUBLE = 5,
  BYTE_ARRAY = 6,
  FIXED_LEN_BYTE_ARRAY = 7,
}

const enum Repetition {
  REQUIRED = 0,
  OPTIONAL = 1,
  REPEATED = 2,
}

/** `ConvertedType`, with parquet-rs's NONE (-1) for an absent one. */
const enum Converted {
  NONE = -1,
  UTF8 = 0,
  MAP = 1,
  MAP_KEY_VALUE = 2,
  LIST = 3,
  ENUM = 4,
  DECIMAL = 5,
  DATE = 6,
  TIME_MILLIS = 7,
  TIME_MICROS = 8,
  TIMESTAMP_MILLIS = 9,
  TIMESTAMP_MICROS = 10,
  UINT_8 = 11,
  UINT_16 = 12,
  UINT_32 = 13,
  UINT_64 = 14,
  INT_8 = 15,
  INT_16 = 16,
  INT_32 = 17,
  INT_64 = 18,
  JSON = 19,
  BSON = 20,
  INTERVAL = 21,
}

type TimeUnit = "MILLIS" | "MICROS" | "NANOS";

/** A `LogicalType` union member, as parquet-rs reads it: a member this
 *  version of the format does not know is `_Unknown`. */
type EmptyLogical =
  | "String"
  | "Map"
  | "List"
  | "Enum"
  | "Date"
  | "Unknown"
  | "Json"
  | "Bson"
  | "Uuid"
  | "Float16";

type Logical =
  | { kind: EmptyLogical }
  | { kind: "Variant" | "Geometry" | "Geography" | "_Unknown" }
  | { kind: "Decimal"; scale: number; precision: number }
  | { kind: "Time"; unit: TimeUnit }
  | { kind: "Timestamp"; unit: TimeUnit; adjusted: boolean }
  | { kind: "Integer"; bitWidth: number; signed: boolean };

interface Element {
  name: string;
  physical: Physical | undefined;
  typeLength: number;
  repetition: Repetition | undefined;
  numChildren: number | undefined;
  converted: Converted;
  scale: number;
  precision: number;
  logical: Logical | undefined;
}

function timeUnit(value: unknown): TimeUnit {
  const unit = struct(value);
  const keys = Object.keys(unit);
  if (keys.length !== 1) throw new Malformed();
  if ("field_1" in unit) return "MILLIS";
  if ("field_2" in unit) return "MICROS";
  if ("field_3" in unit) return "NANOS";
  throw new Malformed();
}

function logicalType(value: unknown): Logical {
  const union = struct(value);
  const keys = Object.keys(union);
  // A union holds exactly one member.
  if (keys.length !== 1) throw new Malformed();
  const member = union[keys[0]!];
  const empty = (kind: EmptyLogical): Logical => {
    struct(member);
    return { kind };
  };
  switch (keys[0]) {
    case "field_1":
      return empty("String");
    case "field_2":
      return empty("Map");
    case "field_3":
      return empty("List");
    case "field_4":
      return empty("Enum");
    case "field_5": {
      const decimal = struct(member);
      return { kind: "Decimal", scale: int(decimal.field_1), precision: int(decimal.field_2) };
    }
    case "field_6":
      return empty("Date");
    case "field_7": {
      const time = struct(member);
      bool(time.field_1);
      return { kind: "Time", unit: timeUnit(time.field_2) };
    }
    case "field_8": {
      const timestamp = struct(member);
      return { kind: "Timestamp", adjusted: bool(timestamp.field_1), unit: timeUnit(timestamp.field_2) };
    }
    case "field_10": {
      const integer = struct(member);
      return { kind: "Integer", bitWidth: int(integer.field_1), signed: bool(integer.field_2) };
    }
    case "field_11":
      return empty("Unknown");
    case "field_12":
      return empty("Json");
    case "field_13":
      return empty("Bson");
    case "field_14":
      return empty("Uuid");
    case "field_15":
      return empty("Float16");
    case "field_16":
      struct(member);
      return { kind: "Variant" };
    case "field_17":
      struct(member);
      return { kind: "Geometry" };
    case "field_18":
      struct(member);
      return { kind: "Geography" };
    default:
      // A newer member: parquet-rs skips it and reads `_Unknown`.
      return { kind: "_Unknown" };
  }
}

function enumValue<T extends number>(value: unknown, max: number): T | undefined {
  if (value === undefined) return undefined;
  const n = int(value);
  if (n < 0 || n > max) throw new Malformed();
  return n as T;
}

function schemaElement(value: unknown): Element {
  const el = struct(value);
  const converted = el.field_6 === undefined ? Converted.NONE : int(el.field_6);
  if (converted < Converted.NONE || converted > Converted.INTERVAL) throw new Malformed();
  const numChildren = optionalInt(el.field_5);
  if (numChildren !== undefined && numChildren < 0) throw new Malformed();
  return {
    name: text(el.field_4),
    physical: enumValue<Physical>(el.field_1, Physical.FIXED_LEN_BYTE_ARRAY),
    typeLength: optionalInt(el.field_2) ?? -1,
    repetition: enumValue<Repetition>(el.field_3, Repetition.REPEATED),
    numChildren,
    converted: converted as Converted,
    scale: optionalInt(el.field_7) ?? -1,
    precision: optionalInt(el.field_8) ?? -1,
    logical: el.field_10 === undefined ? undefined : logicalType(el.field_10),
  };
}

/** The converted type parquet-rs derives from a logical type
 *  (`From<Option<LogicalType>> for ConvertedType`). */
function convertedOf(logical: Logical): Converted {
  switch (logical.kind) {
    case "String":
      return Converted.UTF8;
    case "Map":
      return Converted.MAP;
    case "List":
      return Converted.LIST;
    case "Enum":
      return Converted.ENUM;
    case "Decimal":
      return Converted.DECIMAL;
    case "Date":
      return Converted.DATE;
    case "Time":
      return logical.unit === "MILLIS"
        ? Converted.TIME_MILLIS
        : logical.unit === "MICROS"
          ? Converted.TIME_MICROS
          : Converted.NONE;
    case "Timestamp":
      return logical.unit === "MILLIS"
        ? Converted.TIMESTAMP_MILLIS
        : logical.unit === "MICROS"
          ? Converted.TIMESTAMP_MICROS
          : Converted.NONE;
    case "Integer": {
      const signed: Record<number, Converted> = {
        8: Converted.INT_8,
        16: Converted.INT_16,
        32: Converted.INT_32,
        64: Converted.INT_64,
      };
      const unsigned: Record<number, Converted> = {
        8: Converted.UINT_8,
        16: Converted.UINT_16,
        32: Converted.UINT_32,
        64: Converted.UINT_64,
      };
      return (logical.signed ? signed : unsigned)[logical.bitWidth] ?? Converted.NONE;
    }
    case "Json":
      return Converted.JSON;
    case "Bson":
      return Converted.BSON;
    default:
      return Converted.NONE;
  }
}

/** parquet-rs's checks when it builds a primitive column from the footer
 *  (`PrimitiveTypeBuilder::build`): a failure makes the file unreadable. */
function checkAnnotations(el: Element): void {
  const { physical, logical, converted, typeLength } = el;
  if (physical === Physical.FIXED_LEN_BYTE_ARRAY && typeLength < 0) throw new Malformed();
  const decimalPhysical =
    physical === Physical.INT32 ||
    physical === Physical.INT64 ||
    physical === Physical.BYTE_ARRAY ||
    physical === Physical.FIXED_LEN_BYTE_ARRAY;
  if (logical) {
    if (converted !== Converted.NONE && convertedOf(logical) !== converted) throw new Malformed();
    const ok = (() => {
      switch (logical.kind) {
        case "Map":
        case "List":
          return false;
        case "Enum":
        case "String":
        case "Json":
        case "Bson":
        case "Geometry":
        case "Geography":
          return physical === Physical.BYTE_ARRAY;
        case "Decimal":
          return logical.scale === el.scale && logical.precision === el.precision && decimalPhysical;
        case "Date":
          return physical === Physical.INT32;
        case "Time":
          return (
            (physical === Physical.INT32 && logical.unit === "MILLIS") ||
            (physical === Physical.INT64 && logical.unit !== "MILLIS")
          );
        case "Timestamp":
          return physical === Physical.INT64;
        case "Integer":
          return (
            (physical === Physical.INT32 && logical.bitWidth <= 32) ||
            (physical === Physical.INT64 && logical.bitWidth === 64)
          );
        case "Unknown":
        case "_Unknown":
          return true;
        case "Uuid":
          return physical === Physical.FIXED_LEN_BYTE_ARRAY && typeLength === 16;
        case "Float16":
          return physical === Physical.FIXED_LEN_BYTE_ARRAY && typeLength === 2;
        default:
          return false;
      }
    })();
    if (!ok) throw new Malformed();
  }
  if (logical?.kind === "Decimal" || converted === Converted.DECIMAL) checkDecimal(el);
  switch (converted) {
    case Converted.NONE:
      return;
    case Converted.UTF8:
    case Converted.BSON:
    case Converted.JSON:
    case Converted.ENUM:
      if (physical !== Physical.BYTE_ARRAY) throw new Malformed();
      return;
    case Converted.DECIMAL:
      if (!decimalPhysical) throw new Malformed();
      return;
    case Converted.DATE:
    case Converted.TIME_MILLIS:
    case Converted.UINT_8:
    case Converted.UINT_16:
    case Converted.UINT_32:
    case Converted.INT_8:
    case Converted.INT_16:
    case Converted.INT_32:
      if (physical !== Physical.INT32) throw new Malformed();
      return;
    case Converted.TIME_MICROS:
    case Converted.TIMESTAMP_MILLIS:
    case Converted.TIMESTAMP_MICROS:
    case Converted.UINT_64:
    case Converted.INT_64:
      if (physical !== Physical.INT64) throw new Malformed();
      return;
    case Converted.INTERVAL:
      if (physical !== Physical.FIXED_LEN_BYTE_ARRAY || typeLength !== 12) throw new Malformed();
      return;
    default:
      // MAP, MAP_KEY_VALUE and LIST annotate groups only.
      throw new Malformed();
  }
}

/** parquet-rs `check_decimal_precision_scale`: a precision of at least 1, a
 *  scale from 0 to the precision, and a precision the physical type holds
 *  (9 digits in `INT32`, 18 in `INT64`, and what a fixed length's signed
 *  value holds). `BYTE_ARRAY` has no limit. A logical decimal's precision
 *  and scale equal the element's (`checkAnnotations`). */
function checkDecimal({ physical, precision, scale, typeLength }: Element): void {
  if (precision < 1 || scale < 0 || scale > precision) throw new Malformed();
  if (physical === Physical.INT32 && precision > 9) throw new Malformed();
  if (physical === Physical.INT64 && precision > 18) throw new Malformed();
  if (physical === Physical.FIXED_LEN_BYTE_ARRAY) {
    const max = Math.floor(Math.log10(2 ** (8 * typeLength - 1) - 1));
    if (precision > max) throw new Malformed();
  }
}

/** The Arrow type a primitive column reads as, where it matters for its
 *  family. `int32`, `int64` and `binary` are kept apart because the
 *  embedded Arrow schema can refine exactly those into another family. */
type Kind =
  | { family: ColumnType; arrow?: "int32" | "int64" | "date32" }
  | { family: null; arrow?: "binary" };

/** A decimal's precision and scale fit Arrow's `u8` and `i8`. */
function decimal(precision: number, scale: number): Kind {
  if (precision < 0 || precision > 255 || scale < -128 || scale > 127) throw new Malformed();
  return { family: "decimal" };
}

/** parquet-rs `from_parquet` and its `from_*` helpers, reduced to the
 *  family of the Arrow type they return. Each `Malformed` is one of their
 *  errors. */
function kindOf(el: Element): Kind {
  const { logical, converted } = el;
  // Any physical type annotated UNKNOWN reads as the null type.
  if (logical?.kind === "Unknown") return { family: null };
  switch (el.physical) {
    case Physical.BOOLEAN:
      return { family: "boolean" };
    case Physical.INT96:
      return { family: "timestamp" };
    case Physical.FLOAT:
      return { family: "float32" };
    case Physical.DOUBLE:
      return { family: "float64" };
    case Physical.INT32:
      if (!logical) {
        switch (converted) {
          case Converted.NONE:
          case Converted.INT_32:
            return { family: "int32", arrow: "int32" };
          case Converted.UINT_8:
            return { family: "uint8" };
          case Converted.UINT_16:
            return { family: "uint16" };
          case Converted.UINT_32:
            return { family: "uint32" };
          case Converted.INT_8:
            return { family: "int8" };
          case Converted.INT_16:
            return { family: "int16" };
          case Converted.DATE:
            return { family: "date", arrow: "date32" };
          case Converted.TIME_MILLIS:
            return { family: null };
          case Converted.DECIMAL:
            return decimal(el.precision, el.scale);
          default:
            throw new Malformed();
        }
      }
      switch (logical.kind) {
        case "Integer": {
          const families: Record<string, Kind> = {
            "8,true": { family: "int8" },
            "16,true": { family: "int16" },
            "32,true": { family: "int32", arrow: "int32" },
            "8,false": { family: "uint8" },
            "16,false": { family: "uint16" },
            "32,false": { family: "uint32" },
          };
          const kind = families[`${logical.bitWidth},${logical.signed}`];
          if (!kind) throw new Malformed();
          return kind;
        }
        case "Decimal":
          return decimal(logical.precision, logical.scale);
        case "Date":
          return { family: "date", arrow: "date32" };
        case "Time":
          if (logical.unit !== "MILLIS") throw new Malformed();
          return { family: null };
        default:
          throw new Malformed();
      }
    case Physical.INT64:
      if (!logical) {
        switch (converted) {
          case Converted.NONE:
          case Converted.INT_64:
            return { family: "int64", arrow: "int64" };
          case Converted.UINT_64:
            return { family: "uint64" };
          case Converted.TIME_MICROS:
            return { family: null };
          case Converted.TIMESTAMP_MILLIS:
          case Converted.TIMESTAMP_MICROS:
            return { family: "timestamp" };
          case Converted.DECIMAL:
            return decimal(el.precision, el.scale);
          default:
            throw new Malformed();
        }
      }
      switch (logical.kind) {
        case "Integer":
          if (logical.bitWidth !== 64) throw new Malformed();
          return logical.signed ? { family: "int64", arrow: "int64" } : { family: "uint64" };
        case "Time":
          if (logical.unit === "MILLIS") throw new Malformed();
          return { family: null };
        case "Timestamp":
          return { family: "timestamp" };
        case "Decimal":
          return decimal(logical.precision, logical.scale);
        default:
          throw new Malformed();
      }
    case Physical.BYTE_ARRAY:
      if (!logical) {
        switch (converted) {
          case Converted.NONE:
          case Converted.BSON:
          case Converted.ENUM:
            return { family: null, arrow: "binary" };
          case Converted.UTF8:
          case Converted.JSON:
            return { family: "string" };
          case Converted.DECIMAL:
            return decimal(el.precision, el.scale);
          default:
            throw new Malformed();
        }
      }
      switch (logical.kind) {
        case "String":
        case "Json":
          return { family: "string" };
        case "Bson":
        case "Enum":
        case "Geometry":
        case "Geography":
        case "_Unknown":
          return { family: null, arrow: "binary" };
        case "Decimal":
          return decimal(logical.precision, logical.scale);
        default:
          throw new Malformed();
      }
    case Physical.FIXED_LEN_BYTE_ARRAY:
      if (logical?.kind === "Decimal" || (!logical && converted === Converted.DECIMAL)) {
        if (el.typeLength < 1 || el.typeLength > 32) throw new Malformed();
        return logical?.kind === "Decimal"
          ? decimal(logical.precision, logical.scale)
          : decimal(el.precision, el.scale);
      }
      if (!logical && converted === Converted.INTERVAL) {
        if (el.typeLength !== 12) throw new Malformed();
        return { family: null };
      }
      if (logical?.kind === "Float16" && el.typeLength !== 2) throw new Malformed();
      // Float16, or a fixed-size binary.
      return { family: null };
    default:
      throw new Malformed();
  }
}

/** The family a column reads as once the embedded Arrow schema refines it
 *  (parquet-rs `apply_hint`). Only these refinements change a family; a
 *  dictionary-encoded field refines as its value type does. */
function refined(kind: Kind, hint: HintKind | undefined): ColumnType | null {
  if (hint === undefined) return kind.family;
  switch (kind.arrow) {
    case "int32":
      if (hint === "timestamp") return "timestamp";
      if (hint === "time32") return null;
      return kind.family;
    case "int64":
      if (hint === "timestamp") return "timestamp";
      if (hint === "time64" || hint === "duration") return null;
      if (hint === "date64") return "date";
      return kind.family;
    case "binary":
      return hint === "string" ? "string" : kind.family;
    default:
      return kind.family;
  }
}

/** An Integer logical type's bit width must be one parquet-rs reads, on
 *  any element (`check_logical_type`). */
function checkLogical(el: Element): void {
  if (el.logical?.kind === "Integer" && ![8, 16, 32, 64].includes(el.logical.bitWidth)) {
    throw new Malformed();
  }
}

/** The file's top-level columns, after the same structural checks
 *  parquet-rs makes when it reads the schema list (exactly one root, every
 *  child present). A nested column is returned as a group. */
function topLevelColumns(elements: Element[]): Array<{ el: Element; group: boolean }> {
  const root = elements[0];
  if (!root) throw new Malformed();
  checkLogical(root);
  // A root with no children is an empty schema, whatever follows.
  if (!root.numChildren) {
    if (elements.length !== 1) throw new Malformed();
    return [];
  }
  let next = 1;
  /** Consumes the subtree at `next`; returns whether it is a group. */
  const subtree = (): boolean => {
    const el = elements[next];
    if (!el) throw new Malformed();
    next += 1;
    checkLogical(el);
    if (el.numChildren) {
      if (el.repetition === undefined) throw new Malformed();
      for (let i = 0; i < el.numChildren; i += 1) subtree();
      return true;
    }
    if (el.repetition === undefined) throw new Malformed();
    // A childless element without a physical type is an empty group.
    if (el.physical === undefined) return true;
    checkAnnotations(el);
    return false;
  };
  const columns: Array<{ el: Element; group: boolean }> = [];
  for (let i = 0; i < root.numChildren; i += 1) {
    const el = elements[next];
    const group = subtree();
    columns.push({ el: el!, group });
  }
  if (next !== elements.length) throw new Malformed();
  return columns;
}

/** The embedded Arrow schema's top-level fields, or undefined without one.
 *  Like parquet-rs, the last `ARROW:schema` entry with a value counts. */
function arrowHints(metadata: unknown): HintField[] | undefined {
  if (metadata === undefined) return undefined;
  let encoded: string | undefined;
  for (const entry of list(metadata)) {
    const kv = struct(entry);
    const key = text(kv.field_1);
    if (kv.field_2 === undefined) continue;
    const value = text(kv.field_2);
    if (key === "ARROW:schema") encoded = value;
  }
  if (encoded === undefined) return undefined;
  try {
    return readArrowSchema(encoded);
  } catch (err) {
    if (err instanceof ArrowSchemaError) throw new Refused({ code: "arrow_schema" });
    throw err;
  }
}

function rowsOf(numRows: unknown, rowGroups: unknown): bigint {
  const fileRows = long(numRows);
  let sum = 0n;
  for (const group of list(rowGroups)) {
    const rows = long(struct(group).field_3);
    if (rows < 0n) throw new Malformed();
    sum += rows;
  }
  if (fileRows < 0n) throw new Malformed();
  return fileRows > sum ? fileRows : sum;
}

/** The declaration a decoded footer (`FileMetaData`) makes. Throws
 *  `Malformed` or `Refused`. */
function declare(metadata: Thrift): { schema: DeclaredColumn[]; rows: number } {
  int(metadata.field_1); // version, required
  // A footer with encryption metadata belongs to a file whose columns are
  // encrypted; the enclave cannot read them.
  if (metadata.field_8 !== undefined) throw new Refused({ code: "encrypted" });
  const elements = list(metadata.field_2).map(schemaElement);
  const rows = rowsOf(metadata.field_3, metadata.field_4);
  const columns = topLevelColumns(elements);
  const hints = arrowHints(metadata.field_5);
  if (hints) {
    // parquet-rs refuses an embedded schema that does not name the same
    // top-level columns in the same order.
    if (hints.length !== columns.length || hints.some((hint, i) => hint.name !== columns[i]!.el.name)) {
      throw new Refused({ code: "arrow_schema" });
    }
  }

  const schema: DeclaredColumn[] = [];
  columns.forEach(({ el, group }, i) => {
    if (group || el.repetition === Repetition.REPEATED) {
      throw new Refused({ code: "nested_column", column: el.name });
    }
    const family = refined(kindOf(el), hints?.[i]?.kind);
    if (!family) throw new Refused({ code: "unsupported_type", column: el.name });
    schema.push({ name: el.name, type: family });
  });
  const problem = declarationProblem(schema);
  if (problem) throw new Refused(problem);
  if (rows === 0n) throw new Refused({ code: "no_rows" });
  if (rows > BigInt(Number.MAX_SAFE_INTEGER) || !isRowCap(Number(rows))) {
    throw new Refused({ code: "too_many_rows" });
  }
  return { schema, rows: Number(rows) };
}

/** The declaration the Parquet footer of `file` makes, reading only the
 *  file's tail, or why the file cannot be uploaded. Never throws for a
 *  malformed file; a failed read of the file itself does. */
export async function readFooter(file: Pick<Blob, "size" | "slice">): Promise<FooterReading> {
  const refuse = (refusal: FooterRefusal): FooterReading => ({ ok: false, refusal });
  const size = file.size;
  if (size < TRAILER_BYTES) return refuse({ code: "not_parquet" });
  const trailer = new Uint8Array(await file.slice(size - TRAILER_BYTES, size).arrayBuffer());
  const magic = String.fromCharCode(...trailer.subarray(4));
  if (magic === MAGIC_ENCRYPTED_FOOTER) return refuse({ code: "encrypted" });
  if (magic !== MAGIC) return refuse({ code: "not_parquet" });
  const footerBytes = new DataView(trailer.buffer).getUint32(0, true);
  if (footerBytes > size - TRAILER_BYTES) return refuse({ code: "footer_length" });
  if (footerBytes > FOOTER_MAX_BYTES) return refuse({ code: "footer_too_large" });
  const end = size - TRAILER_BYTES;
  const footer = await file.slice(end - footerBytes, end).arrayBuffer();
  // A short read means the file changed under us.
  if (footer.byteLength !== footerBytes) return refuse({ code: "footer_length" });
  try {
    const metadata = deserializeTCompactProtocol({ view: new DataView(footer), offset: 0 });
    return { ok: true, ...declare(metadata), footerBytes };
  } catch (err) {
    if (err instanceof Refused) return refuse(err.refusal);
    // hyparquet's decoder throws plain Errors, and reads past the end throw
    // RangeErrors; a footer that runs deeper than the call stack throws
    // too. None of them is a file the enclave reads.
    return refuse({ code: "malformed_footer" });
  }
}
