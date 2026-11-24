//! Parquet schema vectors shared with the steward's browser (ADR 0014).
//!
//! Before sealing an upload, the browser reads the Parquet footer and
//! declares the file's schema (`frontend/src/lib/datasets/footer.ts`). The
//! enclave later checks the decrypted Parquet against that declaration
//! (`QueryScope::register_parquet_declared`, ADR 0012). The two derive a
//! column's type family with different code, and a declaration they disagree
//! on makes every query of the dataset fail, so `fixtures/parquet/` holds
//! small synthetic files that both must read alike. `schema-vectors.json`
//! records, for each file, what the enclave does with it and what the
//! browser does. This test checks the enclave's side against the committed
//! files; `frontend/src/lib/datasets/footer.test.ts` checks the browser's.
//!
//! The files are written by `write_vectors`, which is ignored by default:
//!
//! ```text
//! cargo test -p quackxide-engine --test parquet_schema_vectors --locked -- --ignored
//! ```
//!
//! Every value in them is a made-up literal (`docs/DATA_POLICY.md`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, BinaryArray, BooleanArray, Date32Array, Date64Array, Decimal32Array,
    Decimal64Array, Decimal128Array, Decimal256Array, DictionaryArray, DurationMillisecondArray,
    Float32Array, Float64Array, Int8Array, Int16Array, Int32Array, Int64Array,
    IntervalDayTimeArray, LargeStringArray, ListArray, NullArray, RecordBatch, StringArray,
    StringViewArray, StructArray, Time32SecondArray, Time64MicrosecondArray,
    TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
    TimestampSecondArray, UInt8Array, UInt16Array, UInt32Array, UInt64Array,
};
use arrow::datatypes::{
    DataType, Field, Int8Type, Int32Type, Int64Type, IntervalDayTime, Schema, TimeUnit, i256,
};
use bytes::Bytes;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::arrow_writer::ArrowWriterOptions;
use parquet::basic::Type as PhysicalType;
use parquet::basic::{ConvertedType, LogicalType, Repetition, TimeUnit as ParquetTimeUnit};
use parquet::data_type::{
    BoolType, ByteArray, ByteArrayType, DoubleType, FixedLenByteArray, FixedLenByteArrayType,
    FloatType, Int32Type as PqInt32, Int64Type as PqInt64, Int96, Int96Type,
};
use parquet::file::metadata::KeyValue;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::Type;
use platform_core::{ColumnType, DeclaredColumn, DeclaredSchema, QueryLimits, ZkMode};
use quackxide_engine::{EngineSettings, QueryScope, column_type_of};
use serde_json::{Value, json};

/// The key under which Arrow writers embed their schema in a Parquet footer.
const ARROW_SCHEMA_KEY: &str = "ARROW:schema";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/parquet")
}

/// What the enclave does with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Enclave {
    /// Every column has a type family and the schema is a valid
    /// declaration, which the enclave's check accepts.
    Declares,
    /// The Parquet reader refuses the file, so no query could read it.
    Unreadable,
    /// A column's type is in no family, so no declaration matches it.
    NoFamily,
    /// Every column has a family, but the schema is not a valid
    /// declaration (a name or the column count is out of bounds).
    Undeclarable,
}

impl Enclave {
    fn label(self) -> &'static str {
        match self {
            Enclave::Declares => "declares",
            Enclave::Unreadable => "unreadable",
            Enclave::NoFamily => "no_family",
            Enclave::Undeclarable => "undeclarable",
        }
    }
}

/// One vector: a file, how to write it, and what each side does with it.
struct Case {
    file: &'static str,
    about: &'static str,
    enclave: Enclave,
    /// The schema the enclave derives, for [`Enclave::Declares`].
    declared: Vec<(&'static str, ColumnType)>,
    /// The rows the footer reports, for [`Enclave::Declares`].
    rows: u64,
    /// `declares`, or the browser's refusal code.
    browser: &'static str,
    write: fn() -> Vec<u8>,
}

fn arrow_file(columns: Vec<(Field, ArrayRef)>, embed_arrow_schema: bool) -> Vec<u8> {
    let schema = Arc::new(Schema::new(
        columns
            .iter()
            .map(|(field, _)| field.clone())
            .collect::<Vec<_>>(),
    ));
    let arrays = columns.into_iter().map(|(_, array)| array).collect();
    let batch = RecordBatch::try_new(schema.clone(), arrays).expect("batch");
    // Two rows per row group, so a three-row file has two.
    let props = WriterProperties::builder()
        .set_max_row_group_row_count(Some(2))
        .build();
    let options = ArrowWriterOptions::new()
        .with_properties(props)
        .with_skip_arrow_metadata(!embed_arrow_schema);
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new_with_options(&mut buf, schema, options).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

/// One required (or, for `Repetition::REPEATED`, repeated) column's values,
/// for [`raw_file`].
enum Values {
    Bool(Vec<bool>),
    I32(Vec<i32>),
    I64(Vec<i64>),
    I96(Vec<Int96>),
    F32(Vec<f32>),
    F64(Vec<f64>),
    Bytes(Vec<ByteArray>),
    Fixed(Vec<FixedLenByteArray>),
}

fn primitive(
    name: &str,
    physical: PhysicalType,
) -> parquet::schema::types::PrimitiveTypeBuilder<'_> {
    Type::primitive_type_builder(name, physical).with_repetition(Repetition::REQUIRED)
}

fn bytes(values: &[&str]) -> Values {
    Values::Bytes(values.iter().map(|v| ByteArray::from(*v)).collect())
}

/// A file written with parquet's own schema types, for annotations Arrow
/// writers do not produce, and with `metadata` as its key-value metadata.
fn raw_file(columns: Vec<(Type, Values)>, metadata: Vec<KeyValue>) -> Vec<u8> {
    raw_file_with(columns, metadata, WriterProperties::builder())
}

fn raw_file_with(
    columns: Vec<(Type, Values)>,
    metadata: Vec<KeyValue>,
    props: parquet::file::properties::WriterPropertiesBuilder,
) -> Vec<u8> {
    let fields = columns
        .iter()
        .map(|(field, _)| Arc::new(field.clone()))
        .collect();
    let schema = Arc::new(
        Type::group_type_builder("schema")
            .with_fields(fields)
            .build()
            .expect("schema"),
    );
    let props = Arc::new(
        props
            .set_key_value_metadata((!metadata.is_empty()).then_some(metadata))
            .build(),
    );
    let mut buf = Vec::new();
    let mut writer = SerializedFileWriter::new(&mut buf, schema, props).expect("writer");
    let mut group = writer.next_row_group().expect("row group");
    for (field, values) in &columns {
        let repeated = field.get_basic_info().repetition() == Repetition::REPEATED;
        let mut column = group.next_column().expect("column").expect("a column");
        // A repeated column holds each value as a row of its own.
        let count = match values {
            Values::Bool(v) => v.len(),
            Values::I32(v) => v.len(),
            Values::I64(v) => v.len(),
            Values::I96(v) => v.len(),
            Values::F32(v) => v.len(),
            Values::F64(v) => v.len(),
            Values::Bytes(v) => v.len(),
            Values::Fixed(v) => v.len(),
        };
        let levels = vec![if repeated { 1 } else { 0 }; count];
        let rep = vec![0i16; count];
        let (def, rep) = if repeated {
            (Some(levels.as_slice()), Some(rep.as_slice()))
        } else {
            (None, None)
        };
        match values {
            Values::Bool(v) => column.typed::<BoolType>().write_batch(v, def, rep),
            Values::I32(v) => column.typed::<PqInt32>().write_batch(v, def, rep),
            Values::I64(v) => column.typed::<PqInt64>().write_batch(v, def, rep),
            Values::I96(v) => column.typed::<Int96Type>().write_batch(v, def, rep),
            Values::F32(v) => column.typed::<FloatType>().write_batch(v, def, rep),
            Values::F64(v) => column.typed::<DoubleType>().write_batch(v, def, rep),
            Values::Bytes(v) => column.typed::<ByteArrayType>().write_batch(v, def, rep),
            Values::Fixed(v) => column
                .typed::<FixedLenByteArrayType>()
                .write_batch(v, def, rep),
        }
        .expect("write");
        column.close().expect("close column");
    }
    group.close().expect("close row group");
    writer.close().expect("close");
    buf
}

/// An Arrow schema embedded under [`ARROW_SCHEMA_KEY`], as Arrow writers
/// embed it.
fn arrow_hint(fields: Vec<Field>) -> KeyValue {
    KeyValue::new(
        ARROW_SCHEMA_KEY.to_owned(),
        parquet::arrow::encode_arrow_schema(&Schema::new(fields)),
    )
}

fn int64_column(name: &str) -> (Type, Values) {
    (
        primitive(name, PhysicalType::INT64).build().expect("type"),
        Values::I64(vec![1, 2, 3]),
    )
}

fn arc<A: arrow::array::Array + 'static>(array: A) -> ArrayRef {
    Arc::new(array)
}

/// One column of every type family, as Arrow writers store them.
fn families(embed_arrow_schema: bool) -> Vec<u8> {
    let decimal32 = Decimal32Array::from(vec![12_345, -1, 0])
        .with_precision_and_scale(9, 2)
        .expect("decimal32");
    let decimal64 = Decimal64Array::from(vec![123_456_789, -1, 0])
        .with_precision_and_scale(18, 4)
        .expect("decimal64");
    let decimal128 = Decimal128Array::from(vec![1_234_567_890_123, -1, 0])
        .with_precision_and_scale(38, 10)
        .expect("decimal128");
    let decimal256 = Decimal256Array::from(vec![
        i256::from_i128(98_765_432_109_876),
        i256::from_i128(-1),
        i256::ZERO,
    ])
    .with_precision_and_scale(76, 20)
    .expect("decimal256");
    let codes = DictionaryArray::<Int8Type>::try_new(
        Int8Array::from(vec![0, 1, 0]),
        Arc::new(Int64Array::from(vec![10, 20])),
    )
    .expect("dictionary");
    let utc = |unit: TimeUnit, tz: Option<&str>| DataType::Timestamp(unit, tz.map(Into::into));
    arrow_file(
        vec![
            (
                Field::new("flag", DataType::Boolean, false),
                arc(BooleanArray::from(vec![true, false, true])),
            ),
            (
                Field::new("i8", DataType::Int8, false),
                arc(Int8Array::from(vec![-1, 0, 7])),
            ),
            (
                Field::new("i16", DataType::Int16, false),
                arc(Int16Array::from(vec![-300, 0, 300])),
            ),
            (
                Field::new("i32", DataType::Int32, false),
                arc(Int32Array::from(vec![-70_000, 0, 70_000])),
            ),
            (
                Field::new("i64", DataType::Int64, true),
                arc(Int64Array::from(vec![
                    Some(-5_000_000_000),
                    None,
                    Some(5_000_000_000),
                ])),
            ),
            (
                Field::new("u8", DataType::UInt8, false),
                arc(UInt8Array::from(vec![0, 7, 255])),
            ),
            (
                Field::new("u16", DataType::UInt16, false),
                arc(UInt16Array::from(vec![0, 7, 65_535])),
            ),
            (
                Field::new("u32", DataType::UInt32, false),
                arc(UInt32Array::from(vec![0, 7, 4_000_000_000])),
            ),
            (
                Field::new("u64", DataType::UInt64, false),
                arc(UInt64Array::from(vec![0, 7, 18_000_000_000_000_000_000])),
            ),
            (
                Field::new("f32", DataType::Float32, false),
                arc(Float32Array::from(vec![1.5, -2.25, 0.0])),
            ),
            (
                Field::new("f64", DataType::Float64, false),
                arc(Float64Array::from(vec![1.5, -2.25, 1e300])),
            ),
            (
                Field::new("name", DataType::Utf8, false),
                arc(StringArray::from(vec!["alpha", "beta", "gamma"])),
            ),
            (
                Field::new("large_name", DataType::LargeUtf8, false),
                arc(LargeStringArray::from(vec!["alpha", "beta", "gamma"])),
            ),
            (
                Field::new("view_name", DataType::Utf8View, false),
                arc(StringViewArray::from(vec!["alpha", "beta", "gamma"])),
            ),
            (
                Field::new(
                    "category",
                    DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
                    false,
                ),
                arc(DictionaryArray::<Int32Type>::from_iter([
                    "red", "green", "red",
                ])),
            ),
            (
                Field::new(
                    "codes",
                    DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Int64)),
                    false,
                ),
                arc(codes),
            ),
            (
                Field::new("day", DataType::Date32, false),
                arc(Date32Array::from(vec![19_000, 19_001, 19_002])),
            ),
            (
                Field::new("day_ms", DataType::Date64, false),
                arc(Date64Array::from(vec![
                    1_641_600_000_000,
                    1_641_686_400_000,
                    0,
                ])),
            ),
            (
                Field::new("at_s", utc(TimeUnit::Second, None), false),
                arc(TimestampSecondArray::from(vec![1_700_000_000, 0, 1])),
            ),
            (
                Field::new("at_ms_utc", utc(TimeUnit::Millisecond, Some("UTC")), false),
                arc(
                    TimestampMillisecondArray::from(vec![1_700_000_000_000, 0, 1])
                        .with_timezone("UTC"),
                ),
            ),
            (
                Field::new(
                    "at_us_tz",
                    utc(TimeUnit::Microsecond, Some("+02:00")),
                    false,
                ),
                arc(
                    TimestampMicrosecondArray::from(vec![1_700_000_000_000_000, 0, 1])
                        .with_timezone("+02:00"),
                ),
            ),
            (
                Field::new("at_ns", utc(TimeUnit::Nanosecond, None), false),
                arc(TimestampNanosecondArray::from(vec![
                    1_700_000_000_000_000_000,
                    0,
                    1,
                ])),
            ),
            (
                Field::new("price", DataType::Decimal32(9, 2), false),
                arc(decimal32),
            ),
            (
                Field::new("amount", DataType::Decimal64(18, 4), false),
                arc(decimal64),
            ),
            (
                Field::new("big", DataType::Decimal128(38, 10), false),
                arc(decimal128),
            ),
            (
                Field::new("huge", DataType::Decimal256(76, 20), false),
                arc(decimal256),
            ),
            (
                Field::new("größe", DataType::Int64, false),
                arc(Int64Array::from(vec![170, 182, 165])),
            ),
            (
                Field::new("名前", DataType::Utf8, false),
                arc(StringArray::from(vec!["甲", "乙", "丙"])),
            ),
        ],
        embed_arrow_schema,
    )
}

/// [`families`]' declaration: with the embedded Arrow schema, or without it,
/// where `Date64` and `Timestamp(Second)` are only the `INT64` they are
/// stored as.
fn families_declared(embedded: bool) -> Vec<(&'static str, ColumnType)> {
    use ColumnType::*;
    let (day_ms, at_s) = if embedded {
        (Date, Timestamp)
    } else {
        (Int64, Int64)
    };
    vec![
        ("flag", Boolean),
        ("i8", Int8),
        ("i16", Int16),
        ("i32", Int32),
        ("i64", Int64),
        ("u8", Uint8),
        ("u16", Uint16),
        ("u32", Uint32),
        ("u64", Uint64),
        ("f32", Float32),
        ("f64", Float64),
        ("name", String),
        ("large_name", String),
        ("view_name", String),
        ("category", String),
        ("codes", Int64),
        ("day", Date),
        ("day_ms", day_ms),
        ("at_s", at_s),
        ("at_ms_utc", Timestamp),
        ("at_us_tz", Timestamp),
        ("at_ns", Timestamp),
        ("price", Decimal),
        ("amount", Decimal),
        ("big", Decimal),
        ("huge", Decimal),
        ("größe", Int64),
        ("名前", String),
    ]
}

/// Legacy files: converted types only, with no logical type, and `INT96`.
fn legacy_converted() -> Vec<u8> {
    let converted = |name, physical, converted| {
        primitive(name, physical)
            .with_converted_type(converted)
            .build()
            .expect("type")
    };
    let decimal = |name, physical, precision, scale, length| {
        primitive(name, physical)
            .with_converted_type(ConvertedType::DECIMAL)
            .with_precision(precision)
            .with_scale(scale)
            .with_length(length)
            .build()
            .expect("type")
    };
    let be = |value: i128, len: usize| value.to_be_bytes()[16 - len..].to_vec();
    raw_file(
        vec![
            (
                converted("c_i8", PhysicalType::INT32, ConvertedType::INT_8),
                Values::I32(vec![-1, 0, 7]),
            ),
            (
                converted("c_i16", PhysicalType::INT32, ConvertedType::INT_16),
                Values::I32(vec![-300, 0, 300]),
            ),
            (
                converted("c_i32", PhysicalType::INT32, ConvertedType::INT_32),
                Values::I32(vec![-70_000, 0, 70_000]),
            ),
            (
                converted("c_u8", PhysicalType::INT32, ConvertedType::UINT_8),
                Values::I32(vec![0, 7, 255]),
            ),
            (
                converted("c_u16", PhysicalType::INT32, ConvertedType::UINT_16),
                Values::I32(vec![0, 7, 65_535]),
            ),
            (
                converted("c_u32", PhysicalType::INT32, ConvertedType::UINT_32),
                Values::I32(vec![0, 7, -1]),
            ),
            (
                converted("c_date", PhysicalType::INT32, ConvertedType::DATE),
                Values::I32(vec![19_000, 19_001, 19_002]),
            ),
            (
                decimal("c_dec32", PhysicalType::INT32, 9, 2, -1),
                Values::I32(vec![12_345, -1, 0]),
            ),
            (
                converted("c_i64", PhysicalType::INT64, ConvertedType::INT_64),
                Values::I64(vec![-5_000_000_000, 0, 5]),
            ),
            (
                converted("c_u64", PhysicalType::INT64, ConvertedType::UINT_64),
                Values::I64(vec![0, 7, -1]),
            ),
            (
                converted(
                    "c_ts_ms",
                    PhysicalType::INT64,
                    ConvertedType::TIMESTAMP_MILLIS,
                ),
                Values::I64(vec![1_700_000_000_000, 0, 1]),
            ),
            (
                converted(
                    "c_ts_us",
                    PhysicalType::INT64,
                    ConvertedType::TIMESTAMP_MICROS,
                ),
                Values::I64(vec![1_700_000_000_000_000, 0, 1]),
            ),
            (
                decimal("c_dec64", PhysicalType::INT64, 18, 3, -1),
                Values::I64(vec![123_456_789, -1, 0]),
            ),
            (
                converted("c_utf8", PhysicalType::BYTE_ARRAY, ConvertedType::UTF8),
                bytes(&["alpha", "beta", "gamma"]),
            ),
            (
                converted("c_json", PhysicalType::BYTE_ARRAY, ConvertedType::JSON),
                bytes(&["{}", "[1]", "{\"a\":2}"]),
            ),
            (
                decimal("c_dec_bytes", PhysicalType::BYTE_ARRAY, 20, 2, -1),
                Values::Bytes(vec![
                    be(12_345, 3).into(),
                    be(-1, 1).into(),
                    be(0, 1).into(),
                ]),
            ),
            (
                decimal("c_dec_fixed", PhysicalType::FIXED_LEN_BYTE_ARRAY, 38, 4, 16),
                Values::Fixed(vec![
                    ByteArray::from(be(1_234_567, 16)).into(),
                    ByteArray::from(be(-1, 16)).into(),
                    ByteArray::from(be(0, 16)).into(),
                ]),
            ),
            (
                primitive("c_int96", PhysicalType::INT96)
                    .build()
                    .expect("type"),
                Values::I96(vec![
                    Int96::from(vec![0, 0, 2_440_588]),
                    Int96::from(vec![1, 0, 2_460_000]),
                    Int96::from(vec![0, 0, 2_460_001]),
                ]),
            ),
            (
                primitive("c_f", PhysicalType::FLOAT).build().expect("type"),
                Values::F32(vec![1.5, -2.25, 0.0]),
            ),
            (
                primitive("c_d", PhysicalType::DOUBLE)
                    .build()
                    .expect("type"),
                Values::F64(vec![1.5, -2.25, 0.0]),
            ),
            (
                primitive("c_b", PhysicalType::BOOLEAN)
                    .build()
                    .expect("type"),
                Values::Bool(vec![true, false, true]),
            ),
        ],
        Vec::new(),
    )
}

/// Logical-type annotations that Arrow writers leave out: an explicit
/// signed integer type, JSON, and a `BYTE_ARRAY` decimal wider than 38
/// digits.
fn logical_annotations() -> Vec<u8> {
    let logical = |name, physical, logical| {
        primitive(name, physical)
            .with_logical_type(Some(logical))
            .build()
            .expect("type")
    };
    raw_file(
        vec![
            (
                logical("l_i32", PhysicalType::INT32, LogicalType::integer(32, true)),
                Values::I32(vec![1, 2, 3]),
            ),
            (
                logical("l_i64", PhysicalType::INT64, LogicalType::integer(64, true)),
                Values::I64(vec![1, 2, 3]),
            ),
            (
                logical(
                    "l_u64",
                    PhysicalType::INT64,
                    LogicalType::integer(64, false),
                ),
                Values::I64(vec![1, 2, 3]),
            ),
            (
                logical("l_string", PhysicalType::BYTE_ARRAY, LogicalType::String),
                bytes(&["a", "b", "c"]),
            ),
            (
                logical("l_json", PhysicalType::BYTE_ARRAY, LogicalType::Json),
                bytes(&["{}", "[]", "1"]),
            ),
            (
                logical("l_date", PhysicalType::INT32, LogicalType::Date),
                Values::I32(vec![19_000, 19_001, 19_002]),
            ),
            (
                logical(
                    "l_ts",
                    PhysicalType::INT64,
                    LogicalType::timestamp(true, ParquetTimeUnit::NANOS),
                ),
                Values::I64(vec![1_700_000_000_000_000_000, 0, 1]),
            ),
            (
                primitive("l_dec_wide", PhysicalType::BYTE_ARRAY)
                    .with_logical_type(Some(LogicalType::decimal(5, 40)))
                    .with_precision(40)
                    .with_scale(5)
                    .build()
                    .expect("type"),
                Values::Bytes(vec![
                    vec![0x30, 0x39].into(),
                    vec![0xff].into(),
                    vec![0].into(),
                ]),
            ),
        ],
        Vec::new(),
    )
}

/// A one-column file of `field`, as Arrow writers store it.
fn single(field: Field, array: ArrayRef) -> Vec<u8> {
    arrow_file(
        vec![
            (
                Field::new("id", DataType::Int64, false),
                arc(Int64Array::from(vec![1, 2, 3])),
            ),
            (field, array),
        ],
        true,
    )
}

fn binary() -> Vec<u8> {
    single(
        Field::new("payload", DataType::Binary, false),
        arc(BinaryArray::from(vec![b"a".as_ref(), b"b", b"c"])),
    )
}

fn float16() -> Vec<u8> {
    let values = arrow::compute::cast(
        &Float32Array::from(vec![1.5, 0.0, -2.0]),
        &DataType::Float16,
    )
    .expect("cast to float16");
    single(Field::new("half", DataType::Float16, false), values)
}

fn time64() -> Vec<u8> {
    single(
        Field::new("at", DataType::Time64(TimeUnit::Microsecond), false),
        arc(Time64MicrosecondArray::from(vec![1_000, 2_000, 3_000])),
    )
}

fn time32_seconds() -> Vec<u8> {
    single(
        Field::new("at", DataType::Time32(TimeUnit::Second), false),
        arc(Time32SecondArray::from(vec![1, 2, 3])),
    )
}

fn duration() -> Vec<u8> {
    single(
        Field::new("took", DataType::Duration(TimeUnit::Millisecond), false),
        arc(DurationMillisecondArray::from(vec![1_000, 2_000, 3_000])),
    )
}

fn interval() -> Vec<u8> {
    single(
        Field::new(
            "gap",
            DataType::Interval(arrow::datatypes::IntervalUnit::DayTime),
            false,
        ),
        arc(IntervalDayTimeArray::from(vec![
            IntervalDayTime::new(1, 0),
            IntervalDayTime::new(0, 5),
            IntervalDayTime::new(2, 7),
        ])),
    )
}

fn null() -> Vec<u8> {
    single(
        Field::new("nothing", DataType::Null, true),
        arc(NullArray::new(3)),
    )
}

fn nested_struct() -> Vec<u8> {
    let inner = StructArray::from(vec![(
        Arc::new(Field::new("x", DataType::Int64, false)),
        arc(Int64Array::from(vec![1, 2, 3])),
    )]);
    let field = Field::new("point", inner.data_type().clone(), false);
    single(field, arc(inner))
}

fn list() -> Vec<u8> {
    let values = ListArray::from_iter_primitive::<Int64Type, _, _>(vec![
        Some(vec![Some(1), Some(2)]),
        Some(vec![]),
        Some(vec![Some(3)]),
    ]);
    let field = Field::new("tags", values.data_type().clone(), false);
    single(field, arc(values))
}

fn uuid() -> Vec<u8> {
    raw_file(
        vec![(
            primitive("id", PhysicalType::FIXED_LEN_BYTE_ARRAY)
                .with_length(16)
                .with_logical_type(Some(LogicalType::Uuid))
                .build()
                .expect("type"),
            Values::Fixed(vec![
                ByteArray::from(vec![1u8; 16]).into(),
                ByteArray::from(vec![2u8; 16]).into(),
            ]),
        )],
        Vec::new(),
    )
}

fn enum_column() -> Vec<u8> {
    raw_file(
        vec![(
            primitive("mood", PhysicalType::BYTE_ARRAY)
                .with_logical_type(Some(LogicalType::Enum))
                .build()
                .expect("type"),
            bytes(&["calm", "busy"]),
        )],
        Vec::new(),
    )
}

fn repeated() -> Vec<u8> {
    raw_file(
        vec![(
            Type::primitive_type_builder("tags", PhysicalType::INT64)
                .with_repetition(Repetition::REPEATED)
                .build()
                .expect("type"),
            Values::I64(vec![1, 2, 3]),
        )],
        Vec::new(),
    )
}

/// A plain `BYTE_ARRAY`, which alone is binary, that the embedded Arrow
/// schema names a string.
fn hint_binary_as_string() -> Vec<u8> {
    raw_file(
        vec![(
            primitive("label", PhysicalType::BYTE_ARRAY)
                .build()
                .expect("type"),
            bytes(&["alpha", "beta"]),
        )],
        vec![arrow_hint(vec![Field::new("label", DataType::Utf8, false)])],
    )
}

fn hint_renamed() -> Vec<u8> {
    raw_file(
        vec![int64_column("n")],
        vec![arrow_hint(vec![Field::new("m", DataType::Int64, false)])],
    )
}

fn hint_extra_field() -> Vec<u8> {
    raw_file(
        vec![int64_column("n")],
        vec![arrow_hint(vec![
            Field::new("n", DataType::Int64, false),
            Field::new("extra", DataType::Int64, false),
        ])],
    )
}

fn hint_not_base64() -> Vec<u8> {
    raw_file(
        vec![int64_column("n")],
        vec![KeyValue::new(
            ARROW_SCHEMA_KEY.to_owned(),
            "%%% not base64 %%%".to_owned(),
        )],
    )
}

fn hint_not_a_schema() -> Vec<u8> {
    // Valid base64 of bytes that are no flatbuffer message.
    raw_file(
        vec![int64_column("n")],
        vec![KeyValue::new(
            ARROW_SCHEMA_KEY.to_owned(),
            "AAECAwQFBgcICQoLDA0ODw==".to_owned(),
        )],
    )
}

/// Two embedded schemas: the reader keeps the last one.
fn hint_last_wins() -> Vec<u8> {
    raw_file(
        vec![int64_column("t")],
        vec![
            arrow_hint(vec![Field::new(
                "t",
                DataType::Timestamp(TimeUnit::Second, None),
                false,
            )]),
            arrow_hint(vec![Field::new("t", DataType::Int64, false)]),
        ],
    )
}

/// A flat `INT64` column that the embedded Arrow schema names a list.
fn hint_list_on_int64() -> Vec<u8> {
    raw_file(
        vec![int64_column("n")],
        vec![arrow_hint(vec![Field::new(
            "n",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            false,
        )])],
    )
}

/// A column whose name starts with a byte-order mark, as rows read from a
/// UTF-8 CSV with Python's `csv` module carry it.
fn bom_name() -> Vec<u8> {
    arrow_file(
        vec![(
            Field::new("\u{feff}id", DataType::Int64, false),
            arc(Int64Array::from(vec![1, 2, 3])),
        )],
        true,
    )
}

fn duplicate_names() -> Vec<u8> {
    raw_file(vec![int64_column("a"), int64_column("a")], Vec::new())
}

fn too_many_columns() -> Vec<u8> {
    let names: Vec<String> = (0..=platform_core::MAX_DECLARED_COLUMNS)
        .map(|i| format!("c{i}"))
        .collect();
    // No statistics, to keep the fixture small.
    raw_file_with(
        names.iter().map(|name| int64_column(name)).collect(),
        Vec::new(),
        WriterProperties::builder()
            .set_statistics_enabled(parquet::file::properties::EnabledStatistics::None),
    )
}

fn long_name() -> Vec<u8> {
    let name = "x".repeat(platform_core::MAX_COLUMN_NAME_BYTES + 1);
    raw_file(vec![int64_column(&name)], Vec::new())
}

fn control_name() -> Vec<u8> {
    raw_file(vec![int64_column("tab\there")], Vec::new())
}

fn no_rows() -> Vec<u8> {
    arrow_file(
        vec![(
            Field::new("n", DataType::Int64, false),
            arc(Int64Array::from(Vec::<i64>::new())),
        )],
        true,
    )
}

/// The cohort the browser seals for the cross-implementation upload vector
/// (`fixtures/envelope/hpk1-browser-upload.json`): the rows
/// `platform-api`'s upload tests query, six of one condition and one of
/// another.
fn upload_cohort() -> Vec<u8> {
    arrow_file(
        vec![
            (
                Field::new("condition", DataType::Utf8, false),
                arc(StringArray::from(vec![
                    "flu",
                    "flu",
                    "flu",
                    "flu",
                    "flu",
                    "flu",
                    "rare_disease",
                ])),
            ),
            (
                Field::new("age", DataType::Int64, false),
                arc(Int64Array::from(vec![30, 40, 50, 33, 44, 55, 61])),
            ),
        ],
        true,
    )
}

fn families_embedded() -> Vec<u8> {
    families(true)
}

fn families_bare() -> Vec<u8> {
    families(false)
}

fn cases() -> Vec<Case> {
    use ColumnType::*;
    let refused = |file, about, enclave, browser, write| Case {
        file,
        about,
        enclave,
        declared: Vec::new(),
        rows: 0,
        browser,
        write,
    };
    vec![
        Case {
            file: "families.parquet",
            about: "One column of each type family as an Arrow writer stores it, with its embedded Arrow \
                    schema, in two row groups (2 and 1 rows). Date64 and Timestamp(Second) are stored as \
                    plain INT64 and take their type from the embedded schema; LargeUtf8, Utf8View, \
                    dictionaries, time zones and decimal widths keep their family.",
            enclave: Enclave::Declares,
            declared: families_declared(true),
            rows: 3,
            browser: "declares",
            write: families_embedded,
        },
        Case {
            file: "families-without-arrow-schema.parquet",
            about: "The same columns without an embedded Arrow schema: Date64 and Timestamp(Second) are \
                    then only INT64.",
            enclave: Enclave::Declares,
            declared: families_declared(false),
            rows: 3,
            browser: "declares",
            write: families_bare,
        },
        Case {
            file: "legacy-converted.parquet",
            about: "Converted types only, with no logical type, as older writers store them, and an INT96 \
                    timestamp.",
            enclave: Enclave::Declares,
            declared: vec![
                ("c_i8", Int8),
                ("c_i16", Int16),
                ("c_i32", Int32),
                ("c_u8", Uint8),
                ("c_u16", Uint16),
                ("c_u32", Uint32),
                ("c_date", Date),
                ("c_dec32", Decimal),
                ("c_i64", Int64),
                ("c_u64", Uint64),
                ("c_ts_ms", Timestamp),
                ("c_ts_us", Timestamp),
                ("c_dec64", Decimal),
                ("c_utf8", String),
                ("c_json", String),
                ("c_dec_bytes", Decimal),
                ("c_dec_fixed", Decimal),
                ("c_int96", Timestamp),
                ("c_f", Float32),
                ("c_d", Float64),
                ("c_b", Boolean),
            ],
            rows: 3,
            browser: "declares",
            write: legacy_converted,
        },
        Case {
            file: "logical-annotations.parquet",
            about: "Logical types Arrow writers leave out: explicit signed integers, JSON, and a BYTE_ARRAY \
                    decimal of 40 digits.",
            enclave: Enclave::Declares,
            declared: vec![
                ("l_i32", Int32),
                ("l_i64", Int64),
                ("l_u64", Uint64),
                ("l_string", String),
                ("l_json", String),
                ("l_date", Date),
                ("l_ts", Timestamp),
                ("l_dec_wide", Decimal),
            ],
            rows: 3,
            browser: "declares",
            write: logical_annotations,
        },
        Case {
            file: "hint-binary-as-string.parquet",
            about: "A plain BYTE_ARRAY, which alone is binary, that the embedded Arrow schema names Utf8.",
            enclave: Enclave::Declares,
            declared: vec![("label", String)],
            rows: 2,
            browser: "declares",
            write: hint_binary_as_string,
        },
        Case {
            file: "hint-last-wins.parquet",
            about: "Two embedded Arrow schemas: the first names column t a timestamp, the last an Int64. The \
                    reader keeps the last.",
            enclave: Enclave::Declares,
            declared: vec![("t", Int64)],
            rows: 3,
            browser: "declares",
            write: hint_last_wins,
        },
        refused(
            "binary.parquet",
            "A binary column, which no family covers.",
            Enclave::NoFamily,
            "unsupported_type",
            binary,
        ),
        refused(
            "float16.parquet",
            "A Float16 column.",
            Enclave::NoFamily,
            "unsupported_type",
            float16,
        ),
        refused(
            "time64.parquet",
            "A time-of-day column (INT64, TIME MICROS).",
            Enclave::NoFamily,
            "unsupported_type",
            time64,
        ),
        refused(
            "time32-seconds.parquet",
            "Time32(Second), stored as plain INT32 and named a time by the embedded Arrow schema.",
            Enclave::NoFamily,
            "unsupported_type",
            time32_seconds,
        ),
        refused(
            "duration.parquet",
            "A duration, stored as plain INT64 and named a duration by the embedded Arrow schema.",
            Enclave::NoFamily,
            "unsupported_type",
            duration,
        ),
        refused(
            "interval.parquet",
            "An interval (FIXED_LEN_BYTE_ARRAY(12), INTERVAL).",
            Enclave::NoFamily,
            "unsupported_type",
            interval,
        ),
        refused(
            "null.parquet",
            "A column of the null type (UNKNOWN logical type).",
            Enclave::NoFamily,
            "unsupported_type",
            null,
        ),
        refused(
            "uuid.parquet",
            "A UUID (FIXED_LEN_BYTE_ARRAY(16), UUID).",
            Enclave::NoFamily,
            "unsupported_type",
            uuid,
        ),
        refused(
            "enum.parquet",
            "An ENUM-annotated BYTE_ARRAY, which reads as binary.",
            Enclave::NoFamily,
            "unsupported_type",
            enum_column,
        ),
        refused(
            "struct.parquet",
            "A struct column.",
            Enclave::NoFamily,
            "nested_column",
            nested_struct,
        ),
        refused(
            "list.parquet",
            "A list column.",
            Enclave::NoFamily,
            "nested_column",
            list,
        ),
        refused(
            "repeated.parquet",
            "A top-level repeated INT64, which reads as a list.",
            Enclave::NoFamily,
            "nested_column",
            repeated,
        ),
        refused(
            "hint-renamed.parquet",
            "An embedded Arrow schema whose field has another name than the column.",
            Enclave::Unreadable,
            "arrow_schema",
            hint_renamed,
        ),
        refused(
            "hint-extra-field.parquet",
            "An embedded Arrow schema with more fields than the file has columns.",
            Enclave::Unreadable,
            "arrow_schema",
            hint_extra_field,
        ),
        refused(
            "hint-not-base64.parquet",
            "An embedded Arrow schema that is not base64.",
            Enclave::Unreadable,
            "arrow_schema",
            hint_not_base64,
        ),
        refused(
            "hint-not-a-schema.parquet",
            "An embedded Arrow schema that is base64 but no Arrow message.",
            Enclave::Unreadable,
            "arrow_schema",
            hint_not_a_schema,
        ),
        Case {
            file: "hint-list-on-int64.parquet",
            about: "A flat INT64 column that the embedded Arrow schema names a list. The enclave reads an \
                    INT64; the browser refuses a nested type on a flat column, on which the enclave's Arrow \
                    reader can panic.",
            enclave: Enclave::Declares,
            declared: vec![("n", Int64)],
            rows: 3,
            browser: "arrow_schema",
            write: hint_list_on_int64,
        },
        Case {
            file: "bom-name.parquet",
            about: "A column whose name starts with a byte-order mark (U+FEFF), which both sides keep.",
            enclave: Enclave::Declares,
            declared: vec![("\u{feff}id", Int64)],
            rows: 3,
            browser: "declares",
            write: bom_name,
        },
        refused(
            "duplicate-names.parquet",
            "Two columns named a.",
            Enclave::Undeclarable,
            "duplicate_column",
            duplicate_names,
        ),
        refused(
            "too-many-columns.parquet",
            "513 columns, one more than a declaration holds.",
            Enclave::Undeclarable,
            "too_many_columns",
            too_many_columns,
        ),
        refused(
            "long-name.parquet",
            "A column name of 129 bytes, one more than a declaration holds.",
            Enclave::Undeclarable,
            "column_name",
            long_name,
        ),
        refused(
            "control-name.parquet",
            "A column name with a tab in it.",
            Enclave::Undeclarable,
            "column_name",
            control_name,
        ),
        Case {
            file: "upload-cohort.parquet",
            about: "The synthetic cohort the browser seals in the cross-implementation upload vector \
                    (fixtures/envelope/hpk1-browser-upload.json): six rows of one condition and one of \
                    another, in four row groups.",
            enclave: Enclave::Declares,
            declared: vec![("condition", String), ("age", Int64)],
            rows: 7,
            browser: "declares",
            write: upload_cohort,
        },
        Case {
            file: "no-rows.parquet",
            about: "A valid schema with no rows: the enclave reads it, but an upload must declare at least \
                    one row.",
            enclave: Enclave::Declares,
            declared: vec![("n", Int64)],
            rows: 0,
            browser: "no_rows",
            write: no_rows,
        },
    ]
}

fn declared_json(declared: &[(&str, ColumnType)]) -> Value {
    serde_json::to_value(declared_schema(declared).expect("a valid declaration"))
        .expect("schema json")
}

fn declared_schema(declared: &[(&str, ColumnType)]) -> Option<DeclaredSchema> {
    DeclaredSchema::new(
        declared
            .iter()
            .map(|(name, column_type)| DeclaredColumn {
                name: (*name).to_owned(),
                column_type: *column_type,
            })
            .collect(),
    )
    .ok()
}

/// `schema-vectors.json` as the cases describe it.
fn vectors_json() -> Value {
    let vectors: Vec<Value> = cases()
        .iter()
        .map(|case| {
            let mut entry = json!({
                "file": case.file,
                "about": case.about,
                "enclave": case.enclave.label(),
                "browser": case.browser,
            });
            if case.enclave == Enclave::Declares {
                entry["declared"] = declared_json(&case.declared);
                entry["rows"] = json!(case.rows);
            }
            entry
        })
        .collect();
    json!({
        "description": "Parquet files whose schema the steward's browser and the enclave must read alike \
                        (ADR 0014). `enclave` is what the enclave does with the file: `declares` the \
                        schema in `declared` with the footer's `rows`, or refuses it as `unreadable`, \
                        `no_family` (a column no type family covers) or `undeclarable` (a schema no \
                        declaration can hold). `browser` is `declares` (the same schema and rows) or the \
                        browser's refusal code. Every value in the files is a made-up literal. Generated by \
                        backend/crates/quackxide-engine/tests/parquet_schema_vectors.rs.",
        "vectors": vectors,
    })
}

fn read_vectors() -> Value {
    let path = fixtures_dir().join("schema-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("read schema-vectors.json"))
        .expect("schema-vectors.json is JSON")
}

/// The type family of each column the enclave derives, or `Err` when the
/// Parquet reader refuses the file.
fn derived(file: &[u8]) -> Result<Vec<(String, Option<ColumnType>)>, String> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(file))
        .map_err(|err| err.to_string())?;
    Ok(reader
        .schema()
        .fields()
        .iter()
        .map(|field| (field.name().clone(), column_type_of(field.data_type())))
        .collect())
}

fn scope() -> QueryScope {
    QueryScope::new(EngineSettings {
        zk: ZkMode::Disabled,
        max_concurrent_queries: 1,
        limits: QueryLimits::default(),
    })
}

#[test]
fn committed_vectors_are_the_generators() {
    // The expectations are the generator's, and every committed file is
    // one it writes.
    assert_eq!(read_vectors(), vectors_json(), "rerun write_vectors");
    let mut committed: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures/parquet")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".parquet"))
        .collect();
    committed.sort();
    let mut written: Vec<String> = cases().iter().map(|case| case.file.to_owned()).collect();
    written.sort();
    assert_eq!(committed, written);
}

#[test]
fn the_enclave_reads_each_file_as_recorded() {
    for case in cases() {
        let file = std::fs::read(fixtures_dir().join(case.file)).expect("read fixture");
        let what = case.file;
        match case.enclave {
            Enclave::Declares => {
                // The enclave's own check, as a query of an upload runs it.
                let schema = declared_schema(&case.declared).expect("a valid declaration");
                let rows = scope()
                    .register_parquet_declared("t", &[&file], &schema, case.rows)
                    .unwrap_or_else(|err| panic!("{what}: {err:?}"));
                assert_eq!(rows as u64, case.rows, "{what}");
            }
            Enclave::Unreadable => {
                assert!(derived(&file).is_err(), "{what} should be unreadable");
            }
            Enclave::NoFamily => {
                let columns = derived(&file).unwrap_or_else(|err| panic!("{what}: {err}"));
                assert!(
                    columns.iter().any(|(_, family)| family.is_none()),
                    "{what}: {columns:?}"
                );
            }
            Enclave::Undeclarable => {
                let columns = derived(&file).unwrap_or_else(|err| panic!("{what}: {err}"));
                let families: Option<Vec<DeclaredColumn>> = columns
                    .into_iter()
                    .map(|(name, family)| {
                        family.map(|column_type| DeclaredColumn { name, column_type })
                    })
                    .collect();
                let families = families.unwrap_or_else(|| panic!("{what}: a column has no family"));
                assert!(DeclaredSchema::new(families).is_err(), "{what}");
            }
        }
    }
}

#[test]
fn a_browser_declaration_is_always_one_the_enclave_accepts() {
    // The browser may refuse what the enclave reads, never the reverse:
    // whatever it declares, the enclave derives too.
    for case in cases() {
        if case.browser == "declares" {
            assert_eq!(case.enclave, Enclave::Declares, "{}", case.file);
        }
    }
}

/// Writes `fixtures/parquet/`: run with `--ignored` after changing a case.
#[test]
#[ignore = "writes fixtures/parquet/; run by hand after changing a case"]
fn write_vectors() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).expect("create fixtures/parquet");
    for case in cases() {
        std::fs::write(dir.join(case.file), (case.write)()).expect("write fixture");
    }
    let json = serde_json::to_string_pretty(&vectors_json()).expect("json");
    std::fs::write(dir.join("schema-vectors.json"), format!("{json}\n")).expect("write json");
}
