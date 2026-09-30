//! In-memory Parquet encoding. The output is zeroize-on-drop `SecretBytes`,
//! sealed to the tenant key immediately after; nothing touches disk.

use std::io::{self, Write};
use std::sync::Arc;

use arrow::array::{ArrayRef, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use platform_crypto::SecretBytes;
use zeroize::Zeroize;

use crate::ConnectorError;
use crate::dataset::{ColumnType, Dataset, FieldValue};

fn arrow_type(ty: ColumnType) -> DataType {
    match ty {
        ColumnType::Utf8 => DataType::Utf8,
        ColumnType::I64 => DataType::Int64,
        ColumnType::F64 => DataType::Float64,
        ColumnType::Bool => DataType::Boolean,
    }
}

fn shape_err(msg: &str) -> ConnectorError {
    ConnectorError::DatasetShape(msg.to_owned())
}

/// In-memory sink that never leaves plaintext in freed memory: growth moves
/// into a fresh allocation and zeroizes the old one, and drop zeroizes.
struct ZeroizingWriter {
    buf: Vec<u8>,
}

impl ZeroizingWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    fn into_secret(mut self) -> SecretBytes {
        SecretBytes::new(std::mem::take(&mut self.buf))
    }
}

impl Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self
            .buf
            .len()
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("parquet buffer overflow"))?;
        if needed > self.buf.capacity() {
            let mut next = Vec::with_capacity(needed.max(self.buf.capacity().saturating_mul(2)));
            next.extend_from_slice(&self.buf);
            // Zeroizes the full capacity of the old allocation before it is freed.
            self.buf.zeroize();
            self.buf = next;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ZeroizingWriter {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Encode a dataset to Parquet, entirely in memory.
pub fn dataset_to_parquet(dataset: &Dataset) -> Result<SecretBytes, ConnectorError> {
    let fields: Vec<Field> = dataset
        .columns
        .iter()
        .map(|spec| Field::new(spec.name, arrow_type(spec.ty), true))
        .collect();
    let schema = Arc::new(Schema::new(fields));

    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(dataset.columns.len());
    for (index, spec) in dataset.columns.iter().enumerate() {
        let cells = dataset
            .rows
            .iter()
            .map(|row| row.get(index).ok_or_else(|| shape_err("row arity")));
        match spec.ty {
            ColumnType::Utf8 => {
                let mut builder = StringBuilder::new();
                for cell in cells {
                    match cell? {
                        FieldValue::Str(v) => builder.append_value(v),
                        FieldValue::Null => builder.append_null(),
                        _ => return Err(shape_err("expected utf8 cell")),
                    }
                }
                arrays.push(Arc::new(builder.finish()));
            }
            ColumnType::I64 => {
                let mut builder = Int64Builder::new();
                for cell in cells {
                    match cell? {
                        FieldValue::I64(v) => builder.append_value(*v),
                        FieldValue::Null => builder.append_null(),
                        _ => return Err(shape_err("expected i64 cell")),
                    }
                }
                arrays.push(Arc::new(builder.finish()));
            }
            ColumnType::F64 => {
                let mut builder = Float64Builder::new();
                for cell in cells {
                    match cell? {
                        FieldValue::F64(v) => builder.append_value(*v),
                        FieldValue::Null => builder.append_null(),
                        _ => return Err(shape_err("expected f64 cell")),
                    }
                }
                arrays.push(Arc::new(builder.finish()));
            }
            ColumnType::Bool => {
                let mut builder = BooleanBuilder::new();
                for cell in cells {
                    match cell? {
                        FieldValue::Bool(v) => builder.append_value(*v),
                        FieldValue::Null => builder.append_null(),
                        _ => return Err(shape_err("expected bool cell")),
                    }
                }
                arrays.push(Arc::new(builder.finish()));
            }
        }
    }

    let batch = RecordBatch::try_new(schema.clone(), arrays)
        .map_err(|e| ConnectorError::DatasetShape(e.to_string()))?;

    let mut buffer = ZeroizingWriter::with_capacity(64 * 1024);
    let mut writer = ArrowWriter::try_new(&mut buffer, schema, None)
        .map_err(|e| ConnectorError::Parquet(e.to_string()))?;
    writer
        .write(&batch)
        .map_err(|e| ConnectorError::Parquet(e.to_string()))?;
    // Arrow arrays and encoder buffers are immutable or library-owned and
    // cannot be zeroized without unsafe; drop them as soon as possible.
    drop(batch);
    writer
        .close()
        .map_err(|e| ConnectorError::Parquet(e.to_string()))?;

    Ok(buffer.into_secret())
}

/// Decode Parquet bytes back into record batches (tests + the query engine).
pub fn read_parquet_batches(bytes: bytes::Bytes) -> Result<Vec<RecordBatch>, ConnectorError> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)
        .map_err(|e| ConnectorError::Parquet(e.to_string()))?
        .build()
        .map_err(|e| ConnectorError::Parquet(e.to_string()))?;
    reader
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ConnectorError::Parquet(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::col;
    use arrow::array::{Array, Float64Array, StringArray};

    fn sample() -> Dataset {
        let mut ds = Dataset::new(
            "invoices",
            vec![
                col("id", ColumnType::Utf8),
                col("total", ColumnType::F64),
                col("paid", ColumnType::Bool),
            ],
        );
        ds.push_row(vec![
            FieldValue::Str("inv-1".into()),
            FieldValue::F64(120.5),
            FieldValue::Bool(true),
        ])
        .expect("row");
        ds.push_row(vec![
            FieldValue::Str("inv-2".into()),
            FieldValue::Null,
            FieldValue::Bool(false),
        ])
        .expect("row");
        ds
    }

    #[test]
    fn parquet_round_trips_values_and_nulls() {
        let parquet = dataset_to_parquet(&sample()).expect("encode");
        let batches =
            read_parquet_batches(bytes::Bytes::copy_from_slice(parquet.expose())).expect("decode");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 3);

        let ids = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("utf8 column");
        assert_eq!(ids.value(0), "inv-1");
        assert_eq!(ids.value(1), "inv-2");

        let totals = batch
            .column(1)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("f64 column");
        assert_eq!(totals.value(0), 120.5);
        assert!(totals.is_null(1));
    }

    #[test]
    fn empty_dataset_still_encodes() {
        let ds = Dataset::new("empty", vec![col("id", ColumnType::Utf8)]);
        let parquet = dataset_to_parquet(&ds).expect("encode");
        let batches =
            read_parquet_batches(bytes::Bytes::copy_from_slice(parquet.expose())).expect("decode");
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 0);
    }

    #[test]
    fn zeroizing_writer_grows_without_losing_bytes() {
        let mut writer = ZeroizingWriter::with_capacity(4);
        let mut expected = Vec::new();
        for chunk in [
            &b"ab"[..],
            b"cdefg",
            b"",
            b"hijklmnopqrstuvwxyz",
            b"0123456789",
        ] {
            writer.write_all(chunk).expect("write");
            expected.extend_from_slice(chunk);
        }
        assert!(writer.buf.capacity() > 4, "growth must have occurred");
        assert_eq!(writer.into_secret().expose(), expected.as_slice());
    }

    #[test]
    fn parquet_larger_than_initial_capacity_round_trips() {
        let mut ds = Dataset::new("big", vec![col("id", ColumnType::Utf8)]);
        for i in 0..20_000 {
            ds.push_row(vec![FieldValue::Str(format!("row-{i:08}"))])
                .expect("row");
        }
        let parquet = dataset_to_parquet(&ds).expect("encode");
        assert!(parquet.len() > 64 * 1024, "must exercise buffer growth");
        let batches =
            read_parquet_batches(bytes::Bytes::copy_from_slice(parquet.expose())).expect("decode");
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 20_000);
    }
}
