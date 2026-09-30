//! Normalized tables built in enclave RAM from connector payloads, en route
//! to Parquet.

use crate::ConnectorError;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Utf8,
    I64,
    F64,
    Bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColumnSpec {
    pub name: &'static str,
    pub ty: ColumnType,
}

pub fn col(name: &'static str, ty: ColumnType) -> ColumnSpec {
    ColumnSpec { name, ty }
}

/// A single typed cell. `Null` is valid in any column.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    I64(i64),
    F64(f64),
    Bool(bool),
    Null,
}

impl FieldValue {
    fn matches(&self, ty: ColumnType) -> bool {
        matches!(
            (self, ty),
            (FieldValue::Null, _)
                | (FieldValue::Str(_), ColumnType::Utf8)
                | (FieldValue::I64(_), ColumnType::I64)
                | (FieldValue::F64(_), ColumnType::F64)
                | (FieldValue::Bool(_), ColumnType::Bool)
        )
    }
}

/// One normalized table (e.g. "invoices") for one sync.
#[derive(Debug, Clone)]
pub struct Dataset {
    pub name: String,
    pub columns: Vec<ColumnSpec>,
    pub rows: Vec<Vec<FieldValue>>,
}

impl Dataset {
    pub fn new(name: impl Into<String>, columns: Vec<ColumnSpec>) -> Self {
        Self {
            name: name.into(),
            columns,
            rows: Vec::new(),
        }
    }

    /// Append a row, enforcing arity and column types so the Parquet writer
    /// never sees a malformed shape.
    pub fn push_row(&mut self, row: Vec<FieldValue>) -> Result<(), ConnectorError> {
        if row.len() != self.columns.len() {
            return Err(ConnectorError::DatasetShape(format!(
                "row has {} cells, dataset {} has {} columns",
                row.len(),
                self.name,
                self.columns.len()
            )));
        }
        for (cell, spec) in row.iter().zip(&self.columns) {
            if !cell.matches(spec.ty) {
                return Err(ConnectorError::DatasetShape(format!(
                    "column {} expects {:?}",
                    spec.name, spec.ty
                )));
            }
        }
        self.rows.push(row);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_row_enforces_arity_and_types() {
        let mut ds = Dataset::new(
            "t",
            vec![col("id", ColumnType::Utf8), col("total", ColumnType::F64)],
        );
        ds.push_row(vec![FieldValue::Str("a".into()), FieldValue::F64(1.5)])
            .expect("valid row");
        ds.push_row(vec![FieldValue::Str("b".into()), FieldValue::Null])
            .expect("nulls allowed");

        assert!(ds.push_row(vec![FieldValue::Str("c".into())]).is_err());
        assert!(
            ds.push_row(vec![FieldValue::F64(1.0), FieldValue::F64(2.0)])
                .is_err()
        );
    }
}
