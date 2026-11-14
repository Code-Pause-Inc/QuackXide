//! The schema a steward declares for an uploaded dataset (ADR 0012).
//!
//! The upload route holds no key and cannot read an upload, so it keeps
//! what the steward declared: column names and logical types, in order. The
//! route compares a new declaration with the recorded one, and a query in
//! the enclave compares the decrypted Parquet with it. Types are families (any string encoding is
//! `string`), so the check is about the data's shape, not its encoding.

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// Most columns a declared schema may list.
pub const MAX_DECLARED_COLUMNS: usize = 512;
/// Longest column name, in UTF-8 bytes.
pub const MAX_COLUMN_NAME_BYTES: usize = 128;

/// A column's logical type. Each covers the Arrow encodings that hold the
/// same values (for example `string` covers `Utf8`, `LargeUtf8`, `Utf8View`
/// and dictionary-encoded strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Boolean,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float32,
    Float64,
    String,
    /// A calendar date.
    Date,
    /// A timestamp, in any unit or time zone.
    Timestamp,
    /// A fixed-point decimal, of any precision and scale.
    Decimal,
}

/// One declared column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: ColumnType,
}

/// A validated, ordered list of columns: 1..=[`MAX_DECLARED_COLUMNS`]
/// columns, each name 1..=[`MAX_COLUMN_NAME_BYTES`] bytes with no control
/// characters, and no name twice. Deserializing validates too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<DeclaredColumn>", into = "Vec<DeclaredColumn>")]
pub struct DeclaredSchema(Vec<DeclaredColumn>);

impl DeclaredSchema {
    pub fn new(columns: Vec<DeclaredColumn>) -> Result<Self, CoreError> {
        if columns.is_empty() || columns.len() > MAX_DECLARED_COLUMNS {
            return Err(CoreError::InvalidDeclaredSchema);
        }
        let mut seen = std::collections::HashSet::with_capacity(columns.len());
        for column in &columns {
            let name = column.name.as_str();
            let name_ok = (1..=MAX_COLUMN_NAME_BYTES).contains(&name.len())
                && !name.chars().any(char::is_control);
            if !name_ok || !seen.insert(name) {
                return Err(CoreError::InvalidDeclaredSchema);
            }
        }
        Ok(Self(columns))
    }

    pub fn columns(&self) -> &[DeclaredColumn] {
        &self.0
    }
}

impl TryFrom<Vec<DeclaredColumn>> for DeclaredSchema {
    type Error = CoreError;

    fn try_from(columns: Vec<DeclaredColumn>) -> Result<Self, Self::Error> {
        Self::new(columns)
    }
}

impl From<DeclaredSchema> for Vec<DeclaredColumn> {
    fn from(schema: DeclaredSchema) -> Self {
        schema.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str, column_type: ColumnType) -> DeclaredColumn {
        DeclaredColumn {
            name: name.to_owned(),
            column_type,
        }
    }

    #[test]
    fn schema_round_trips_through_json() {
        let schema = DeclaredSchema::new(vec![
            column("condition", ColumnType::String),
            column("age", ColumnType::Int64),
            column("enrolled", ColumnType::Uint8),
        ])
        .expect("valid");
        let json = serde_json::to_string(&schema).expect("json");
        assert_eq!(
            json,
            r#"[{"name":"condition","type":"string"},{"name":"age","type":"int64"},{"name":"enrolled","type":"uint8"}]"#
        );
        let parsed: DeclaredSchema = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, schema);
    }

    #[test]
    fn invalid_schemas_are_refused() {
        let long = "x".repeat(MAX_COLUMN_NAME_BYTES + 1);
        let too_many: Vec<_> = (0..=MAX_DECLARED_COLUMNS)
            .map(|i| column(&format!("c{i}"), ColumnType::Int64))
            .collect();
        for columns in [
            vec![],
            vec![column("", ColumnType::Int64)],
            vec![column(&long, ColumnType::Int64)],
            vec![column("tab\there", ColumnType::Int64)],
            vec![
                column("a", ColumnType::Int64),
                column("a", ColumnType::String),
            ],
            too_many,
        ] {
            assert_eq!(
                DeclaredSchema::new(columns.clone()),
                Err(CoreError::InvalidDeclaredSchema),
                "{columns:?}"
            );
        }
        let max_name = "x".repeat(MAX_COLUMN_NAME_BYTES);
        assert!(DeclaredSchema::new(vec![column(&max_name, ColumnType::Date)]).is_ok());
    }

    #[test]
    fn deserializing_validates_and_refuses_unknown_types_and_fields() {
        for bad in [
            "[]",
            r#"[{"name":"a","type":"int64"},{"name":"a","type":"int64"}]"#,
            r#"[{"name":"a","type":"utf8"}]"#,
            r#"[{"name":"a","type":"int64","nullable":true}]"#,
            r#"[{"name":"a"}]"#,
            r#"{"name":"a","type":"int64"}"#,
        ] {
            assert!(
                serde_json::from_str::<DeclaredSchema>(bad).is_err(),
                "{bad}"
            );
        }
    }
}
