//! Pure mappers from raw connector API JSON to normalized datasets. They run
//! inside the enclave.

use serde_json::Value;

use crate::ConnectorError;
use crate::dataset::{ColumnType, Dataset, FieldValue, col};

fn malformed(what: &str) -> ConnectorError {
    ConnectorError::MalformedPayload(what.to_owned())
}

fn str_at(value: &Value, pointer: &str) -> FieldValue {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(|s| FieldValue::Str(s.to_owned()))
        .unwrap_or(FieldValue::Null)
}

fn f64_at(value: &Value, pointer: &str) -> FieldValue {
    value
        .pointer(pointer)
        .and_then(Value::as_f64)
        .map(FieldValue::F64)
        .unwrap_or(FieldValue::Null)
}

fn bool_at(value: &Value, pointer: &str) -> FieldValue {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .map(FieldValue::Bool)
        .unwrap_or(FieldValue::Null)
}

fn required_str(value: &Value, pointer: &str, what: &str) -> Result<FieldValue, ConnectorError> {
    match str_at(value, pointer) {
        FieldValue::Null => Err(malformed(what)),
        found => Ok(found),
    }
}

/// QuickBooks Online `query` response for Invoice objects.
pub fn quickbooks_invoices(payload: &Value) -> Result<Dataset, ConnectorError> {
    let invoices = payload
        .pointer("/QueryResponse/Invoice")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("missing QueryResponse.Invoice array"))?;

    let mut dataset = Dataset::new(
        "invoices",
        vec![
            col("id", ColumnType::Utf8),
            col("customer", ColumnType::Utf8),
            col("txn_date", ColumnType::Utf8),
            col("currency", ColumnType::Utf8),
            col("total", ColumnType::F64),
            col("balance", ColumnType::F64),
        ],
    );

    for invoice in invoices {
        dataset.push_row(vec![
            required_str(invoice, "/Id", "invoice without Id")?,
            str_at(invoice, "/CustomerRef/name"),
            str_at(invoice, "/TxnDate"),
            str_at(invoice, "/CurrencyRef/value"),
            f64_at(invoice, "/TotalAmt"),
            f64_at(invoice, "/Balance"),
        ])?;
    }
    Ok(dataset)
}

/// Odoo JSON-RPC `res.partner` search_read result.
pub fn odoo_partners(payload: &Value) -> Result<Dataset, ConnectorError> {
    let partners = payload
        .pointer("/result")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("missing result array"))?;

    let mut dataset = Dataset::new(
        "partners",
        vec![
            col("id", ColumnType::I64),
            col("name", ColumnType::Utf8),
            col("email", ColumnType::Utf8),
            col("is_company", ColumnType::Bool),
        ],
    );

    for partner in partners {
        let id = partner
            .pointer("/id")
            .and_then(Value::as_i64)
            .ok_or_else(|| malformed("partner without integer id"))?;
        dataset.push_row(vec![
            FieldValue::I64(id),
            str_at(partner, "/name"),
            str_at(partner, "/email"),
            bool_at(partner, "/is_company"),
        ])?;
    }
    Ok(dataset)
}

/// Generic CRM contacts export.
pub fn crm_contacts(payload: &Value) -> Result<Dataset, ConnectorError> {
    let contacts = payload
        .pointer("/contacts")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("missing contacts array"))?;

    let mut dataset = Dataset::new(
        "contacts",
        vec![
            col("id", ColumnType::Utf8),
            col("name", ColumnType::Utf8),
            col("email", ColumnType::Utf8),
            col("stage", ColumnType::Utf8),
        ],
    );

    for contact in contacts {
        dataset.push_row(vec![
            required_str(contact, "/id", "contact without id")?,
            str_at(contact, "/name"),
            str_at(contact, "/email"),
            str_at(contact, "/stage"),
        ])?;
    }
    Ok(dataset)
}

/// Embedded sample payloads for tests and the demo worker.
pub mod fixtures {
    use serde_json::Value;

    pub fn quickbooks() -> Value {
        serde_json::from_str(include_str!("../fixtures/quickbooks_invoices.json"))
            .expect("valid embedded fixture")
    }

    pub fn odoo() -> Value {
        serde_json::from_str(include_str!("../fixtures/odoo_partners.json"))
            .expect("valid embedded fixture")
    }

    pub fn crm() -> Value {
        serde_json::from_str(include_str!("../fixtures/crm_contacts.json"))
            .expect("valid embedded fixture")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickbooks_fixture_maps_to_typed_rows() {
        let ds = quickbooks_invoices(&fixtures::quickbooks()).expect("map");
        assert_eq!(ds.name, "invoices");
        assert_eq!(ds.rows.len(), 3);
        assert_eq!(ds.rows[0][0], FieldValue::Str("1042".into()));
        assert_eq!(ds.rows[0][4], FieldValue::F64(1250.0));
        assert_eq!(ds.rows[2][3], FieldValue::Str("EUR".into()));
    }

    #[test]
    fn odoo_fixture_maps_including_null_email() {
        let ds = odoo_partners(&fixtures::odoo()).expect("map");
        assert_eq!(ds.rows.len(), 3);
        assert_eq!(ds.rows[0][0], FieldValue::I64(14));
        assert_eq!(ds.rows[2][2], FieldValue::Null);
        assert_eq!(ds.rows[1][3], FieldValue::Bool(false));
    }

    #[test]
    fn crm_fixture_maps() {
        let ds = crm_contacts(&fixtures::crm()).expect("map");
        assert_eq!(ds.rows.len(), 3);
        assert_eq!(ds.rows[0][3], FieldValue::Str("qualified".into()));
    }

    #[test]
    fn malformed_payloads_are_rejected_not_guessed() {
        assert!(quickbooks_invoices(&serde_json::json!({})).is_err());
        assert!(odoo_partners(&serde_json::json!({"result": "nope"})).is_err());
        assert!(
            quickbooks_invoices(
                &serde_json::json!({"QueryResponse": {"Invoice": [{"TotalAmt": 5}]}})
            )
            .is_err(),
            "invoice without Id must be rejected"
        );
    }
}
