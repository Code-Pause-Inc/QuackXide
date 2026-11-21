//! Dataset catalog: a steward publishes a priced listing; a researcher
//! browses, requests access, and after approval runs disclosure-controlled
//! queries against the included budget. Also covers denial, withdrawal,
//! scoping, input bounds, and the listing's data dictionary with the
//! connector columns it starts from.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use platform_api::build_app;
use platform_connectors::parquet_out::dataset_to_parquet;
use platform_connectors::source::{ConnectorSource, FixtureSource, SyncContext};
use platform_core::{DeclaredColumn, DeclaredSchema, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_storage::ObjectStoreVault;
use quackxide_engine::{EngineSettings, QueryLimits, QueryScope};
use serde_json::{Value, json};

use common::{call, dev_attestation, post};

const SECRET: &str = "catalog-itest-secret";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// App where `steward` has a sealed `health` dataset and the research layer
/// (catalog + grants + budgets, k=5, default budget 100) is enabled.
async fn marketplace_app(steward: TenantId, steward_keypair: TenantKeypair) -> Router {
    common::research_app(SECRET, steward, steward_keypair, dev_attestation(), false).await
}

const PUBLISH_BODY: &str = r#"{
    "connector": "health",
    "title": "De-identified respiratory cohort extracts",
    "description": "Quarterly condition-level extracts. Aggregate queries only; k-suppression enforced.",
    "license_fee_cents": 120000,
    "compute_rate_cents": 40,
    "grant_budget": 25
}"#;

const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

#[tokio::test]
async fn publish_browse_request_approve_query_lifecycle() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

    // Steward publishes a priced listing.
    let (status, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    assert_eq!(listing["license_fee_cents"], 120000);
    assert_eq!(listing["compute_rate_cents"], 40);
    assert_eq!(listing["grant_budget"], 25);
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    // Researcher browses the catalog: pricing + platform currency visible.
    let (status, catalog) =
        call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(catalog["currency"], "USD");
    let listings = catalog["listings"].as_array().expect("listings");
    assert_eq!(listings.len(), 1);
    assert_eq!(
        listings[0]["title"],
        "De-identified respiratory cohort extracts"
    );

    // Researcher requests access with a stated purpose.
    let (status, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"IRB protocol 44-A, respiratory outcomes study"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request: {request}");
    assert_eq!(request["status"], "pending");
    let request_id = request["request_id"].as_str().expect("id").to_owned();

    // Repeat request while pending is idempotent.
    let (_, again) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"duplicate click"}"#,
    )
    .await;
    assert_eq!(again["request_id"].as_str().expect("id"), request_id);

    // Steward sees the pending request.
    let (status, inbox) = call(
        &app,
        "GET",
        "/api/v1/research/requests",
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox["requests"].as_array().expect("requests").len(), 1);

    // Approval mints the grant with the listing's included budget.
    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/approve"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    assert_eq!(resolved["request"]["status"], "approved");
    assert_eq!(resolved["grant"]["budget"]["limit"], 25);

    // Researcher sees the approval and can now run metered research queries.
    let (_, mine) = call(
        &app,
        "GET",
        "/api/v1/research/requests",
        &token_for(researcher),
        None,
    )
    .await;
    assert_eq!(mine["requests"][0]["status"], "approved");

    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 24);
    assert_eq!(body["suppressed_rows"], 1);
}

#[tokio::test]
async fn denial_records_outcome_and_leaves_no_access() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

    let (_, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    let (_, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    let request_id = request["request_id"].as_str().expect("id").to_owned();

    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/deny"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved["request"]["status"], "denied");

    // No grant was minted: research queries stay forbidden.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Denial doesn't block a fresh request (a new pending is created).
    let (status, fresh) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"revised protocol"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh["status"], "pending");
    assert_ne!(fresh["request_id"].as_str().expect("id"), request_id);
}

#[tokio::test]
async fn catalog_scoping_and_input_bounds() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

    let (_, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    // Steward cannot request access to their own listing.
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Only the steward can withdraw; others learn nothing.
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &token_for(outsider),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Withdrawn ⇒ invisible in the catalog and unrequestable (same 404 as
    // an id that never existed).
    let (_, catalog) = call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert!(catalog["listings"].as_array().expect("listings").is_empty());
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Input bounds: oversize title and note are refused, not truncated.
    let long_title = "t".repeat(121);
    let (status, _) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &format!(
            r#"{{"connector":"health","title":"{long_title}","license_fee_cents":0,"compute_rate_cents":0}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Republish, then an oversize request note is refused.
    post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let long_note = "n".repeat(1001);
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        &format!(r#"{{"note":"{long_note}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Only the listing's steward can approve a request; others (including
    // the researcher) get the same not-found as an unknown id.
    let (_, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    let request_id = request["request_id"].as_str().expect("id");
    for who in [researcher, outsider] {
        let (status, _) = post(
            &app,
            &format!("/api/v1/research/requests/{request_id}/approve"),
            &token_for(who),
            "{}",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn publishing_a_dataset_the_steward_does_not_hold_is_404() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let keypair = TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT);
    let key = keypair.public_key();
    let app = common::upload_research_app(
        SECRET,
        vec![(steward, keypair)],
        std::sync::Arc::new(platform_storage::ObjectStoreVault::new_in_memory()),
    );
    let publish = |dataset: &str| {
        format!(
            r#"{{"connector":"{dataset}","title":"Cohorts","license_fee_cents":0,"compute_rate_cents":0}}"#
        )
    };

    // Nothing uploaded yet, and a connector with no synced data: neither
    // is held, so no listing appears.
    for dataset in ["upload_cohorts", "quickbooks"] {
        let (status, body) = post(
            &app,
            "/api/v1/catalog",
            &token_for(steward),
            &publish(dataset),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{dataset}: {body}");
    }
    let (_, catalog) = call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert!(catalog["listings"].as_array().expect("listings").is_empty());

    // After an upload commits, the same publish succeeds.
    let upload = common::cohorts_upload(steward, &key, "upload_cohorts", None);
    let (status, body) = common::put_upload(
        &app,
        Some(&token_for(steward)),
        "upload_cohorts",
        upload.body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "upload: {body}");
    let (status, listing) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &publish("upload_cohorts"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    assert_eq!(listing["connector"], "upload_cohorts");

    // Holding is per tenant: the researcher holds no such dataset.
    let (status, _) = post(
        &app,
        "/api/v1/catalog",
        &token_for(researcher),
        &publish("upload_cohorts"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unpublish_is_the_stewards_alone_and_removes_the_listing() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

    let (_, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();
    let unpublish = |who: TenantId, id: String| {
        let app = app.clone();
        async move {
            call(
                &app,
                "DELETE",
                &format!("/api/v1/catalog/{id}"),
                &token_for(who),
                None,
            )
            .await
        }
    };
    let published_ids = || {
        let app = app.clone();
        async move {
            let (status, catalog) =
                call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
            assert_eq!(status, StatusCode::OK);
            catalog["listings"]
                .as_array()
                .expect("listings")
                .iter()
                .map(|l| l["listing_id"].as_str().expect("id").to_owned())
                .collect::<Vec<_>>()
        }
    };

    // Another tenant gets the same 404 as an unknown listing, and the
    // listing stays published.
    for who in [outsider, researcher] {
        let (status, body) = unpublish(who, listing_id.clone()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
    for unknown in ["00000000-0000-4000-8000-000000000000", "not-a-listing"] {
        let (status, body) = unpublish(steward, unknown.to_owned()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}: {body}");
    }
    assert_eq!(published_ids().await, std::slice::from_ref(&listing_id));

    // The steward unpublishes, and the listing leaves the catalog index.
    let (status, withdrawn) = unpublish(steward, listing_id.clone()).await;
    assert_eq!(status, StatusCode::OK, "{withdrawn}");
    assert_eq!(withdrawn["listing_id"], listing_id.as_str());
    assert_eq!(withdrawn["published"], false);
    assert!(published_ids().await.is_empty());
}

// ── Data dictionary ──

/// A publish of `dataset` whose `data_dictionary` is `dictionary`.
fn publish_with(dataset: &str, dictionary: Value) -> String {
    json!({
        "connector": dataset,
        "title": "Cohorts",
        "license_fee_cents": 0,
        "compute_rate_cents": 0,
        "data_dictionary": dictionary,
    })
    .to_string()
}

#[tokio::test]
async fn a_published_listing_carries_its_data_dictionary() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

    let dictionary = json!({ "columns": [
        { "name": "condition", "type": "string", "description": "  Diagnosis group  " },
        { "name": "age", "type": "int64" },
    ]});
    let (status, listing) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &publish_with("health", dictionary),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    let expected = json!({
        "table": "health",
        "columns": [
            { "name": "condition", "type": "string", "description": "Diagnosis group" },
            { "name": "age", "type": "int64", "description": "" },
        ],
    });
    assert_eq!(listing["data_dictionary"], expected);

    // Researchers browsing the catalog see it as published.
    let (_, catalog) = call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert_eq!(catalog["listings"][0]["data_dictionary"], expected);

    // A re-publish replaces it: without one, or with `null`, only the table
    // name is left.
    for body in [PUBLISH_BODY.to_owned(), publish_with("health", Value::Null)] {
        let (status, listing) = post(&app, "/api/v1/catalog", &token_for(steward), &body).await;
        assert_eq!(status, StatusCode::OK, "republish: {listing}");
        assert_eq!(
            listing["data_dictionary"],
            json!({ "table": "health", "columns": [] })
        );
    }
}

#[tokio::test]
async fn an_oversized_or_malformed_data_dictionary_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
    let column = |name: &str, description: &str| json!({ "name": name, "type": "int64", "description": description });

    // At every bound it is accepted: 512 columns, names of 128 bytes
    // (64 two-byte characters in the first) and descriptions of 500
    // characters (1000 bytes).
    let mut widest: Vec<Value> = (1..512)
        .map(|i| column(&format!("{i:0>128}"), &"é".repeat(500)))
        .collect();
    widest.insert(0, column(&"é".repeat(64), ""));
    let (status, listing) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &publish_with("health", json!({ "columns": widest })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "at the bounds");
    assert_eq!(
        listing["data_dictionary"]["columns"]
            .as_array()
            .expect("columns")
            .len(),
        512
    );
    // Withdrawn, so a refused publish below would show by reappearing.
    let listing_id = listing["listing_id"].as_str().expect("id");
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let too_many: Vec<Value> = (0..513).map(|i| column(&format!("c{i}"), "")).collect();
    let refusals = [
        // Over a bound, or not a column name: refused like other listing text.
        (
            "513 columns",
            json!({ "columns": too_many }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "an empty name",
            json!({ "columns": [column("", "")] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "a 129-byte name",
            json!({ "columns": [column(&"x".repeat(129), "")] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "65 two-byte characters",
            json!({ "columns": [column(&"é".repeat(65), "")] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "a control character",
            json!({ "columns": [column("tab\there", "")] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "a name twice",
            json!({ "columns": [column("age", ""), column("age", "years")] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            "a 501-character description",
            json!({ "columns": [column("age", &"d".repeat(501))] }),
            StatusCode::BAD_REQUEST,
        ),
        // Not a dictionary's shape: refused by the JSON extractor, a type
        // family it does not know and a table name the steward cannot set
        // included.
        (
            "an unknown type",
            json!({ "columns": [{ "name": "age", "type": "utf8" }] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "no type",
            json!({ "columns": [{ "name": "age" }] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "an unknown column field",
            json!({ "columns": [{ "name": "age", "type": "int64", "nullable": true }] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "a table name",
            json!({ "table": "health", "columns": [] }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "columns that are not a list",
            json!({ "columns": "age" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];
    for (case, dictionary, expected) in refusals {
        let (status, body) = post(
            &app,
            "/api/v1/catalog",
            &token_for(steward),
            &publish_with("health", dictionary),
        )
        .await;
        assert_eq!(status, expected, "{case}: {}", body["error"]);
    }
    let (_, catalog) = call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert_eq!(catalog["listings"], json!([]), "nothing was published");
}

#[tokio::test]
async fn a_digit_leading_hyphenated_slug_is_queried_by_its_quoted_table_name() {
    const DATASET: &str = "2026-cohorts";
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = common::research_app_for(
        SECRET,
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        dev_attestation(),
        false,
        DATASET,
    )
    .await;

    // The listing names the table as a query must write it.
    let columns = json!({ "columns": [
        { "name": "condition", "type": "string" },
        { "name": "age", "type": "int64" },
    ]});
    let (status, listing) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &publish_with(DATASET, columns),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    let table = listing["data_dictionary"]["table"]
        .as_str()
        .expect("table")
        .to_owned();
    assert_eq!(table, r#""2026-cohorts""#);

    let listing_id = listing["listing_id"].as_str().expect("id");
    let (_, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    let request_id = request["request_id"].as_str().expect("id");
    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/approve"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");

    let query = |sql: String| {
        let app = app.clone();
        let body = json!({ "steward_tenant": steward, "connector": DATASET, "sql": sql });
        async move {
            post(
                &app,
                "/api/v1/research/query",
                &token_for(researcher),
                &body.to_string(),
            )
            .await
        }
    };

    // The example query the portal shows runs as written.
    let (status, body) = query(format!("SELECT COUNT(*) AS n FROM {table}")).await;
    assert_eq!(status, StatusCode::OK, "quoted: {body}");
    assert_eq!(body["rows"], json!([{ "n": 7 }]));

    // Unquoted, the slug is a number minus a name, not the table: SQL that
    // cannot run, charged like any other.
    let (status, body) = query(format!("SELECT COUNT(*) AS n FROM {DATASET}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unquoted: {body}");
    assert_eq!(body["error"], "query could not be executed");
}

#[tokio::test]
async fn connectors_list_the_columns_each_mapper_writes() {
    // The route is static: it needs no research service.
    let app = build_app(common::app_state(
        SECRET,
        Arc::new(ObjectStoreVault::new_in_memory()),
    ));
    let (status, body) = call(
        &app,
        "GET",
        "/api/v1/connectors",
        &token_for(TenantId::generate()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let connectors = body["connectors"].as_array().expect("connectors");
    let find = |slug: &str| {
        connectors
            .iter()
            .find(|c| c["slug"] == slug)
            .unwrap_or_else(|| panic!("{slug} listed"))
    };
    assert_eq!(
        find("quickbooks")["columns"],
        json!([
            { "name": "id", "type": "string" },
            { "name": "customer", "type": "string" },
            { "name": "txn_date", "type": "string" },
            { "name": "currency", "type": "string" },
            { "name": "total", "type": "float64" },
            { "name": "balance", "type": "float64" },
        ])
    );
    assert_eq!(find("odoo")["kind"], "erp");
    assert_eq!(
        find("odoo")["columns"][3],
        json!({ "name": "is_company", "type": "boolean" })
    );
    // No mapper yet: nothing to pre-fill, so the steward types the columns.
    assert_eq!(find("research_extract")["columns"], json!([]));

    // Each list is the shape of the Parquet that connector writes, as the
    // engine's declared-schema check reads it.
    for source in [
        FixtureSource::quickbooks_demo(),
        FixtureSource::odoo_demo(),
        FixtureSource::crm_demo(),
    ] {
        let source = source.expect("fixture");
        let slug = source.descriptor().slug.to_string();
        let columns: Vec<DeclaredColumn> =
            serde_json::from_value(find(&slug)["columns"].clone()).expect("declared columns");
        let schema = DeclaredSchema::new(columns).expect("schema");
        let context = SyncContext {
            tenant: TenantId::generate(),
            since: None,
        };
        for dataset in source.fetch(&context).await.expect("fetch") {
            let parquet = dataset_to_parquet(&dataset).expect("parquet");
            let mut scope = QueryScope::new(EngineSettings {
                zk: ZkMode::Enabled,
                max_concurrent_queries: 1,
                limits: QueryLimits::default(),
            });
            let rows = u64::try_from(dataset.rows.len()).expect("rows");
            scope
                .register_parquet_declared("t", &[parquet.expose()], &schema, rows)
                .unwrap_or_else(|err| panic!("{slug}: {err}"));
        }
    }

    // Like every route, it needs an access token.
    let (status, _) = common::send(&app, "GET", "/api/v1/connectors", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
