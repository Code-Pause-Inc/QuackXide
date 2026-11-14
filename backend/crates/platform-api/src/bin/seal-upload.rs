//! DEV ONLY: plays the steward's browser for the simulated TEE. It seals a
//! seeded synthetic cohort (`synth-data`) to the steward's public key, as
//! the browser seals an upload (ADR 0012), and writes the body of
//! `PUT /api/v1/datasets/{dataset}` to stdout. It holds no private key and
//! sends nothing: `scripts/test-simulated-tee.sh` uploads the body. Built
//! only with the `dev` feature.
//!
//! Usage:
//!   seal-upload --tenant <uuid> --public-key <base64> --dataset <upload_name> [--k <k>] > body
//!
//! `--public-key` is the steward's raw public key in standard base64, as
//! `key-release`'s enrollment returns it. The cohort's groups are built
//! around `--k` (default 11), so with `RESEARCH_MIN_COHORT_SIZE` set to it
//! some are released and some suppressed. The sealing is
//! `platform_api::dev::seal_cohort_upload`, which the API tests also run.

use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_api::dev;
use platform_core::{ConnectorSlug, DatasetKind, TenantId};
use platform_crypto::TenantPublicKey;

const USAGE: &str = "usage: seal-upload --tenant <uuid> --public-key <base64> \
                     --dataset <upload_name> [--k <k>] > body";

struct Args {
    tenant: TenantId,
    key: TenantPublicKey,
    dataset: ConnectorSlug,
    k: usize,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<Args> {
    let (mut tenant, mut key, mut dataset) = (None, None, None);
    let mut k = synth_data::DEFAULT_K;
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--tenant" => tenant = Some(value.parse().context("--tenant is not a tenant id")?),
            "--public-key" => {
                let raw = B64
                    .decode(value.trim())
                    .context("--public-key is not base64")?;
                key = Some(
                    TenantPublicKey::from_raw(&raw).context("--public-key is not a public key")?,
                );
            }
            "--dataset" => {
                let slug = ConnectorSlug::new(&value).context("--dataset is not a dataset id")?;
                // The browser uploads only into the upload namespace.
                if slug.kind() != DatasetKind::Upload {
                    bail!(
                        "--dataset must start with {}",
                        platform_core::UPLOAD_DATASET_PREFIX
                    );
                }
                dataset = Some(slug);
            }
            "--k" => k = value.parse().context("--k is not a number")?,
            _ => bail!("unknown argument {flag}\n{USAGE}"),
        }
    }
    Ok(Args {
        tenant: tenant.context(USAGE)?,
        key: key.context(USAGE)?,
        dataset: dataset.context(USAGE)?,
        k,
    })
}

fn main() -> anyhow::Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    let mut stdout = std::io::stdout().lock();
    if stdout.is_terminal() {
        bail!("the upload body is binary; redirect stdout to a file\n{USAGE}");
    }
    let sealed = dev::seal_cohort_upload(args.tenant, &args.key, &args.dataset, args.k)?;
    stdout.write_all(&sealed.body)?;
    stdout.flush()?;
    eprintln!(
        "sealed {} for tenant {}: version {}, object {}, {} bytes",
        args.dataset,
        args.tenant,
        sealed.version,
        sealed.object,
        sealed.body.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_crypto::TenantKeypair;

    /// `--tenant`, `--public-key` and `--dataset` with these values.
    fn flags(tenant: &str, key: &str, dataset: &str) -> Vec<String> {
        [
            "--tenant",
            tenant,
            "--public-key",
            key,
            "--dataset",
            dataset,
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn tenant_and_key() -> (String, String) {
        let key = TenantKeypair::generate().public_key().to_raw();
        (TenantId::generate().to_string(), B64.encode(key))
    }

    #[test]
    fn a_steward_key_and_an_upload_dataset_are_accepted() {
        let (tenant, key) = tenant_and_key();
        let given = flags(&tenant, &key, "upload_cohort");
        let args = parse_args(given.clone().into_iter()).expect("args");
        assert_eq!(args.tenant.to_string(), tenant);
        assert_eq!(args.key.to_raw(), B64.decode(&key).expect("key"));
        assert_eq!(args.dataset.as_str(), "upload_cohort");
        assert_eq!(args.k, synth_data::DEFAULT_K);
        let with_k = [given, vec!["--k".into(), "2".into()]].concat();
        assert_eq!(parse_args(with_k.into_iter()).expect("args").k, 2);
    }

    #[test]
    fn incomplete_or_malformed_arguments_are_refused() {
        let (tenant, key) = tenant_and_key();
        let valid = flags(&tenant, &key, "upload_cohort");
        let cases = [
            ("a connector dataset", flags(&tenant, &key, "quickbooks")),
            ("not a dataset id", flags(&tenant, &key, "upload.cohort")),
            ("not a public key", flags(&tenant, "AAAA", "upload_cohort")),
            ("not a tenant id", flags("steward", &key, "upload_cohort")),
            (
                "an unknown flag",
                [valid.clone(), vec!["--rows".into(), "5".into()]].concat(),
            ),
            ("a flag without a value", valid[..5].to_vec()),
            ("no dataset", valid[..4].to_vec()),
        ];
        for (case, args) in cases {
            assert!(parse_args(args.into_iter()).is_err(), "{case}");
        }
    }
}
