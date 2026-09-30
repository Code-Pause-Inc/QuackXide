# QuackXide — Data Policy

This repository, its issues, its pull requests, and every development and
test environment use **synthetic or public data only**.

## Rules

1. **No protected health information (PHI).** No data covered by HIPAA, and
   no data derived from real patients, participants, or medical records, in
   any form: raw, de-identified, pseudonymized, aggregated, sampled, or
   "just for a quick test". De-identified health data can often be
   re-identified, so it is treated as PHI here.
2. **No other personal data.** No real names, email addresses, phone
   numbers, addresses, government identifiers, or financial records.
   Fixtures use obviously fake values (for example `alex@lead-one.example`,
   "Alex Sample") on reserved `.example` domains.
3. **No credentials.** No API keys, tokens, private keys, passwords, or
   `.env` files. Only `*.env.example` templates with empty values are
   committed.
4. **Public datasets only with a license that allows it.** A public dataset
   may be used when its license permits redistribution and its source and
   license are recorded next to it.
5. **Data files live in `fixtures/` directories.** Tabular and binary data
   files (CSV, TSV, Parquet, NDJSON, JSONL, Excel, statistical-package
   formats, genomic and imaging formats) are committed only under a
   `fixtures/` directory, and only when small and synthetic.

## Enforcement

* `scripts/check.sh` fails if a data file is tracked outside a `fixtures/`
  directory.
* Pull requests are reviewed for data content.
* If real or sensitive data is committed by mistake, do not try to fix it
  with a follow-up commit alone: report it immediately as described in
  `SECURITY.md`. The history will be rewritten and any exposed credential
  rotated.

## Generating test data

Generate synthetic data with a fixed seed so tests are reproducible, keep
the generator in the repository, and describe the schema in a comment next
to the fixture. Cohort sizes in fixtures should exercise both sides of the
suppression threshold (`RESEARCH_MIN_COHORT_SIZE`).
