//! Writes a seeded synthetic dataset to a Parquet file. Dev-only: every value
//! is invented, and the output is for tests, benchmarks and demos
//! (`docs/DATA_POLICY.md`).
//!
//! Usage, from `backend/`:
//!   cargo run -p synth-data -- --schema cohort --seed 7 --rows 1000
//!   cargo run -p synth-data -- --schema cohort --seed 7 --rows 200 --k 5
//!   cargo run --release -p synth-data -- --schema wide --seed 1 --rows 10000000
//!   cargo run -p synth-data -- --schema cohort --seed 7 --rows 100 \
//!       --out crates/synth-data/fixtures/cohort-k11-seed7-rows100.parquet
//!
//! Without `--out` the file goes to `backend/target/synth-data/`, which is
//! gitignored, under a name built from the arguments. The path is printed on
//! stdout, and the command that writes the same file again on stderr, ready
//! to record next to a committed fixture. A bad command line exits with 2
//! and writes nothing; a failed write exits with 1 and leaves no file behind.

use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use synth_data::{DEFAULT_K, SchemaName, Spec};

/// Flags that take a value. `-h` and `--help` print the usage.
const FLAGS: [&str; 5] = ["--schema", "--seed", "--rows", "--k", "--out"];

fn main() -> ExitCode {
    let args = match parse_args(env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("synth-data: {message}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let out = args.out.clone().unwrap_or_else(|| default_out(&args.spec));
    if let Err(message) = write_atomically(&args.spec, &out) {
        eprintln!("synth-data: {message}");
        return ExitCode::FAILURE;
    }
    eprintln!("wrote {} {} rows", args.spec.rows, args.spec.schema);
    eprintln!("regenerate with: {}", command_line(&args));
    if out.components().any(|part| part.as_os_str() == "fixtures") {
        eprintln!("record the schema and that command next to the file (docs/DATA_POLICY.md)");
    }
    println!("{}", out.display());
    ExitCode::SUCCESS
}

/// A parsed and validated command line.
struct Args {
    spec: Spec,
    /// `--out`, if given.
    out: Option<PathBuf>,
}

/// Reads `--flag value` pairs. `Ok(None)` means help was asked for. Unknown,
/// repeated and valueless flags are refused, and so is anything
/// [`Spec::validate`] refuses, so a bad command line writes nothing.
fn parse_args(raw: impl IntoIterator<Item = String>) -> Result<Option<Args>, String> {
    let mut raw = raw.into_iter();
    let mut given: Vec<(String, String)> = Vec::new();
    while let Some(flag) = raw.next() {
        if flag == "-h" || flag == "--help" {
            return Ok(None);
        }
        if !FLAGS.contains(&flag.as_str()) {
            return Err(format!("unknown argument {flag:?}"));
        }
        if given.iter().any(|(seen, _)| *seen == flag) {
            return Err(format!("{flag} is given more than once"));
        }
        let value = raw
            .next()
            .filter(|value| !value.is_empty() && !value.starts_with("--"))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        given.push((flag, value));
    }

    let schema = required(&given, "--schema")?
        .parse::<SchemaName>()
        .map_err(|e| e.to_string())?;
    let seed: u64 = number("--seed", required(&given, "--seed")?)?;
    let rows: usize = number("--rows", required(&given, "--rows")?)?;
    let mut spec = Spec::new(schema, seed, rows);
    if let Some(k) = lookup(&given, "--k") {
        if schema != SchemaName::Cohort {
            return Err("--k applies only to the cohort schema".to_owned());
        }
        spec = spec.with_k(number("--k", k)?);
    }
    spec.validate().map_err(|e| e.to_string())?;
    Ok(Some(Args {
        spec,
        out: lookup(&given, "--out").map(PathBuf::from),
    }))
}

fn lookup<'a>(given: &'a [(String, String)], flag: &str) -> Option<&'a str> {
    given
        .iter()
        .find(|(name, _)| name == flag)
        .map(|(_, value)| value.as_str())
}

fn required<'a>(given: &'a [(String, String)], flag: &str) -> Result<&'a str, String> {
    lookup(given, flag).ok_or_else(|| format!("{flag} is required"))
}

fn number<T>(flag: &str, value: &str) -> Result<T, String>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    value
        .parse()
        .map_err(|e| format!("{flag} {value:?} is not a valid number: {e}"))
}

fn usage() -> String {
    format!(
        "usage: synth-data --schema <{schemas}> --seed <u64> --rows <n> [--k <k>] [--out <path>]\n\
         from backend/: cargo run -p synth-data -- <arguments>\n\
         \n  --schema  cohort (health-style, built around k) or wide (for benchmarks)\
         \n  --seed    seeds every random choice\
         \n  --rows    total rows; the cohort needs at least 9k + 1\
         \n  --k       cohort threshold, default {DEFAULT_K}\
         \n  --out     output file, default {dir}/<name>.parquet\
         \n  --help    print this and exit",
        schemas = SchemaName::ALL.map(SchemaName::name).join("|"),
        dir = default_dir().display(),
    )
}

/// `backend/target/synth-data`, found from this crate's own directory so it
/// does not depend on where cargo runs. `target/` is gitignored.
fn default_dir() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .ancestors()
        .nth(2)
        .unwrap_or(crate_dir)
        .join("target")
        .join("synth-data")
}

/// The default output file, named after the arguments.
fn default_out(spec: &Spec) -> PathBuf {
    let name = match spec.schema {
        SchemaName::Cohort => {
            format!(
                "cohort-k{}-seed{}-rows{}.parquet",
                spec.k, spec.seed, spec.rows
            )
        }
        SchemaName::Wide => format!("wide-seed{}-rows{}.parquet", spec.seed, spec.rows),
    };
    default_dir().join(name)
}

/// The command that writes the same file again, for the record
/// `docs/DATA_POLICY.md` asks for next to a committed fixture.
fn command_line(args: &Args) -> String {
    let spec = &args.spec;
    let mut parts = vec![
        "cargo run -p synth-data --".to_owned(),
        format!("--schema {}", spec.schema),
        format!("--seed {}", spec.seed),
        format!("--rows {}", spec.rows),
    ];
    if spec.schema == SchemaName::Cohort {
        parts.push(format!("--k {}", spec.k));
    }
    if let Some(out) = &args.out {
        parts.push(format!("--out {}", out.display()));
    }
    parts.join(" ")
}

/// Writes `<out>.partial` and renames it to `out`, so a failed or
/// interrupted run never leaves a truncated file under the real name.
fn write_atomically(spec: &Spec, out: &Path) -> Result<(), String> {
    if let Some(dir) = out.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let mut partial = out.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let written = write_then_rename(spec, &partial, out);
    if written.is_err() {
        // Best effort: the partial file may never have been created.
        let _ = fs::remove_file(partial);
    }
    written
}

fn write_then_rename(spec: &Spec, tmp: &Path, out: &Path) -> Result<(), String> {
    let file = File::create(tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    let mut writer = BufWriter::new(file);
    synth_data::write_parquet(spec, &mut writer).map_err(|e| e.to_string())?;
    // Flushes, then drops the file, so it is closed before the rename.
    writer
        .into_inner()
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(tmp, out).map_err(|e| format!("cannot rename to {}: {e}", out.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Result<Option<Args>, String> {
        parse_args(line.split_whitespace().map(str::to_owned))
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("synth-data-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn reads_a_full_command_line() {
        let args = parse("--schema cohort --seed 7 --rows 200 --k 5")
            .expect("valid")
            .expect("not help");
        assert_eq!(args.spec, Spec::new(SchemaName::Cohort, 7, 200).with_k(5));
        assert!(args.out.is_none());
        assert_eq!(
            command_line(&args),
            "cargo run -p synth-data -- --schema cohort --seed 7 --rows 200 --k 5"
        );
    }

    #[test]
    fn echoes_an_explicit_out_path() {
        let args = parse("--schema wide --seed 1 --rows 10 --out x/y.parquet")
            .expect("valid")
            .expect("not help");
        assert_eq!(
            command_line(&args),
            "cargo run -p synth-data -- --schema wide --seed 1 --rows 10 --out x/y.parquet"
        );
    }

    #[test]
    fn help_writes_nothing() {
        assert!(matches!(parse("--rows 5 --help"), Ok(None)));
    }

    #[test]
    fn refuses_bad_command_lines() {
        for line in [
            "",
            "--schema cohort --seed 7",
            "--schema cohort --seed 7 --rows 200 --color red",
            "--schema cohort --schema wide --seed 7 --rows 200",
            "--schema cohort --seed --rows 200",
            "--schema cohort --seed 7 --rows",
            "--schema cohort --seed -7 --rows 200",
            "--schema cohort --seed 7 --rows lots",
            "--schema bogus --seed 7 --rows 200",
            "--schema wide --seed 7 --rows 200 --k 5",
            "--schema cohort --seed 7 --rows 99",
            "--schema cohort --seed 7 --rows 200 --k 1",
            "--schema wide --seed 7 --rows 0",
        ] {
            assert!(parse(line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn default_output_is_under_backend_target() {
        let out = default_out(&Spec::new(SchemaName::Wide, 3, 10));
        assert!(out.ends_with("backend/target/synth-data/wide-seed3-rows10.parquet"));
    }

    #[test]
    fn writes_the_file_and_leaves_no_partial() {
        let dir = scratch_dir("written");
        let out = dir.join("cohort.parquet");
        write_atomically(&Spec::new(SchemaName::Cohort, 1, 100), &out).expect("written");
        assert!(out.is_file());
        assert!(!dir.join("cohort.parquet.partial").exists());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn failed_write_leaves_nothing_behind() {
        let dir = scratch_dir("failed");
        // A non-empty directory where the file should go makes the rename fail.
        let out = dir.join("taken");
        fs::create_dir_all(out.join("inside")).expect("blocker");
        assert!(write_atomically(&Spec::new(SchemaName::Wide, 1, 10), &out).is_err());
        assert!(!dir.join("taken.partial").exists());
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
