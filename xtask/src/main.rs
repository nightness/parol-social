//! xtask — workspace tooling.
//!
//! Current commands:
//!   * `clauses` — compute spec-clause coverage across PNP-001..PNP-009.
//!   * `clauses --check` — fail if MUST coverage < threshold. Used in CI.
//!   * `clauses --report` — rewrite the coverage column of specs/SPEC-INDEX.md.
//!   * `vectors --validate` — parse every specs/vectors/PNP-XXX/*.json and
//!     ensure its declared `clause` field references a real clause ID.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(about = "ParolNet workspace tooling", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute spec-clause coverage.
    Clauses {
        /// Fail with exit code 1 if any MUST clause is uncovered.
        #[arg(long)]
        check: bool,
        /// Rewrite the coverage column of specs/SPEC-INDEX.md.
        #[arg(long)]
        report: bool,
    },
    /// Validate that every specs/vectors/PNP-XXX/*.json parses and
    /// references a real clause ID.
    Vectors {
        #[arg(long)]
        validate: bool,
    },
}

fn workspace_root() -> PathBuf {
    // xtask binary runs with CWD set to workspace root when invoked via alias.
    // Fall back to CARGO_MANIFEST_DIR/.. for manual `cargo run -p xtask` calls.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if cwd.join("specs").is_dir() && cwd.join("Cargo.toml").is_file() {
        return cwd;
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Clauses { check, report } => run_clauses(check, report),
        Cmd::Vectors { validate } => run_vectors(validate),
    }
}

// ---- clause coverage ------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct ClauseSet {
    must: BTreeSet<String>,
    should: BTreeSet<String>,
    may: BTreeSet<String>,
}

impl ClauseSet {
    fn insert(&mut self, id: &str) {
        if id.contains("-MUST-") {
            self.must.insert(id.to_string());
        } else if id.contains("-SHOULD-") {
            self.should.insert(id.to_string());
        } else if id.contains("-MAY-") {
            self.may.insert(id.to_string());
        }
    }
    #[allow(dead_code)]
    fn total(&self) -> usize {
        self.must.len() + self.should.len() + self.may.len()
    }
}

fn clause_regex() -> Regex {
    Regex::new(r"\bPNP-(\d{3})-(MUST|SHOULD|MAY)-(\d{3})\b").unwrap()
}

fn collect_spec_clauses(root: &Path) -> Result<BTreeMap<String, ClauseSet>> {
    let re = clause_regex();
    let mut out: BTreeMap<String, ClauseSet> = BTreeMap::new();
    let specs = root.join("specs");
    for e in WalkDir::new(&specs).max_depth(1) {
        let e = e?;
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !fname.starts_with("PNP-") {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        for cap in re.captures_iter(&text) {
            let spec = format!("PNP-{}", &cap[1]);
            let id = cap[0].to_string();
            out.entry(spec).or_default().insert(&id);
        }
    }
    Ok(out)
}

fn collect_conformance_clauses(root: &Path) -> Result<BTreeSet<String>> {
    // Scan only the conformance crate's tests/ and src/ for #[clause(...)].
    let re = Regex::new(r#"#\[clause\(([^)]*)\)\]"#).unwrap();
    let id_re = clause_regex();
    let mut out = BTreeSet::new();
    let dirs = [
        root.join("crates/parolnet-conformance/tests"),
        root.join("crates/parolnet-conformance/src"),
    ];
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for e in WalkDir::new(&dir) {
            let e = e?;
            if !e.file_type().is_file() {
                continue;
            }
            if e.path().extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(e.path())
                .with_context(|| format!("read {}", e.path().display()))?;
            for cap in re.captures_iter(&text) {
                for id_cap in id_re.captures_iter(&cap[1]) {
                    out.insert(id_cap[0].to_string());
                }
            }
        }
    }
    Ok(out)
}

struct Coverage {
    spec: String,
    must_total: usize,
    must_covered: usize,
    should_total: usize,
    should_covered: usize,
    may_total: usize,
    may_covered: usize,
}

impl Coverage {
    fn must_pct(&self) -> f64 {
        if self.must_total == 0 {
            100.0
        } else {
            100.0 * self.must_covered as f64 / self.must_total as f64
        }
    }
    fn should_pct(&self) -> f64 {
        if self.should_total == 0 {
            100.0
        } else {
            100.0 * self.should_covered as f64 / self.should_total as f64
        }
    }
}

fn run_clauses(check: bool, report: bool) -> Result<()> {
    let root = workspace_root();
    let spec = collect_spec_clauses(&root)?;
    let covered = collect_conformance_clauses(&root)?;

    let mut rows: Vec<Coverage> = Vec::new();
    for (spec_name, set) in &spec {
        let must_covered = set.must.iter().filter(|id| covered.contains(*id)).count();
        let should_covered = set.should.iter().filter(|id| covered.contains(*id)).count();
        let may_covered = set.may.iter().filter(|id| covered.contains(*id)).count();
        rows.push(Coverage {
            spec: spec_name.clone(),
            must_total: set.must.len(),
            must_covered,
            should_total: set.should.len(),
            should_covered,
            may_total: set.may.len(),
            may_covered,
        });
    }
    rows.sort_by(|a, b| a.spec.cmp(&b.spec));

    println!("{:<10}  {:>12}  {:>14}  {:>11}", "Spec", "MUST", "SHOULD", "MAY");
    println!("{}", "-".repeat(54));
    let mut total_must = 0usize;
    let mut total_must_cov = 0usize;
    let mut total_should = 0usize;
    let mut total_should_cov = 0usize;
    let mut uncovered_must: Vec<String> = Vec::new();
    for r in &rows {
        println!(
            "{:<10}  {:>4}/{:<4} {:>4.0}%  {:>4}/{:<4} {:>4.0}%  {:>2}/{:<2} {:>4.0}%",
            r.spec,
            r.must_covered,
            r.must_total,
            r.must_pct(),
            r.should_covered,
            r.should_total,
            r.should_pct(),
            r.may_covered,
            r.may_total,
            if r.may_total == 0 {
                100.0
            } else {
                100.0 * r.may_covered as f64 / r.may_total as f64
            }
        );
        total_must += r.must_total;
        total_must_cov += r.must_covered;
        total_should += r.should_total;
        total_should_cov += r.should_covered;
        if let Some(cs) = spec.get(&r.spec) {
            for id in &cs.must {
                if !covered.contains(id) {
                    uncovered_must.push(id.clone());
                }
            }
        }
    }
    println!("{}", "-".repeat(54));
    let must_pct = if total_must == 0 {
        100.0
    } else {
        100.0 * total_must_cov as f64 / total_must as f64
    };
    let should_pct = if total_should == 0 {
        100.0
    } else {
        100.0 * total_should_cov as f64 / total_should as f64
    };
    println!(
        "TOTAL       {:>4}/{:<4} {:>4.0}%  {:>4}/{:<4} {:>4.0}%",
        total_must_cov, total_must, must_pct, total_should_cov, total_should, should_pct
    );

    if report {
        rewrite_spec_index(&root, &rows)?;
        println!("\nRewrote specs/SPEC-INDEX.md coverage column.");
    }

    if check {
        if total_must_cov < total_must {
            eprintln!(
                "\nclause check FAILED: {} MUST clauses uncovered",
                uncovered_must.len()
            );
            let limit = std::env::var("XTASK_FULL").is_ok();
            let shown = if limit { uncovered_must.len() } else { 20.min(uncovered_must.len()) };
            for id in uncovered_must.iter().take(shown) {
                eprintln!("  uncovered: {id}");
            }
            if !limit && uncovered_must.len() > 20 {
                eprintln!("  ... {} more (set XTASK_FULL=1 to see all)", uncovered_must.len() - 20);
            }
            std::process::exit(1);
        }
        if should_pct < 80.0 {
            eprintln!(
                "\nclause check FAILED: SHOULD coverage {should_pct:.1}% < 80% threshold"
            );
            std::process::exit(1);
        }
        println!("\nclause check PASSED");
    }

    Ok(())
}

fn rewrite_spec_index(root: &Path, rows: &[Coverage]) -> Result<()> {
    let p = root.join("specs/SPEC-INDEX.md");
    let text = std::fs::read_to_string(&p)?;
    let mut out_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(spec) = line_spec(line) {
            if let Some(r) = rows.iter().find(|r| r.spec == spec) {
                out_lines.push(update_row_line(line, r));
                continue;
            }
        }
        out_lines.push(line.to_string());
    }
    let mut out = out_lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(&p, out)?;
    Ok(())
}

fn line_spec(line: &str) -> Option<String> {
    let re = Regex::new(r"^\|\s*(PNP-\d{3})\s*\|").unwrap();
    re.captures(line).map(|c| c[1].to_string())
}

fn update_row_line(line: &str, r: &Coverage) -> String {
    let cols: Vec<&str> = line.split('|').collect();
    if cols.len() < 11 {
        return line.to_string();
    }
    let cov_pct = r.must_pct();
    let cov = format!(" {:.0}% M / {:.0}% S ", cov_pct, r.should_pct());
    let mut new_cols: Vec<String> = cols.iter().map(|s| s.to_string()).collect();
    let last = new_cols.len() - 2;
    new_cols[last] = cov;
    new_cols.join("|")
}

// ---- vectors --------------------------------------------------------------

fn run_vectors(_validate: bool) -> Result<()> {
    let root = workspace_root();
    let vectors_root = root.join("specs/vectors");
    if !vectors_root.is_dir() {
        println!("no specs/vectors directory yet — skipping");
        return Ok(());
    }
    let clause_ids: BTreeSet<String> = collect_spec_clauses(&root)?
        .into_values()
        .flat_map(|cs| {
            cs.must
                .into_iter()
                .chain(cs.should.into_iter())
                .chain(cs.may.into_iter())
        })
        .collect();

    let mut count = 0usize;
    let mut bad = 0usize;
    for e in WalkDir::new(&vectors_root) {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        if e.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let raw = std::fs::read_to_string(e.path())?;
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("{}: parse failed — {err}", e.path().display());
                bad += 1;
                continue;
            }
        };
        let clause = v.get("clause").and_then(|c| c.as_str()).unwrap_or("");
        if !clause_regex().is_match(clause) {
            eprintln!("{}: invalid `clause` field {clause:?}", e.path().display());
            bad += 1;
            continue;
        }
        if !clause_ids.contains(clause) {
            eprintln!(
                "{}: `clause` {clause} does not match any published spec clause",
                e.path().display()
            );
            bad += 1;
        }
    }
    println!("scanned {count} vectors — {bad} failed");
    if bad > 0 {
        std::process::exit(1);
    }
    Ok(())
}
