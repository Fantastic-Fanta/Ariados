//! Accuracy measurement.
//!
//! Detection quality is meaningless as an assertion and only meaningful as a
//! measurement, so `eval` runs the scanner over labeled corpora and reports the
//! numbers:
//!
//!   * a **benign** corpus — the machine's own system binaries, which should
//!     almost never be flagged; anything flagged is a false positive to fix;
//!   * an optional **malicious** corpus (handled only inside a VM) — the
//!     detection rate.
//!
//! It also prints which behaviors fired how often, so a noisy rule is obvious.

use crate::analysis::VerdictLevel;
use crate::scan::{collect_targets, Engine};
use std::collections::BTreeMap;
use std::path::Path;

pub struct CorpusResult {
    pub total: usize,
    pub flagged: usize,
    pub errors: usize,
    /// finding id -> how many files it fired in.
    pub behavior_counts: BTreeMap<String, usize>,
    /// (path, level, score) for each flagged file.
    pub flagged_files: Vec<(String, VerdictLevel, u32)>,
}

/// Scans every binary under `dirs`, counting files at or above `flag_at`.
pub fn run_corpus(engine: &Engine, dirs: &[&Path], flag_at: VerdictLevel) -> CorpusResult {
    let mut res = CorpusResult {
        total: 0,
        flagged: 0,
        errors: 0,
        behavior_counts: BTreeMap::new(),
        flagged_files: Vec::new(),
    };
    for dir in dirs {
        for target in collect_targets(dir) {
            match engine.scan_file(&target) {
                Ok(r) => {
                    res.total += 1;
                    for f in &r.findings {
                        *res.behavior_counts.entry(f.id.clone()).or_default() += 1;
                    }
                    if r.verdict.level >= flag_at {
                        res.flagged += 1;
                        res.flagged_files.push((r.path, r.verdict.level, r.verdict.score));
                    }
                }
                Err(_) => res.errors += 1,
            }
        }
    }
    res
}

/// Runs an evaluation and prints a human-readable summary.
pub fn report(
    engine: &Engine,
    benign: &[&Path],
    malicious: &[&Path],
    flag_at: VerdictLevel,
) {
    println!("Evaluation (flagging at: {:?})\n", flag_at);

    let b = run_corpus(engine, benign, flag_at);
    let fp_rate = pct(b.flagged, b.total);
    println!("Benign corpus: {} files, {} errors", b.total, b.errors);
    println!("  false positives: {} ({fp_rate:.2}%)", b.flagged);
    if !b.behavior_counts.is_empty() {
        println!("  behaviors fired (benign — ideally all low counts):");
        let mut counts: Vec<_> = b.behavior_counts.iter().collect();
        counts.sort_by(|a, c| c.1.cmp(a.1));
        for (id, n) in counts.iter().take(12) {
            println!("    {n:>5}  {id}");
        }
    }
    if !b.flagged_files.is_empty() {
        println!("  flagged benign files (first 20):");
        for (p, lvl, score) in b.flagged_files.iter().take(20) {
            println!("    [{:?} {score}] {p}", lvl);
        }
    }

    if !malicious.is_empty() {
        let m = run_corpus(engine, malicious, flag_at);
        let det = pct(m.flagged, m.total);
        println!("\nMalicious corpus: {} files, {} errors", m.total, m.errors);
        println!("  detected: {} ({det:.2}%)", m.flagged);
        if m.total > b.total.max(1) {
            // nothing
        }
    }
}

fn pct(n: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        n as f64 * 100.0 / total as f64
    }
}
