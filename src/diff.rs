//! Diff mode: compare two binaries and show what changed.
//!
//! The motivating case is tampering — a pirated or trojanized copy of an app
//! against the official one. Addresses and compiler details shift between
//! builds, so diffing raw bytes is useless; instead we compare *behavioral*
//! sets: imported functions, referenced strings, named functions, and the
//! findings each binary raises. New imports/strings/findings in the second
//! binary are what an injected payload looks like.

use crate::analysis::VerdictLevel;
use crate::graph;
use crate::scan::{Engine, prepare};
use std::collections::BTreeSet;
use std::path::Path;

pub struct Fingerprint {
    pub imports: BTreeSet<String>,
    pub strings: BTreeSet<String>,
    pub functions: BTreeSet<String>,
    pub findings: BTreeSet<String>,
    pub verdict: VerdictLevel,
}

/// Builds the behavioral fingerprint of one binary.
pub fn fingerprint(engine: &Engine, path: &Path) -> Result<Fingerprint, String> {
    let report = engine.scan_file(path).map_err(|e| e.to_string())?;
    let findings = report.findings.iter().map(|f| f.id.clone()).collect();

    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut program = crate::formats::parse(&data).map_err(|e| e.to_string())?;
    prepare(&mut program);

    let mut imports = BTreeSet::new();
    let mut strings = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for obj in &program.objects {
        let g = graph::build(obj);
        for f in g.functions.values() {
            imports.extend(f.imports.iter().cloned());
            strings.extend(f.strings.iter().cloned());
            // Only named functions are comparable across builds; sub_<addr>
            // names are build-specific noise.
            if !f.name.starts_with("sub_") {
                functions.insert(f.name.clone());
            }
        }
    }

    Ok(Fingerprint {
        imports,
        strings,
        functions,
        findings,
        verdict: report.verdict.level,
    })
}

fn print_set(title: &str, items: &BTreeSet<String>, limit: usize) {
    if items.is_empty() {
        return;
    }
    println!("{title} ({})", items.len());
    for s in items.iter().take(limit) {
        println!("    + {}", truncate(s, 100));
    }
    if items.len() > limit {
        println!("    … and {} more", items.len() - limit);
    }
}

/// Compares two binaries and prints the behavioral differences. Returns true
/// if the second binary gained anything (added imports/strings/findings).
pub fn diff(engine: &Engine, a: &Path, b: &Path) -> Result<bool, String> {
    let fa = fingerprint(engine, a)?;
    let fb = fingerprint(engine, b)?;

    println!(
        "A: {}  [{:?}]\nB: {}  [{:?}]\n",
        a.display(),
        fa.verdict,
        b.display(),
        fb.verdict
    );

    let added_imports: BTreeSet<_> = fb.imports.difference(&fa.imports).cloned().collect();
    let added_strings: BTreeSet<_> = fb.strings.difference(&fa.strings).cloned().collect();
    let added_funcs: BTreeSet<_> = fb.functions.difference(&fa.functions).cloned().collect();
    let added_findings: BTreeSet<_> = fb.findings.difference(&fa.findings).cloned().collect();
    let removed_findings: BTreeSet<_> = fa.findings.difference(&fb.findings).cloned().collect();

    println!("== added in B (what a tampered copy would introduce) ==");
    print_set("imports", &added_imports, 30);
    print_set("strings", &added_strings, 30);
    print_set("named functions", &added_funcs, 30);
    print_set("findings", &added_findings, 30);

    if !removed_findings.is_empty() {
        println!("\n== only in A ==");
        print_set("findings", &removed_findings, 30);
    }

    let gained =
        !added_imports.is_empty() || !added_strings.is_empty() || !added_findings.is_empty();
    if !gained {
        println!("\nNo new imports, strings or findings in B.");
    } else if !added_findings.is_empty() {
        println!("\nB raises new findings not present in A — treat as tampered until explained.");
    }
    Ok(gained)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}
