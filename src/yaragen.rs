//! Auto-generate a YARA rule from a sample — and prove it.
//!
//! Writing a detection rule is easy; writing one that catches the sample
//! *without* firing on every clean file is the hard part, and it's usually done
//! by eyeballing. Here we pick the sample's most distinctive strings, build a
//! rule from them, then validate it: it must match the sample and must match
//! none of a set of known-clean binaries. A rule that fails validation is
//! reported as too generic rather than silently shipped.

use crate::graph;
use crate::scan::prepare;
use crate::yara::YaraEngine;
use std::collections::BTreeSet;
use std::path::Path;

pub struct GenResult {
    pub rule: String,
    pub strings_used: usize,
    pub matched_sample: bool,
    /// Clean binaries the rule wrongly matched (empty = rule is specific).
    pub clean_hits: Vec<String>,
}

/// Default known-clean binaries to validate against when the caller gives none.
const DEFAULT_CLEAN: &[&str] = &["/bin/ls", "/bin/cat", "/usr/bin/true", "/bin/zsh"];

/// Generates a rule from `path` and validates it against the clean set.
pub fn generate(path: &Path, clean: &[std::path::PathBuf]) -> Result<GenResult, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut program = crate::formats::parse(&data).map_err(|e| e.to_string())?;
    prepare(&mut program);

    let strings = distinctive_strings(&program, 8);
    if strings.len() < 2 {
        return Err("not enough distinctive strings to build a rule".into());
    }

    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sample");
    let rule = build_rule(name, &program.sha256, &strings);

    // Validate.
    let engine = YaraEngine::from_source(&rule)
        .map_err(|e| format!("generated rule failed to compile: {e}"))?;
    let matched_sample = !engine.matching(&data).is_empty();

    let clean_paths: Vec<std::path::PathBuf> = if clean.is_empty() {
        DEFAULT_CLEAN.iter().map(std::path::PathBuf::from).collect()
    } else {
        clean
            .iter()
            .flat_map(|d| crate::scan::collect_targets(d))
            .collect()
    };
    let mut clean_hits = Vec::new();
    for c in &clean_paths {
        if let Ok(bytes) = std::fs::read(c)
            && !engine.matching(&bytes).is_empty()
        {
            clean_hits.push(c.display().to_string());
        }
    }

    Ok(GenResult {
        rule,
        strings_used: strings.len(),
        matched_sample,
        clean_hits,
    })
}

/// Picks the most distinctive strings: long, specific, and favoring indicators
/// (URLs, paths, commands) over generic tokens.
fn distinctive_strings(program: &crate::model::Program, max: usize) -> Vec<String> {
    let mut all: BTreeSet<String> = BTreeSet::new();
    for obj in &program.objects {
        let g = graph::build(obj);
        for f in g.functions.values() {
            for s in f.strings.iter().chain(f.stack_strings.iter()) {
                all.insert(s.clone());
            }
        }
    }
    let mut scored: Vec<(i64, String)> = all
        .into_iter()
        .filter(|s| is_usable(s))
        .map(|s| (score(&s), s))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(max).map(|(_, s)| s).collect()
}

fn is_usable(s: &str) -> bool {
    let n = s.chars().count();
    (8..=200).contains(&n)
        && s.chars().all(|c| c == '\t' || (' '..='~').contains(&c))
        && s.chars().filter(|c| c.is_ascii_alphanumeric()).count() * 2 >= n
}

fn score(s: &str) -> i64 {
    let mut sc = s.len() as i64;
    if crate::decode::notable(s).is_some() {
        sc += 100;
    }
    if s.contains('/') || s.contains('.') || s.contains(':') {
        sc += 20; // path/url/host-like
    }
    sc
}

fn build_rule(name: &str, sha: &str, strings: &[String]) -> String {
    let ident = sanitize_ident(name);
    let mut out = String::new();
    out.push_str(&format!("rule ariados_auto_{ident} {{\n"));
    out.push_str("    meta:\n");
    out.push_str(&format!(
        "        description = \"Auto-generated from {name}\"\n"
    ));
    out.push_str("        author = \"ariados yara-gen\"\n");
    out.push_str(&format!("        sha256 = \"{sha}\"\n"));
    out.push_str("        severity = \"high\"\n");
    out.push_str("    strings:\n");
    for (i, s) in strings.iter().enumerate() {
        out.push_str(&format!("        $s{i} = \"{}\"\n", yara_escape(s)));
    }
    // Require most strings so the rule is specific but tolerant of small
    // variations between samples.
    let need = strings.len().saturating_sub(1).max(2).min(strings.len());
    out.push_str("    condition:\n");
    out.push_str(&format!("        {need} of them\n"));
    out.push_str("}\n");
    out
}

fn yara_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\t', "\\t")
}

fn sanitize_ident(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}
