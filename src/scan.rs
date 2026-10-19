//! The scan pipeline: parse → graph → match rules → score → report.

use crate::analysis::*;
use crate::disasm::resolve_stub_names;
use crate::error::AnalyzeError;
use crate::graph;
use crate::model::{Format, Signing};
use crate::policy::Policy;
use crate::rules::Rules;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct Engine {
    rules: Rules,
    policy: Policy,
    /// Ask the OS (`codesign`/`spctl`) for richer signing info. Off during bulk
    /// eval, where it would be thousands of subprocesses.
    pub enrich_signing: bool,
    /// Brute-force single-byte XOR strings. Off during bulk eval, where the
    /// 255-key sweep over every data section would dominate runtime.
    pub decode_hidden: bool,
}

impl Engine {
    pub fn builtin() -> Engine {
        Engine { rules: Rules::builtin(), policy: Policy::builtin(), enrich_signing: true, decode_hidden: true }
    }

    pub fn with_rules(rules: Rules, policy: Policy) -> Engine {
        Engine { rules, policy, enrich_signing: true, decode_hidden: true }
    }

    /// Scans one binary file and produces a report.
    pub fn scan_file(&self, path: &Path) -> Result<Report, AnalyzeError> {
        let data = std::fs::read(path)?;
        let mut program = crate::formats::parse(&data)?;

        for obj in &mut program.objects {
            // ELF/PE: name PLT/IAT thunks before anything else so calls to them
            // resolve. Mach-O stubs are already named during parsing.
            if program.format != Format::MachO {
                resolve_stub_names(obj);
            }
            // Recover functions for stripped binaries (always the case for PE).
            // Skip when the symbol table / function-starts already gave plenty,
            // so the common Mach-O/ELF path stays fast.
            if program.format == Format::Pe || obj.functions.len() < 16 {
                obj.functions = crate::disasm::discover_functions(obj);
            }
        }

        let arches = arches_label(&program.objects.iter().map(|o| o.arch).collect::<Vec<_>>());

        // Match rules per architecture slice, then merge identical findings
        // (fat binaries report the same behavior in each slice).
        let mut merged: BTreeMap<String, Finding> = BTreeMap::new();
        let mut arches_with: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for obj in &program.objects {
            let g = graph::build(obj);
            for f in self.rules.match_graph(&g, obj.arch.label()) {
                arches_with.entry(f.id.clone()).or_default().push(obj.arch.label().to_string());
                merged.entry(f.id.clone()).or_insert(f);
            }
        }
        let mut findings: Vec<Finding> = merged
            .into_values()
            .map(|mut f| {
                if let Some(list) = arches_with.get(&f.id) {
                    f.arch = list.join(" + ");
                }
                f
            })
            .collect();
        // Hidden strings: a suspicious string that was XOR-obfuscated is a much
        // stronger signal than a plaintext one, so it gets its own finding.
        if self.decode_hidden {
            if let Some(f) = self.hidden_string_finding(&program) {
                findings.push(f);
            }
        }

        // Drop findings that a stronger present finding supersedes.
        let superseded: std::collections::BTreeSet<String> =
            findings.iter().flat_map(|f| f.supersedes.iter().cloned()).collect();
        findings.retain(|f| !superseded.contains(&f.id));
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));

        let signing = program.objects.first().map(|o| o.signing).unwrap_or(Signing::Unsigned);
        let signing_detail = if self.enrich_signing && program.format == Format::MachO {
            codesign_detail(path)
        } else {
            None
        };

        let verdict = self.policy.verdict(&findings, signing);

        Ok(Report {
            path: path.display().to_string(),
            format: program.format,
            sha256: program.sha256,
            size: program.size,
            arches,
            signing,
            signing_detail,
            findings,
            verdict,
        })
    }
}

impl Engine {
    /// Builds a finding from XOR-obfuscated strings that decode to indicators,
    /// de-duplicating across fat-binary slices.
    fn hidden_string_finding(&self, program: &crate::model::Program) -> Option<Finding> {
        use crate::analysis::{Evidence, TrailStep};
        let mut seen = std::collections::BTreeSet::new();
        let mut evidence = Vec::new();
        for obj in &program.objects {
            for h in crate::decode::xor_strings(obj, 6) {
                if let Some(label) = crate::decode::notable(&h.text) {
                    if seen.insert(h.text.clone()) {
                        evidence.push(Evidence::String(format!(
                            "[hidden · XOR key {:#04x} · {label}] {}",
                            h.key, h.text
                        )));
                    }
                }
            }
        }
        if evidence.is_empty() {
            return None;
        }
        Some(Finding {
            id: "obfuscated-indicators".into(),
            title: "Hides suspicious strings with single-byte XOR".into(),
            severity: Severity::High,
            arch: program.objects.iter().map(|o| o.arch.label()).collect::<Vec<_>>().join(" + "),
            trail: vec![TrailStep { function: "(data section)".into(), addr: 0, evidence }],
            supersedes: vec![],
        })
    }
}

/// Expands a scan target into the list of binaries to analyze. A plain file is
/// itself; an `.app` bundle or any directory expands to every executable inside
/// it, so "the app is clean but a bundled helper isn't" is visible.
pub fn collect_targets(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(path).into_iter().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        // Peek at the first bytes; only parse things that look executable.
        if let Ok(head) = read_head(p, 4) {
            if crate::formats::looks_executable(&head) {
                out.push(p.to_path_buf());
            }
        }
    }
    out.sort();
    out
}

fn read_head(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}

/// Best-effort richer signing summary from the macOS tools. Never fails the
/// scan — if the tools aren't there or the file isn't signed, returns None.
fn codesign_detail(path: &Path) -> Option<String> {
    use std::process::Command;
    let out = Command::new("codesign").args(["-dv", "--verbose=2"]).arg(path).output().ok()?;
    // codesign writes its detail to stderr.
    let text = String::from_utf8_lossy(&out.stderr);
    let mut bits = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Authority=") {
            bits.push(format!("authority: {rest}"));
            break;
        }
    }
    if text.contains("flags=0x2(adhoc)") || text.contains("adhoc") {
        bits.insert(0, "ad-hoc signed".to_string());
    }
    // Gatekeeper assessment.
    if let Ok(spctl) = Command::new("spctl").args(["-a", "-vv", "--type", "execute"]).arg(path).output() {
        let s = String::from_utf8_lossy(&spctl.stderr);
        if s.contains("accepted") {
            bits.push("gatekeeper: accepted".into());
        } else if s.contains("rejected") {
            bits.push("gatekeeper: rejected".into());
        }
    }
    if bits.is_empty() {
        None
    } else {
        Some(bits.join(", "))
    }
}
