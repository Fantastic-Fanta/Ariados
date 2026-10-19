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
        Engine {
            rules: Rules::builtin(),
            policy: Policy::builtin(),
            enrich_signing: true,
            decode_hidden: true,
        }
    }

    pub fn with_rules(rules: Rules, policy: Policy) -> Engine {
        Engine {
            rules,
            policy,
            enrich_signing: true,
            decode_hidden: true,
        }
    }

    /// Scans one binary file and produces a report.
    pub fn scan_file(&self, path: &Path) -> Result<Report, AnalyzeError> {
        let data = std::fs::read(path)?;
        let mut program = crate::formats::parse(&data)?;
        prepare(&mut program);

        let arches = arches_label(&program.objects.iter().map(|o| o.arch).collect::<Vec<_>>());

        // Build each slice's graph once (disassembly is the expensive step) and
        // reuse it for rule matching and stack-string detection.
        let graphs: Vec<(String, graph::Graph)> = program
            .objects
            .iter()
            .map(|obj| (obj.arch.label().to_string(), graph::build(obj)))
            .collect();

        // Match rules per architecture slice, then merge identical findings
        // (fat binaries report the same behavior in each slice).
        let mut merged: BTreeMap<String, Finding> = BTreeMap::new();
        let mut arches_with: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (arch, g) in &graphs {
            for f in self.rules.match_graph(g, arch) {
                arches_with
                    .entry(f.id.clone())
                    .or_default()
                    .push(arch.clone());
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
        if self.decode_hidden
            && let Some(f) = hidden_string_finding(&program, &graphs)
        {
            findings.push(f);
        }

        // Packing: an executable section with near-random bytes is a strong
        // sign the real code is compressed/encrypted and unpacked at runtime.
        if let Some(f) = packing_finding(&program) {
            findings.push(f);
        }

        // Drop findings that a stronger present finding supersedes.
        let superseded: std::collections::BTreeSet<String> = findings
            .iter()
            .flat_map(|f| f.supersedes.iter().cloned())
            .collect();
        findings.retain(|f| !superseded.contains(&f.id));
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));

        let signing = program
            .objects
            .first()
            .map(|o| o.signing)
            .unwrap_or(Signing::Unsigned);
        let signing_detail = if self.enrich_signing && program.format == Format::MachO {
            codesign_detail(path)
        } else {
            None
        };

        // "Trusted" = signed by a verified Apple developer: Gatekeeper accepted
        // it, or it carries a Developer ID / Apple authority (an identity-checked,
        // revocable cert). spctl alone is too strict — it rejects legitimately
        // Developer-ID-signed apps that just aren't notarized for loose
        // assessment. Ad-hoc and unsigned binaries have no such authority, so
        // they stay untrusted. Only known when signing was enriched.
        let trusted = signing_detail.as_deref().is_some_and(|d| {
            d.contains("gatekeeper: accepted")
                || d.contains("authority: Developer ID")
                || d.contains("authority: Apple")
                || d.contains("authority: Software Signing")
        });
        let verdict = self.policy.verdict(&findings, signing, trusted);

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

/// Builds a finding from XOR-obfuscated indicators (fast delta search) and
/// stack-constructed strings (read from the already-built graphs), de-duped
/// across fat-binary slices.
fn hidden_string_finding(
    program: &crate::model::Program,
    graphs: &[(String, graph::Graph)],
) -> Option<Finding> {
    use crate::analysis::{Evidence, TrailStep};
    let mut seen = std::collections::BTreeSet::new();
    let mut evidence = Vec::new();

    for obj in &program.objects {
        for h in crate::decode::xor_indicators(obj) {
            if seen.insert(h.text.clone()) {
                evidence.push(Evidence::String(format!(
                    "[hidden · XOR key {:#04x} · {}] {}",
                    h.key, h.label, h.text
                )));
            }
        }
    }
    for (_, g) in graphs {
        for f in g.functions.values() {
            for s in &f.stack_strings {
                if let Some(label) = crate::decode::notable(s)
                    && seen.insert(s.clone())
                {
                    evidence.push(Evidence::String(format!(
                        "[hidden · stack string · {label}] {s}"
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
        title: "Hides suspicious strings (XOR or stack-constructed)".into(),
        severity: Severity::High,
        arch: program
            .objects
            .iter()
            .map(|o| o.arch.label())
            .collect::<Vec<_>>()
            .join(" + "),
        trail: vec![TrailStep {
            function: "(data section)".into(),
            addr: 0,
            evidence,
        }],
        supersedes: vec![],
    })
}

/// Flags executable sections whose bytes are near-random, which is what packed
/// or encrypted code looks like before it unpacks itself. Normal machine code
/// sits around 6.0–6.7 bits/byte; above ~7.2 is suspicious for a code section.
fn packing_finding(program: &crate::model::Program) -> Option<Finding> {
    use crate::analysis::{Evidence, TrailStep};
    const THRESHOLD: f64 = 7.2;
    const MIN_SIZE: usize = 2048;

    let mut evidence = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for obj in &program.objects {
        for sec in obj.code_sections() {
            if sec.bytes.len() < MIN_SIZE {
                continue;
            }
            let e = crate::entropy::shannon(&sec.bytes);
            if e > THRESHOLD && seen.insert(sec.name.clone()) {
                evidence.push(Evidence::String(format!(
                    "section {} is {e:.2}/8.0 bits per byte (normal code ~6.3)",
                    sec.name
                )));
            }
        }
    }
    if evidence.is_empty() {
        return None;
    }
    Some(Finding {
        id: "packed-code".into(),
        title: "Executable section looks packed or encrypted (high entropy)".into(),
        severity: Severity::Medium,
        arch: program
            .objects
            .iter()
            .map(|o| o.arch.label())
            .collect::<Vec<_>>()
            .join(" + "),
        trail: vec![TrailStep {
            function: "(code section)".into(),
            addr: 0,
            evidence,
        }],
        supersedes: vec![],
    })
}

/// Resolves import thunks and recovers functions so a parsed program is ready
/// for graph building. Shared by the scan and diff paths.
pub fn prepare(program: &mut crate::model::Program) {
    for obj in &mut program.objects {
        if program.format != Format::MachO {
            resolve_stub_names(obj);
        }
        if program.format == Format::Pe || obj.functions.len() < 16 {
            obj.functions = crate::disasm::discover_functions(obj);
        }
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
        if let Ok(head) = read_head(p, 4)
            && crate::formats::looks_executable(&head)
        {
            out.push(p.to_path_buf());
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
    use std::process::{Command, Stdio};
    let piped = || (Stdio::piped(), Stdio::piped());
    // Launch both tools at once; they're independent and each costs ~100ms.
    let (o1, e1) = piped();
    let codesign = Command::new("codesign")
        .args(["-dv", "--verbose=2"])
        .arg(path)
        .stdout(o1)
        .stderr(e1)
        .spawn()
        .ok();
    let (o2, e2) = piped();
    let spctl_child = Command::new("spctl")
        .args(["-a", "-vv", "--type", "execute"])
        .arg(path)
        .stdout(o2)
        .stderr(e2)
        .spawn();

    let out = codesign?.wait_with_output().ok()?;
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
    if let Ok(spctl) = spctl_child.and_then(|c| c.wait_with_output()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, Format, Object, Program, Section, SectionKind, Signing};
    use std::collections::BTreeMap;

    fn code_obj(bytes: Vec<u8>) -> Object {
        Object {
            arch: Arch::X86_64,
            entry: 0,
            little_endian: true,
            sections: vec![Section {
                name: "__text".into(),
                segment: "__TEXT".into(),
                vaddr: 0x1000,
                size: bytes.len() as u64,
                file_off: 0,
                kind: SectionKind::Code,
                bytes,
            }],
            functions: vec![],
            names: BTreeMap::new(),
            import_slots: BTreeMap::new(),
            signing: Signing::Unsigned,
            libraries: vec![],
        }
    }

    fn program(obj: Object) -> Program {
        Program {
            format: Format::MachO,
            sha256: "0".repeat(64),
            size: 0,
            objects: vec![obj],
        }
    }

    #[test]
    fn high_entropy_code_is_flagged_as_packed() {
        // Uniform byte distribution => entropy 8.0, well above the threshold.
        let bytes: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        assert!(packing_finding(&program(code_obj(bytes))).is_some());
    }

    #[test]
    fn low_entropy_code_is_not_flagged() {
        // Repetitive bytes => low entropy, like ordinary code padding.
        let bytes = vec![0x90u8; 4096];
        assert!(packing_finding(&program(code_obj(bytes))).is_none());
    }
}
