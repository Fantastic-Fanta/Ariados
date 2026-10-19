//! YARA rule support, via VirusTotal's pure-Rust `yara-x` engine.
//!
//! YARA is the industry-standard format for malware signatures, with large
//! public rule sets (YARA-Forge, Neo23x0/signature-base). Running YARA
//! alongside the behavioral engine lets Ariados use that ecosystem: point it at
//! a directory of `.yar` files with `--yara <dir>`, or rely on the small
//! illustrative set bundled in `rules/yara/`.
//!
//! A matching rule becomes a finding. Its severity and description come from
//! the rule's `meta` block (`severity = "high"`, `description = "..."`).

use crate::analysis::{Evidence, Finding, Severity, TrailStep};

pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    /// Compiles the rule set bundled into the binary.
    pub fn builtin() -> Option<YaraEngine> {
        let sources: &[&str] = &[
            include_str!("../rules/yara/macos_indicators.yar"),
            include_str!("../rules/yara/obfuscation.yar"),
        ];
        Self::compile(sources)
    }

    /// Compiles every `.yar`/`.yara` file in a directory (recursively). Files
    /// that fail to compile are skipped with a warning, so one bad rule file
    /// doesn't sink the whole scan.
    pub fn from_dir(dir: &std::path::Path) -> Option<YaraEngine> {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0;
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "yar" || e == "yara") {
                match std::fs::read_to_string(p) {
                    Ok(src) => {
                        if let Err(e) = compiler.add_source(src.as_str()) {
                            eprintln!("skipping YARA file {}: {e}", p.display());
                        } else {
                            count += 1;
                        }
                    }
                    Err(e) => eprintln!("cannot read {}: {e}", p.display()),
                }
            }
        }
        if count == 0 {
            return None;
        }
        Some(YaraEngine {
            rules: compiler.build(),
        })
    }

    fn compile(sources: &[&str]) -> Option<YaraEngine> {
        let mut compiler = yara_x::Compiler::new();
        for src in sources {
            compiler.add_source(*src).ok()?;
        }
        Some(YaraEngine {
            rules: compiler.build(),
        })
    }

    /// Scans raw file bytes and returns a finding per matching rule.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let Ok(results) = scanner.scan(data) else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        for rule in results.matching_rules() {
            let name = rule.identifier().to_string();
            let mut severity = Severity::Medium;
            let mut description = None;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("severity", yara_x::MetaValue::String(s)) => severity = Severity::parse(s),
                    ("description", yara_x::MetaValue::String(s)) => {
                        description = Some(s.to_string())
                    }
                    _ => {}
                }
            }
            let title = description.unwrap_or_else(|| format!("YARA rule {name} matched"));
            findings.push(Finding {
                id: format!("yara:{name}"),
                title,
                severity,
                arch: "file".to_string(),
                trail: vec![TrailStep {
                    function: "(yara)".to_string(),
                    addr: 0,
                    evidence: vec![Evidence::String(format!("rule {name}"))],
                }],
                supersedes: vec![],
            });
        }
        findings
    }
}
