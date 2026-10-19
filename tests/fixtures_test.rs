//! Integration tests over the committed fixtures. These compile-check the
//! whole pipeline and guard against detection regressions. The fixtures are
//! harmless (see tests/fixtures/src/*.c).

use ariados::analysis::VerdictLevel;
use ariados::scan::Engine;
use std::path::Path;

fn scan(name: &str) -> ariados::analysis::Report {
    let engine = Engine::builtin();
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    engine
        .scan_file(Path::new(&p))
        .expect("scan should succeed")
}

fn has_finding(r: &ariados::analysis::Report, id: &str) -> bool {
    r.findings.iter().any(|f| f.id == id)
}

#[test]
fn stealer_macho_arm64_is_highly_suspicious() {
    let r = scan("stealer_arm64");
    assert_eq!(
        r.verdict.level,
        VerdictLevel::HighlySuspicious,
        "{:?}",
        r.verdict
    );
    assert!(has_finding(&r, "credential-exfiltration"));
    assert!(has_finding(&r, "fake-password-prompt"));
}

#[test]
fn stealer_macho_x64_is_highly_suspicious() {
    let r = scan("stealer_x64");
    assert_eq!(r.verdict.level, VerdictLevel::HighlySuspicious);
}

#[test]
fn stealer_elf_detects_credential_trail() {
    for name in ["stealer_elf_x64", "stealer_elf_arm64"] {
        let r = scan(name);
        assert_eq!(r.format, ariados::model::Format::Elf);
        assert!(
            has_finding(&r, "credential-exfiltration"),
            "{name}: {:?}",
            r.findings
        );
    }
}

#[test]
fn stealer_pe_is_flagged() {
    let r = scan("stealer_pe_x64.exe");
    assert_eq!(r.format, ariados::model::Format::Pe);
    assert!(
        r.verdict.level >= VerdictLevel::Suspicious,
        "{:?}",
        r.verdict
    );
}

#[test]
fn xor_fixture_reveals_hidden_indicators() {
    let r = scan("xor_arm64");
    assert!(has_finding(&r, "obfuscated-indicators"), "{:?}", r.findings);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "obfuscated-indicators")
        .unwrap();
    let joined = format!("{:?}", f.trail);
    assert!(
        joined.contains("malware-c2.example.com"),
        "decoded URL missing: {joined}"
    );
}

#[test]
fn solve_finds_the_secret_in_the_check() {
    let p = format!(
        "{}/tests/fixtures/crackme_arm64",
        env!("CARGO_MANIFEST_DIR")
    );
    let opts = ariados::solve::Options {
        no_llm: true,
        show_prompt: false,
    };
    let out = ariados::solve::solve(std::path::Path::new(&p), &opts).expect("solve");
    // The annotated listing must surface the strcmp target and the comparison.
    assert!(out.contains("h4ck3r-5Ecr3t"), "secret not surfaced:\n{out}");
    assert!(out.contains("strcmp"), "comparison not resolved:\n{out}");
}
