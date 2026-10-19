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
    // IAT resolution means the credential+network chain is found (not just
    // string-only findings), and a resolved import appears in the trails.
    assert!(
        has_finding(&r, "credential-exfiltration"),
        "{:?}",
        r.findings
    );
    assert!(
        format!("{:?}", r.findings).contains("fopen"),
        "no resolved import"
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

#[test]
fn stack_strings_are_recovered() {
    let r = scan("stackstr_x64");
    assert!(has_finding(&r, "obfuscated-indicators"), "{:?}", r.findings);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "obfuscated-indicators")
        .unwrap();
    let joined = format!("{:?}", f.trail);
    assert!(
        joined.contains("stack string") && joined.contains("osascript"),
        "{joined}"
    );
}

#[test]
fn new_rules_detect_dropper_wallet_gatekeeper() {
    let r = scan("dropper_arm64");
    assert!(has_finding(&r, "crypto-wallet-theft"), "{:?}", r.findings);
    assert!(has_finding(&r, "curl-pipe-shell"), "{:?}", r.findings);
    assert!(has_finding(&r, "gatekeeper-disable"), "{:?}", r.findings);
}

#[test]
fn yara_bundled_rules_match_stealer() {
    let r = scan("stealer_arm64");
    // The bundled YARA rules (fake prompt + browser credential paths) fire.
    assert!(
        r.findings.iter().any(|f| f.id.starts_with("yara:")),
        "no yara findings: {:?}",
        r.findings
    );
}

/// Detection regression: every malicious fixture must stay flagged, and the
/// clean one must not. Runs in CI so a rule or decoder change that silently
/// breaks detection fails the build.
#[test]
fn detection_regression_suite() {
    let malicious = [
        "stealer_arm64",
        "stealer_x64",
        "stealer_fat",
        "stealer_elf_arm64",
        "stealer_elf_x64",
        "stealer_pe_x64.exe",
        "dropper_arm64",
        "xor_arm64",
        "stackstr_x64",
        "app_tampered_arm64",
    ];
    for name in malicious {
        let r = scan(name);
        assert!(
            r.verdict.level >= VerdictLevel::Suspicious,
            "{name} should be flagged, got {:?}",
            r.verdict
        );
    }
    // The clean build of the same app must not be flagged.
    let clean = scan("app_clean_arm64");
    assert!(
        clean.verdict.level < VerdictLevel::Suspicious,
        "app_clean should be clean, got {:?}",
        clean.verdict
    );
}

#[test]
fn yara_gen_produces_a_specific_rule() {
    let p = format!(
        "{}/tests/fixtures/stealer_arm64",
        env!("CARGO_MANIFEST_DIR")
    );
    let r = ariados::yaragen::generate(std::path::Path::new(&p), &[]).expect("generate");
    assert!(r.matched_sample, "rule must match its own sample");
    assert!(
        r.clean_hits.is_empty(),
        "rule matched clean binaries: {:?}",
        r.clean_hits
    );
    assert!(r.rule.contains("rule ariados_auto_"));
}
