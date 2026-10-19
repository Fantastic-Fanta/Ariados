//! Rendering a `Report` as readable terminal text or as JSON.
//!
//! The text form is the product's headline feature: every finding shows the
//! chain of code that proves it, so the reader can jump straight to those
//! addresses in a disassembler instead of trusting an opaque label.

use crate::analysis::{Evidence, Finding, Report, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Renders a full report as terminal text.
pub fn render_text(r: &Report) -> String {
    let mut out = String::new();
    let name = std::path::Path::new(&r.path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| r.path.clone());

    out.push_str(&format!("ariados {VERSION} — {name}\n"));

    let signing = match &r.signing_detail {
        Some(d) => d.clone(),
        None => match r.signing {
            crate::model::Signing::Signed => "signed".into(),
            crate::model::Signing::Unsigned => "unsigned".into(),
        },
    };
    out.push_str(&format!(
        "{} · {} · {} · sha256 {}\n\n",
        r.format,
        r.arches.join(" + "),
        signing,
        &r.sha256[..r.sha256.len().min(16)]
    ));

    let n = r.findings.len();
    out.push_str(&format!(
        "VERDICT  {}  (score {})\n",
        r.verdict.level.headline(),
        r.verdict.score
    ));
    if n == 0 {
        out.push_str("\nNo suspicious behaviors found.\n");
        return out;
    }
    out.push_str(&format!(
        "{n} evidence trail{}\n\n",
        if n == 1 { "" } else { "s" }
    ));

    for f in &r.findings {
        out.push_str(&render_finding(f));
        out.push('\n');
    }
    out
}

fn dot(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "●",
        Severity::Medium => "◆",
        Severity::Low => "○",
        Severity::Info => "·",
    }
}

fn render_finding(f: &Finding) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "{} {:<6} {}  ({})\n",
        dot(f.severity),
        f.severity.label(),
        f.title,
        f.arch
    ));

    for (i, step) in f.trail.iter().enumerate() {
        let indent = "  ";
        s.push_str(&format!(
            "{indent}fn {} @ {:#x}\n",
            step.function, step.addr
        ));
        let last_step = i == f.trail.len() - 1;
        for (j, ev) in step.evidence.iter().enumerate() {
            let last_ev = j == step.evidence.len() - 1;
            let branch = if last_ev && last_step {
                "└─"
            } else {
                "├─"
            };
            s.push_str(&format!("{indent}{branch} {}\n", render_evidence(ev)));
        }
    }
    s
}

fn render_evidence(ev: &Evidence) -> String {
    match ev {
        Evidence::String(v) => format!("string  {:?}", truncate(v, 90)),
        Evidence::Import(v) => format!("import  {v}"),
        Evidence::Call(v) => format!("calls   {v}  ↓"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// Renders a report as pretty JSON.
pub fn render_json(r: &Report) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Renders one or more reports as a Markdown document — clean, professional,
/// and good for attaching to a ticket or committing alongside a review.
pub fn render_markdown(reports: &[Report]) -> String {
    reports
        .iter()
        .map(md_report)
        .collect::<Vec<_>>()
        .join("\n---\n\n")
}

fn md_report(r: &Report) -> String {
    let name = std::path::Path::new(&r.path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| r.path.clone());
    let signing = r.signing_detail.clone().unwrap_or_else(|| match r.signing {
        crate::model::Signing::Signed => "signed".into(),
        crate::model::Signing::Unsigned => "unsigned".into(),
    });

    let mut s = String::new();
    s.push_str(&format!("# Ariados report: {name}\n\n"));
    s.push_str(&format!(
        "**Verdict: {}** (score {})\n\n",
        r.verdict.level.headline(),
        r.verdict.score
    ));
    s.push_str(&format!("- **Format:** {}\n", r.format));
    s.push_str(&format!("- **Architectures:** {}\n", r.arches.join(" + ")));
    s.push_str(&format!("- **Signing:** {signing}\n"));
    s.push_str(&format!("- **SHA-256:** `{}`\n\n", r.sha256));

    if r.findings.is_empty() {
        s.push_str("No suspicious behaviors found.\n");
        return s;
    }

    s.push_str(&format!("## Findings ({})\n\n", r.findings.len()));
    for f in &r.findings {
        s.push_str(&md_finding(f));
    }
    s
}

fn md_finding(f: &Finding) -> String {
    let mut s = String::new();
    s.push_str(&format!("### {} — {}\n\n", f.severity.label(), f.title));
    s.push_str(&format!("_{}_\n\n", f.arch));
    for (i, step) in f.trail.iter().enumerate() {
        s.push_str(&format!(
            "{}. **`{}`** `{:#x}`\n",
            i + 1,
            step.function,
            step.addr
        ));
        for ev in &step.evidence {
            let (kind, val) = match ev {
                Evidence::String(v) => ("string", v.clone()),
                Evidence::Import(v) => ("import", v.clone()),
                Evidence::Call(v) => ("calls", v.clone()),
            };
            s.push_str(&format!("   - {kind}: `{}`\n", md_escape(&val)));
        }
    }
    s.push('\n');
    s
}

/// Escapes backticks so a string containing one doesn't break the code span.
fn md_escape(s: &str) -> String {
    s.replace('`', "'")
}
