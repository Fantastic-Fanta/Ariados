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

/// Renders one or more reports as a self-contained HTML page. Handy for
/// reviewing a whole `.app` bundle or a directory scan in a browser.
pub fn render_html(reports: &[Report]) -> String {
    let mut body = String::new();
    for r in reports {
        body.push_str(&html_report(r));
    }
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>ariados report</title><style>{CSS}</style></head>\
<body><h1>ariados {VERSION}</h1>{body}</body></html>"
    )
}

const CSS: &str = "\
:root{color-scheme:light dark}\
body{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#fff;color:#1a1a1a}\
@media(prefers-color-scheme:dark){body{background:#16181c;color:#e6e6e6}.card{background:#1e2127;border-color:#2c2f36}code{background:#2c2f36}}\
h1{font-size:1.3rem}\
.card{border:1px solid #e2e2e2;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0;background:#fafafa}\
.meta{color:#888;font-size:.85rem;margin:.2rem 0 .8rem}\
.verdict{display:inline-block;padding:.2rem .6rem;border-radius:6px;font-weight:600}\
.v3{background:#c0392b;color:#fff}.v2{background:#e67e22;color:#fff}.v1{background:#f1c40f;color:#333}.v0{background:#27ae60;color:#fff}\
.finding{border-left:3px solid #ccc;padding:.4rem 0 .4rem .8rem;margin:.8rem 0}\
.sev-high{border-color:#c0392b}.sev-medium{border-color:#e67e22}.sev-low{border-color:#f1c40f}.sev-info{border-color:#aaa}\
.badge{font-size:.72rem;font-weight:700;padding:.08rem .4rem;border-radius:4px;color:#fff;margin-right:.4rem}\
.b-high{background:#c0392b}.b-medium{background:#e67e22}.b-low{background:#f1c40f;color:#333}.b-info{background:#888}\
.step{margin:.3rem 0 .3rem 1rem}.step .fn{font-weight:600}\
ul.ev{margin:.2rem 0 .2rem 1.4rem;padding:0;list-style:none}\
ul.ev li{color:#555}ul.ev li::before{content:'├─ ';color:#aaa}\
@media(prefers-color-scheme:dark){ul.ev li{color:#aab}.meta{color:#99a}}\
code{background:#eee;padding:.05rem .3rem;border-radius:4px;font-size:.85em}";

fn html_report(r: &Report) -> String {
    let name = std::path::Path::new(&r.path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| r.path.clone());
    let signing = r.signing_detail.clone().unwrap_or_else(|| match r.signing {
        crate::model::Signing::Signed => "signed".into(),
        crate::model::Signing::Unsigned => "unsigned".into(),
    });
    let vclass = format!("v{}", r.verdict.level.exit_code());

    let mut findings = String::new();
    for f in &r.findings {
        findings.push_str(&html_finding(f));
    }
    if r.findings.is_empty() {
        findings.push_str("<p>No suspicious behaviors found.</p>");
    }

    format!(
        "<div class=\"card\"><h2>{name}</h2>\
<div class=\"meta\">{} · {} · {} · sha256 {}</div>\
<p><span class=\"verdict {vclass}\">{}</span> &nbsp;score {}</p>{findings}</div>",
        esc(&r.format.to_string()),
        esc(&r.arches.join(" + ")),
        esc(&signing),
        &r.sha256[..r.sha256.len().min(16)],
        esc(r.verdict.level.headline()),
        r.verdict.score,
    )
}

fn html_finding(f: &Finding) -> String {
    let sev = f.severity.label().to_lowercase();
    let mut steps = String::new();
    for step in &f.trail {
        let mut items = String::new();
        for ev in &step.evidence {
            let (k, v) = match ev {
                Evidence::String(v) => ("string", v.clone()),
                Evidence::Import(v) => ("import", v.clone()),
                Evidence::Call(v) => ("calls", v.clone()),
            };
            items.push_str(&format!("<li><code>{k}</code> {}</li>", esc(&v)));
        }
        steps.push_str(&format!(
            "<div class=\"step\"><span class=\"fn\">{}</span> @ {:#x}<ul class=\"ev\">{items}</ul></div>",
            esc(&step.function),
            step.addr
        ));
    }
    format!(
        "<div class=\"finding sev-{sev}\"><span class=\"badge b-{sev}\">{}</span>{} <span class=\"meta\">({})</span>{steps}</div>",
        f.severity.label(),
        esc(&f.title),
        esc(&f.arch),
    )
}

/// Minimal HTML escaping for text we embed.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
