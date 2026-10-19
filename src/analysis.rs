//! Finding, trail and verdict types — the output of analysis, shared by the
//! report renderers (text and JSON) and the scoring policy.

use crate::model::{Arch, Format, Signing};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(s: &str) -> Severity {
        match s.to_ascii_lowercase().as_str() {
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// One piece of proof attached to a trail step.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Evidence {
    /// A string the function references.
    String(String),
    /// An imported function it calls.
    Import(String),
    /// A local function it calls (names the next step).
    Call(String),
}

/// One function in an evidence trail, with the proof found in it.
#[derive(Debug, Clone, Serialize)]
pub struct TrailStep {
    pub function: String,
    pub addr: u64,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// Which architecture slice this was found in (fat binaries have several).
    pub arch: String,
    /// The chain of code that proves the behavior.
    pub trail: Vec<TrailStep>,
    /// Weaker finding ids this one makes redundant (e.g. an exfiltration
    /// finding hides the bare "reads credentials" finding). Not serialized;
    /// used only to prune the list before rendering.
    #[serde(skip)]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLevel {
    Clean,
    LowRisk,
    Suspicious,
    HighlySuspicious,
}

impl VerdictLevel {
    pub fn headline(&self) -> &'static str {
        match self {
            VerdictLevel::Clean => "Clean — no suspicious behavior found",
            VerdictLevel::LowRisk => "Low risk — minor signals only",
            VerdictLevel::Suspicious => "Suspicious",
            VerdictLevel::HighlySuspicious => "Highly suspicious",
        }
    }
    /// Process exit code for scripting: 0 clean, 1 low, 2 suspicious, 3 high.
    pub fn exit_code(&self) -> u8 {
        match self {
            VerdictLevel::Clean => 0,
            VerdictLevel::LowRisk => 1,
            VerdictLevel::Suspicious => 2,
            VerdictLevel::HighlySuspicious => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub level: VerdictLevel,
    pub score: u32,
}

/// Everything a scan produced for one file.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub path: String,
    #[serde(serialize_with = "ser_display")]
    pub format: Format,
    pub sha256: String,
    pub size: u64,
    pub arches: Vec<String>,
    #[serde(serialize_with = "ser_signing")]
    pub signing: Signing,
    /// Optional richer signing detail from the OS (codesign/spctl).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_detail: Option<String>,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

fn ser_display<S: serde::Serializer>(v: &Format, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

fn ser_signing<S: serde::Serializer>(v: &Signing, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(match v {
        Signing::Signed => "signed",
        Signing::Unsigned => "unsigned",
    })
}

/// Formats an arch list for display, e.g. `arm64 + x86_64`.
pub fn arches_label(arches: &[Arch]) -> Vec<String> {
    arches.iter().map(|a| a.label().to_string()).collect()
}
