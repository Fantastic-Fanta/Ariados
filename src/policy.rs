//! Scoring policy: turns a set of findings into a verdict.
//!
//! This is intentionally dumb and transparent — a weighted sum with
//! thresholds, all data-driven from `policy.toml`. The point is that the
//! verdict is always explainable from the findings, and tuning how strict it is
//! never means editing detection code.

use crate::analysis::{Finding, Severity, Verdict, VerdictLevel};
use crate::model::Signing;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
struct Weights {
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
    #[serde(default = "default_true")]
    count_each_finding_once: bool,
}

#[derive(Debug, Deserialize, Default)]
struct Modifiers {
    #[serde(default)]
    unsigned_with_findings: u32,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    low_risk: u32,
    suspicious: u32,
    highly_suspicious: u32,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    weights: Weights,
    #[serde(default)]
    modifiers: Modifiers,
    thresholds: Thresholds,
}

fn default_true() -> bool {
    true
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Policy, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    pub fn builtin() -> Policy {
        Policy::from_toml(include_str!("../rules/policy.toml")).expect("built-in policy must parse")
    }

    fn weight(&self, sev: Severity) -> u32 {
        match sev {
            Severity::High => self.weights.high,
            Severity::Medium => self.weights.medium,
            Severity::Low => self.weights.low,
            Severity::Info => self.weights.info,
        }
    }

    /// Computes the verdict for a set of findings.
    pub fn verdict(&self, findings: &[Finding], signing: Signing) -> Verdict {
        let mut score = 0u32;
        if self.weights.count_each_finding_once {
            // Collapse the same finding id (same behavior across fat slices).
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for f in findings {
                if seen.insert(f.id.as_str()) {
                    score += self.weight(f.severity);
                }
            }
        } else {
            for f in findings {
                score += self.weight(f.severity);
            }
        }

        if signing == Signing::Unsigned && !findings.is_empty() {
            score += self.modifiers.unsigned_with_findings;
        }

        let level = if score >= self.thresholds.highly_suspicious {
            VerdictLevel::HighlySuspicious
        } else if score >= self.thresholds.suspicious {
            VerdictLevel::Suspicious
        } else if score >= self.thresholds.low_risk {
            VerdictLevel::LowRisk
        } else {
            VerdictLevel::Clean
        };

        Verdict { level, score }
    }
}
