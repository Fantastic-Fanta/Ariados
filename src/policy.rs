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

    /// Findings that stay alarming even on a code-signed app, because a
    /// legitimate developer has no reason to pack code, hide strings or evade
    /// debuggers. Everything else (networking, keychain, persistence) is normal
    /// app behavior and shouldn't flag a Gatekeeper-accepted binary.
    fn anomalous_even_when_trusted(id: &str) -> bool {
        matches!(id, "obfuscated-indicators" | "packed-code" | "anti-debug")
    }

    /// Computes the verdict. `trusted` means the OS accepted the signature
    /// (notarized / valid Developer ID), which heavily discounts behavioral
    /// findings — the common case that made real apps look "highly suspicious".
    pub fn verdict(&self, findings: &[Finding], signing: Signing, trusted: bool) -> Verdict {
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

        let mut level = if score >= self.thresholds.highly_suspicious {
            VerdictLevel::HighlySuspicious
        } else if score >= self.thresholds.suspicious {
            VerdictLevel::Suspicious
        } else if score >= self.thresholds.low_risk {
            VerdictLevel::LowRisk
        } else {
            VerdictLevel::Clean
        };

        // A signature the OS accepts ties the binary to a known developer, so
        // behavioral findings alone don't make it suspicious. Cap the level at
        // low-risk unless something genuinely anomalous for a signed app is
        // present (packing, hidden strings, anti-debug).
        if trusted
            && !findings
                .iter()
                .any(|f| Self::anomalous_even_when_trusted(&f.id))
            && level > VerdictLevel::LowRisk
        {
            level = VerdictLevel::LowRisk;
        }

        Verdict { level, score }
    }
}
