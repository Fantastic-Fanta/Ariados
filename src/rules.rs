//! Capability tagging and behavior matching.
//!
//! Detection works in two layers, like a miniature of Mandiant's `capa`:
//!
//!   1. **Capabilities** tag what a single function does, from the imports it
//!      calls and the strings it uses (e.g. `network`, `credential-access`).
//!   2. **Behaviors** are the findings: dangerous *combinations* of
//!      capabilities, either within one function or chained across a call edge
//!      (e.g. "reads credentials *and* reaches a function that sends data").
//!
//! Keeping behaviors as combinations of capabilities means new detections are
//! usually a few lines of data, not code, and every finding carries the exact
//! strings/imports that triggered it — that's the evidence trail.

use crate::analysis::{Evidence, Finding, Severity, TrailStep};
use crate::graph::{FunctionInfo, Graph};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, VecDeque};

#[derive(Debug, Deserialize)]
struct CapabilityDef {
    id: String,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    strings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BehaviorDef {
    id: String,
    title: String,
    severity: String,
    /// A single capability present anywhere is enough.
    capability: Option<String>,
    /// All of these capabilities in the *same* function.
    #[serde(default)]
    all: Vec<String>,
    /// A function with `source` that reaches a function with `reaches` through
    /// the call graph.
    source: Option<String>,
    reaches: Option<String>,
    /// Weaker findings this one makes redundant.
    #[serde(default)]
    supersedes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    capability: Vec<CapabilityDef>,
    #[serde(default)]
    behavior: Vec<BehaviorDef>,
}

/// A capability with its string patterns pre-compiled.
struct CompiledCap {
    import_pats: Vec<String>,
    string_res: Vec<Regex>,
}

pub struct Rules {
    caps: Vec<CompiledCap>,
    cap_index: HashMap<String, usize>,
    behaviors: Vec<BehaviorDef>,
}

/// How far across call edges a chained behavior will follow a trail. Kept
/// short on purpose: in a large binary, a deep reach links almost any two
/// capabilities and produces false positives. One hop (a function and the
/// helper it calls) is the sweet spot for precision.
const MAX_CALL_DEPTH: usize = 1;

impl Rules {
    /// Loads the rule set from TOML text (capabilities + behaviors may be split
    /// across several files; pass each file's contents).
    pub fn from_toml(parts: &[&str]) -> Result<Rules, String> {
        let mut caps = Vec::new();
        let mut cap_index = HashMap::new();
        let mut behaviors = Vec::new();
        for text in parts {
            let rf: RuleFile = toml::from_str(text).map_err(|e| e.to_string())?;
            for c in rf.capability {
                let string_res = c
                    .strings
                    .iter()
                    .map(|p| Regex::new(p).unwrap_or_else(|_| Regex::new(&regex::escape(p)).unwrap()))
                    .collect();
                cap_index.insert(c.id.clone(), caps.len());
                caps.push(CompiledCap {
                    import_pats: c.imports.iter().map(|s| s.to_ascii_lowercase()).collect(),
                    string_res,
                });
            }
            behaviors.extend(rf.behavior);
        }
        Ok(Rules { caps, cap_index, behaviors })
    }

    /// The built-in rule set, embedded in the binary so it works with no
    /// external files. Override with `--rules <dir>` on the CLI.
    pub fn builtin() -> Rules {
        let caps = include_str!("../rules/capabilities.toml");
        let behaviors = include_str!("../rules/behaviors.toml");
        Rules::from_toml(&[caps, behaviors]).expect("built-in rules must parse")
    }

    /// Does this function exhibit capability `idx`? If so, returns the evidence.
    fn cap_hits(&self, idx: usize, f: &FunctionInfo) -> Vec<Evidence> {
        let cap = &self.caps[idx];
        let mut ev = Vec::new();
        for imp in &f.imports {
            let lower = imp.to_ascii_lowercase();
            if cap.import_pats.iter().any(|p| lower.contains(p.as_str())) {
                ev.push(Evidence::Import(imp.clone()));
            }
        }
        for s in &f.strings {
            if cap.string_res.iter().any(|re| re.is_match(s)) {
                ev.push(Evidence::String(s.clone()));
            }
        }
        ev
    }

    fn has_cap(&self, idx: usize, f: &FunctionInfo) -> bool {
        !self.cap_hits(idx, f).is_empty()
    }

    /// Runs every behavior against one architecture's graph.
    pub fn match_graph(&self, g: &Graph, arch_label: &str) -> Vec<Finding> {
        // Precompute each function's capability set for the reach search.
        let mut capset: HashMap<u64, BTreeSet<usize>> = HashMap::new();
        for f in g.functions.values() {
            let mut set = BTreeSet::new();
            for idx in 0..self.caps.len() {
                if self.has_cap(idx, f) {
                    set.insert(idx);
                }
            }
            capset.insert(f.addr, set);
        }

        let mut findings = Vec::new();
        for b in &self.behaviors {
            if let Some(f) = self.match_behavior(b, g, &capset, arch_label) {
                findings.push(f);
            }
        }
        // Most severe first, then stable by id.
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
        findings
    }

    fn match_behavior(
        &self,
        b: &BehaviorDef,
        g: &Graph,
        capset: &HashMap<u64, BTreeSet<usize>>,
        arch_label: &str,
    ) -> Option<Finding> {
        let sev = Severity::parse(&b.severity);

        // Form 1: a chained behavior (source reaches target across calls).
        if let (Some(src), Some(dst)) = (&b.source, &b.reaches) {
            let si = *self.cap_index.get(src)?;
            let di = *self.cap_index.get(dst)?;
            for f in g.functions.values() {
                if !capset.get(&f.addr).is_some_and(|s| s.contains(&si)) {
                    continue;
                }
                if let Some(path) = self.find_reach(g, capset, f.addr, di) {
                    return Some(self.build_chain_finding(b, sev, arch_label, g, &path, si, di));
                }
            }
            return None;
        }

        // Form 2: several capabilities in the same function.
        if !b.all.is_empty() {
            let idxs: Vec<usize> = b.all.iter().filter_map(|c| self.cap_index.get(c).copied()).collect();
            if idxs.len() != b.all.len() {
                return None;
            }
            for f in g.functions.values() {
                if idxs.iter().all(|&i| self.has_cap(i, f)) {
                    let mut ev = Vec::new();
                    for &i in &idxs {
                        ev.extend(self.cap_hits(i, f));
                    }
                    dedup_evidence(&mut ev);
                    return Some(single_step_finding(b, sev, arch_label, f, ev));
                }
            }
            return None;
        }

        // Form 3: a single capability present anywhere. Pick the function with
        // the most evidence so the trail is the clearest example.
        if let Some(cap) = &b.capability {
            let idx = *self.cap_index.get(cap)?;
            let best = g
                .functions
                .values()
                .map(|f| (f, self.cap_hits(idx, f)))
                .filter(|(_, ev)| !ev.is_empty())
                .max_by_key(|(_, ev)| ev.len())?;
            return Some(single_step_finding(b, sev, arch_label, best.0, best.1));
        }

        None
    }

    /// Breadth-first search over call edges for a function with capability `dst`.
    /// Returns the path of addresses from `start` to the first match.
    fn find_reach(
        &self,
        g: &Graph,
        capset: &HashMap<u64, BTreeSet<usize>>,
        start: u64,
        dst: usize,
    ) -> Option<Vec<u64>> {
        let mut seen = BTreeSet::new();
        let mut queue: VecDeque<Vec<u64>> = VecDeque::new();
        queue.push_back(vec![start]);
        seen.insert(start);
        while let Some(path) = queue.pop_front() {
            let last = *path.last().unwrap();
            if capset.get(&last).is_some_and(|s| s.contains(&dst)) {
                return Some(path);
            }
            if path.len() > MAX_CALL_DEPTH {
                continue;
            }
            if let Some(f) = g.functions.get(&last) {
                for &callee in &f.calls {
                    if seen.insert(callee) {
                        let mut next = path.clone();
                        next.push(callee);
                        queue.push_back(next);
                    }
                }
            }
        }
        None
    }

    fn build_chain_finding(
        &self,
        b: &BehaviorDef,
        sev: Severity,
        arch_label: &str,
        g: &Graph,
        path: &[u64],
        src_cap: usize,
        dst_cap: usize,
    ) -> Finding {
        let mut trail = Vec::new();
        for (i, &addr) in path.iter().enumerate() {
            let f = g.functions.get(&addr);
            let mut ev = Vec::new();
            if i == 0 {
                if let Some(f) = f {
                    ev.extend(self.cap_hits(src_cap, f));
                }
            }
            if i == path.len() - 1 {
                if let Some(f) = f {
                    ev.extend(self.cap_hits(dst_cap, f));
                }
            }
            // Name the next hop so the reader can follow the chain.
            if i + 1 < path.len() {
                ev.push(Evidence::Call(g.name_of(path[i + 1])));
            }
            dedup_evidence(&mut ev);
            trail.push(TrailStep { function: g.name_of(addr), addr, evidence: ev });
        }
        Finding {
            id: b.id.clone(),
            title: b.title.clone(),
            severity: sev,
            arch: arch_label.to_string(),
            trail,
            supersedes: b.supersedes.clone(),
        }
    }
}

fn single_step_finding(
    b: &BehaviorDef,
    sev: Severity,
    arch_label: &str,
    f: &FunctionInfo,
    evidence: Vec<Evidence>,
) -> Finding {
    Finding {
        id: b.id.clone(),
        title: b.title.clone(),
        severity: sev,
        arch: arch_label.to_string(),
        trail: vec![TrailStep { function: f.name.clone(), addr: f.addr, evidence }],
        supersedes: b.supersedes.clone(),
    }
}

fn dedup_evidence(ev: &mut Vec<Evidence>) {
    let mut seen = BTreeSet::new();
    ev.retain(|e| {
        let key = match e {
            Evidence::String(s) => format!("s:{s}"),
            Evidence::Import(s) => format!("i:{s}"),
            Evidence::Call(s) => format!("c:{s}"),
        };
        seen.insert(key)
    });
}
