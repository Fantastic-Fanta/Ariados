//! `solve`: help reverse a crackme by finding the check function, showing its
//! annotated disassembly, and (opt-in) asking an LLM to work out the input that
//! passes it.

use crate::disasm::Disassembler;
use crate::graph::{self, FunctionInfo};
use crate::llm::Provider;
use crate::model::{Object, SectionKind};
use crate::scan::prepare;
use regex::Regex;
use std::path::Path;

/// Words that tend to appear in or near a crackme's success/failure check.
const CHECK_HINTS: &str = r"(?i)(wrong|incorrect|correct|congrat|flag\{|\bflag\b|password|passwd|serial|license|registration|denied|granted|success|accepted|try again|invalid|\bkey\b)";

/// Picks the functions most likely to contain the check, best first.
fn candidates(g: &graph::Graph) -> Vec<&FunctionInfo> {
    let re = Regex::new(CHECK_HINTS).unwrap();
    let mut scored: Vec<(i32, &FunctionInfo)> = g
        .functions
        .values()
        .map(|f| {
            let mut score = 0;
            for s in &f.strings {
                if re.is_match(s) {
                    score += 3;
                }
            }
            for imp in &f.imports {
                if matches!(imp.as_str(), "strcmp" | "strncmp" | "memcmp" | "strcasecmp") {
                    score += 2;
                }
            }
            (score, f)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.addr.cmp(&b.1.addr)));
    // Keep functions with any signal; if none, fall back to the one with the
    // most strings so there's always something to show.
    let mut out: Vec<&FunctionInfo> = scored
        .iter()
        .filter(|(s, _)| *s > 0)
        .map(|(_, f)| *f)
        .collect();
    if out.is_empty()
        && let Some((_, f)) = scored.iter().max_by_key(|(_, f)| f.strings.len())
    {
        out.push(f);
    }
    out.truncate(2);
    out
}

/// Returns the raw bytes of a function and its start address.
fn function_bytes(obj: &Object, start: u64) -> Option<&[u8]> {
    let sec = obj.section_at(start)?;
    if sec.kind != SectionKind::Code {
        return None;
    }
    let sec_end = sec.vaddr + sec.size;
    let end = obj
        .functions
        .iter()
        .copied()
        .find(|&f| f > start && f <= sec_end)
        .unwrap_or(sec_end);
    let off = (start - sec.vaddr) as usize;
    let end_off = (end - sec.vaddr) as usize;
    sec.bytes.get(off..end_off.min(sec.bytes.len()))
}

pub struct Options {
    pub no_llm: bool,
    pub show_prompt: bool,
}

/// Runs the solver. Returns the text to print.
pub fn solve(path: &Path, opts: &Options) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let mut program = crate::formats::parse(&data).map_err(|e| e.to_string())?;
    prepare(&mut program);

    // Prefer an arm64 slice if present, else the first.
    let obj = program
        .objects
        .iter()
        .find(|o| o.arch == crate::model::Arch::Aarch64)
        .or_else(|| program.objects.first())
        .ok_or("no code to analyze")?;

    let dis = Disassembler::new(obj.arch).map_err(|e| e.to_string())?;
    let g = graph::build(obj);
    let cands = candidates(&g);
    if cands.is_empty() {
        return Err("no functions found to analyze".into());
    }

    let mut listings = String::new();
    for f in &cands {
        if let Some(bytes) = function_bytes(obj, f.addr) {
            listings.push_str(&format!("; function {} @ {:#x}\n", f.name, f.addr));
            listings.push_str(&dis.listing(obj, f.addr, bytes));
            listings.push('\n');
        }
    }

    let system = "You are a reverse-engineering assistant. You are given annotated \
        disassembly of one or more functions from a small 'crackme' challenge binary. \
        Work out what input (password, serial, key, or flag) makes the check succeed. \
        Reason step by step from the instructions, note any comparison against a constant \
        or embedded string, and state the final answer clearly. If the exact input cannot \
        be recovered from static disassembly alone, say so and explain what it depends on.";
    let user = format!(
        "Architecture: {}\n\nDisassembly:\n{}\n\nWhat input passes the check?",
        obj.arch.label(),
        listings
    );

    if opts.show_prompt {
        return Ok(format!("--- system ---\n{system}\n\n--- user ---\n{user}"));
    }

    if opts.no_llm {
        return Ok(format!(
            "LLM reasoning disabled (--no-llm). Candidate check function(s):\n\n{listings}\
             \nSet a provider (LLM_PROVIDER + LLM_API_KEY) and drop --no-llm to have a model solve it."
        ));
    }

    match Provider::from_env() {
        Ok(p) => {
            eprintln!("asking {} ({})…", p.name, p.model);
            let answer = p.complete(system, &user)?;
            Ok(format!(
                "{listings}\n=== {} / {} ===\n{answer}\n",
                p.name, p.model
            ))
        }
        Err(e) => Ok(format!(
            "{listings}\nLLM not configured: {e}\n(Showing disassembly only. Re-run with a provider set, or --no-llm to silence this.)"
        )),
    }
}
