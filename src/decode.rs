//! Hidden-string recovery.
//!
//! Malware routinely hides its telltale strings (URLs, paths, commands) by
//! XOR-encoding them, so a plain `strings` pass sees nothing. This module
//! brute-forces single-byte XOR keys over the data sections and reports any key
//! that turns a run of bytes into readable text — the most common obfuscation,
//! and one that needs no code emulation.
//!
//! Recovering stack-built strings (bytes assembled by instructions at runtime)
//! would need an emulator; that's noted as future work in the README.

use crate::model::{Object, SectionKind};
use serde::Serialize;

/// A string recovered by XOR-decoding.
#[derive(Debug, Clone, Serialize)]
pub struct Hidden {
    pub section: String,
    pub offset: usize,
    pub key: u8,
    pub text: String,
}

/// Cap per section so a huge data blob can't make decoding dominate runtime.
const MAX_SECTION_SCAN: usize = 2 * 1024 * 1024;

fn is_text(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

/// Finds runs of `min_len`+ bytes that decode to printable text under some
/// single-byte XOR key (key 0 excluded — that's just a plaintext string).
pub fn xor_strings(obj: &Object, min_len: usize) -> Vec<Hidden> {
    let mut out = Vec::new();
    for sec in &obj.sections {
        if sec.kind == SectionKind::Code || sec.bytes.is_empty() {
            continue;
        }
        let data = &sec.bytes[..sec.bytes.len().min(MAX_SECTION_SCAN)];
        for key in 1u8..=255 {
            // 0x20 is ASCII case-flip and maps NUL→space, so it turns ordinary
            // NUL-separated plaintext into one "decoded" run — a systematic
            // false positive, never a real malware key. Skip it.
            if key == 0x20 {
                continue;
            }
            let mut run_start = None;
            for i in 0..=data.len() {
                let decoded_printable = data.get(i).map(|&b| is_text(b ^ key)).unwrap_or(false);
                match (decoded_printable, run_start) {
                    (true, None) => run_start = Some(i),
                    (false, Some(s)) => {
                        if i - s >= min_len {
                            let text: String =
                                data[s..i].iter().map(|&b| (b ^ key) as char).collect();
                            // Require some letters so we don't report runs of
                            // decoded punctuation or whitespace.
                            if text.chars().filter(|c| c.is_ascii_alphabetic()).count()
                                >= min_len / 2
                            {
                                out.push(Hidden {
                                    section: sec.name.clone(),
                                    offset: s,
                                    key,
                                    text,
                                });
                            }
                        }
                        run_start = None;
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Indicator cribs and their labels, used by the fast scan-path search below.
/// These mirror `notable()` but are the literal needles to look for.
const INDICATORS: &[(&str, &str)] = &[
    ("http://", "URL"),
    ("https://", "URL"),
    ("osascript", "shell/script command"),
    ("do shell script", "shell/script command"),
    ("/bin/sh -c", "shell/script command"),
    ("LaunchAgents/", "persistence path"),
    ("LaunchDaemons/", "persistence path"),
    ("login.keychain-db", "credential store"),
    ("cookies.sqlite", "credential store"),
    ("Login Data", "credential store"),
];

/// A hidden indicator string recovered quickly for the scan path.
#[derive(Debug, Clone)]
pub struct HiddenIndicator {
    pub key: u8,
    pub label: &'static str,
    pub text: String,
}

/// Finds single-byte-XOR-hidden indicator strings in data sections, fast.
///
/// Instead of brute-forcing all 255 keys and extracting every string (which
/// produces millions of hits on a real app), this exploits a property of
/// single-byte XOR: it cancels in the byte-to-byte difference, so `c[i]^c[i+1]`
/// equals `plain[i]^plain[i+1]` regardless of the key. We search the data's
/// difference stream for each indicator's difference signature with one
/// `memmem` per indicator, recover the key at each hit, and decode the run.
pub fn xor_indicators(obj: &Object) -> Vec<HiddenIndicator> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for sec in &obj.sections {
        if sec.kind == SectionKind::Code || sec.bytes.len() < 8 {
            continue;
        }
        let data = &sec.bytes[..sec.bytes.len().min(MAX_SECTION_SCAN)];
        // Difference stream of the ciphertext (key-independent).
        let data_diff: Vec<u8> = data.windows(2).map(|w| w[0] ^ w[1]).collect();

        for (crib, label) in INDICATORS {
            let c = crib.as_bytes();
            if c.len() < 2 {
                continue;
            }
            let crib_diff: Vec<u8> = c.windows(2).map(|w| w[0] ^ w[1]).collect();
            for pos in memchr::memmem::find_iter(&data_diff, &crib_diff) {
                // Single-byte key that makes data[pos..] decode to the crib.
                let key = data[pos] ^ c[0];
                if key == 0 {
                    continue; // key 0 == plaintext, not hidden
                }
                // Expand to the full printable run around the match.
                let dec = |i: usize| data[i] ^ key;
                let mut start = pos;
                while start > 0 && is_text(dec(start - 1)) {
                    start -= 1;
                }
                let mut end = pos + c.len();
                while end < data.len() && is_text(dec(end)) {
                    end += 1;
                }
                let text: String = (start..end).map(|i| dec(i) as char).collect();
                if seen.insert(text.clone()) {
                    out.push(HiddenIndicator { key, label, text });
                }
            }
        }
    }
    out
}

/// If a decoded string looks like a malware indicator, returns a short label.
/// Used to turn hidden-string recovery into a finding, since a *hidden*
/// suspicious string is a much stronger signal than a plaintext one.
///
/// Indicators here must be specific and long. Short, common fragments (`.ssh`,
/// `keychain`, `wallet`) match by chance when brute-forcing XOR keys over
/// megabytes of a real app's data, producing false "hidden string" findings.
pub fn notable(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    if l.contains("http://") || l.contains("https://") {
        Some("URL")
    } else if l.contains("osascript") || l.contains("do shell script") || l.contains("/bin/sh -c") {
        Some("shell/script command")
    } else if l.contains("launchagents/") || l.contains("launchdaemons/") {
        Some("persistence path")
    } else if l.contains("login data")
        || l.contains("login.keychain-db")
        || l.contains("cookies.sqlite")
    {
        Some("credential store")
    } else {
        None
    }
}
