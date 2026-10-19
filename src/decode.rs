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
                            let text: String = data[s..i].iter().map(|&b| (b ^ key) as char).collect();
                            // Require some letters so we don't report runs of
                            // decoded punctuation or whitespace.
                            if text.chars().filter(|c| c.is_ascii_alphabetic()).count() >= min_len / 2 {
                                out.push(Hidden { section: sec.name.clone(), offset: s, key, text });
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

/// If a decoded string looks like a malware indicator, returns a short label.
/// Used to turn hidden-string recovery into a finding, since a *hidden*
/// suspicious string is a much stronger signal than a plaintext one.
pub fn notable(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    if l.contains("http://") || l.contains("https://") {
        Some("URL")
    } else if l.contains("osascript") || l.contains("/bin/sh") || l.contains("/bin/bash") {
        Some("shell/script command")
    } else if l.contains("launchagents") || l.contains("launchdaemons") {
        Some("persistence path")
    } else if l.contains("login data") || l.contains("keychain") || l.contains(".ssh") {
        Some("credential path")
    } else {
        None
    }
}
