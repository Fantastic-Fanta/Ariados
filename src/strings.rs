//! Printable-string extraction, like the classic `strings` command.
//!
//! Binaries store text (URLs, file paths, error messages, shell commands) as
//! raw bytes. We scan for runs of printable characters in two encodings:
//! plain ASCII/UTF-8, and UTF-16 little-endian, which Windows programs use a lot.

use serde::Serialize;

/// Which encoding a string was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

/// One string found in the file.
#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    /// Byte offset in the file where the string starts.
    pub offset: usize,
    pub encoding: Encoding,
    pub text: String,
}

fn is_printable(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

/// Extracts every string of at least `min_len` characters from `data`.
pub fn extract(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut found = extract_ascii(data, min_len);
    found.extend(extract_utf16le(data, min_len));
    found.sort_by_key(|s| s.offset);
    found
}

fn extract_ascii(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut found = Vec::new();
    // `start` is `Some(index)` while we're inside a run of printable bytes.
    let mut start: Option<usize> = None;

    // Iterating to `data.len()` inclusive lets the final run be flushed by the
    // same code path as every other run.
    for i in 0..=data.len() {
        let printable = data.get(i).is_some_and(|&b| is_printable(b));
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    found.push(FoundString {
                        offset: s,
                        encoding: Encoding::Ascii,
                        // Every byte is printable ASCII, so this never loses data.
                        text: String::from_utf8_lossy(&data[s..i]).into_owned(),
                    });
                }
                start = None;
            }
            _ => {}
        }
    }
    found
}

fn extract_utf16le(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut found = Vec::new();

    // A UTF-16LE ASCII character looks like `[char, 0x00]`. Strings can start
    // at an even or odd offset, so we scan both alignments.
    for alignment in 0..2 {
        let mut current = String::new();
        let mut start = 0;
        let mut i = alignment;

        // Running one step past the end guarantees a final flush of `current`.
        while i <= data.len() {
            let pair = (data.get(i), data.get(i + 1));
            let ch = match pair {
                (Some(&lo), Some(&0)) if is_printable(lo) => Some(lo as char),
                _ => None,
            };

            match ch {
                Some(c) => {
                    if current.is_empty() {
                        start = i;
                    }
                    current.push(c);
                }
                None => {
                    if current.len() >= min_len {
                        found.push(FoundString {
                            offset: start,
                            encoding: Encoding::Utf16Le,
                            text: std::mem::take(&mut current),
                        });
                    } else {
                        current.clear();
                    }
                }
            }
            i += 2;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_runs_and_skips_short_ones() {
        let data = b"\x00\x01hello world\x00ab\x00curl -s http://x\xff";
        let texts: Vec<_> = extract(data, 6).into_iter().map(|s| s.text).collect();
        assert_eq!(texts, vec!["hello world", "curl -s http://x"]);
    }

    #[test]
    fn finds_string_at_end_of_input() {
        let found = extract(b"\x00trailing", 6);
        assert_eq!(found[0].text, "trailing");
        assert_eq!(found[0].offset, 1);
    }

    #[test]
    fn finds_utf16le() {
        let mut data = vec![0xff, 0xff];
        for c in "cmd.exe /c".bytes() {
            data.extend([c, 0]);
        }
        let found = extract(&data, 6);
        assert!(
            found
                .iter()
                .any(|s| s.encoding == Encoding::Utf16Le && s.text == "cmd.exe /c")
        );
    }
}
