//! Error types for the analysis engine.
//!
//! Parsing runs on attacker-controlled files, so every failure path returns a
//! typed error rather than panicking. The CLI turns these into a clean message
//! and a non-zero exit code instead of a stack trace.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzeError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a recognized executable (unknown magic {0:#010x})")]
    UnknownFormat(u32),

    #[error("file is too short: wanted {want} bytes at offset {at}")]
    Truncated { want: usize, at: usize },

    #[error("malformed binary: {0}")]
    Malformed(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("disassembler error: {0}")]
    Disasm(String),
}
