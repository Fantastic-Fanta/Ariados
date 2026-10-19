//! Ariados: a static binary triage tool.
//!
//! The library parses an executable (Mach-O, ELF or PE) into a format-neutral
//! model, disassembles it to build a cross-reference graph of which code uses
//! which strings and imports, matches capability and behavior rules over that
//! graph, and renders an evidence-backed report. The binary in `main.rs` is a
//! thin CLI over this library.

pub mod analysis;
pub mod audit;
pub mod byteutil;
pub mod decode;
pub mod diff;
pub mod disasm;
pub mod entropy;
pub mod error;
pub mod eval;
pub mod formats;
pub mod graph;
pub mod llm;
pub mod model;
pub mod policy;
pub mod report;
pub mod rules;
pub mod scan;
pub mod solve;
pub mod strings;
pub mod supplychain;
pub mod yara;

pub use error::AnalyzeError;
pub use model::{Arch, Format, Object, Program};
