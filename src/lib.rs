//! Ariados: a static binary triage tool.
//!
//! The library parses an executable (Mach-O, ELF or PE) into a format-neutral
//! model, disassembles it to build a cross-reference graph of which code uses
//! which strings and imports, matches capability and behavior rules over that
//! graph, and renders an evidence-backed report. The binary in `main.rs` is a
//! thin CLI over this library.

pub mod byteutil;
pub mod entropy;
pub mod error;
pub mod formats;
pub mod model;
pub mod strings;

pub use error::AnalyzeError;
pub use model::{Arch, Format, Object, Program};
