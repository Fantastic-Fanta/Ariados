//! Container parsing: turn a file on disk into a `Program` of analyzable
//! `Object`s, dispatching on the magic bytes to the right format parser.

pub mod elf;
pub mod macho;
pub mod pe;

use crate::error::AnalyzeError;
use crate::model::{Format, Program};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, AnalyzeError>;

/// Parses raw bytes into a `Program`, selecting the format by magic number.
pub fn parse(data: &[u8]) -> Result<Program> {
    if data.len() < 4 {
        return Err(AnalyzeError::Truncated { want: 4, at: 0 });
    }
    let magic = crate::byteutil::u32_le(data, 0)?;

    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex(&hasher.finalize());

    let (format, objects) = if macho::matches(magic) {
        (Format::MachO, macho::parse(data)?)
    } else if &data[0..4] == b"\x7fELF" {
        (Format::Elf, elf::parse(data)?)
    } else if &data[0..2] == b"MZ" {
        (Format::Pe, pe::parse(data)?)
    } else {
        return Err(AnalyzeError::UnknownFormat(magic));
    };

    Ok(Program {
        format,
        sha256,
        size: data.len() as u64,
        objects,
    })
}

/// True if the bytes look like an executable we can parse. Cheap check used
/// when walking a directory tree so we don't try to parse text files.
pub fn looks_executable(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = crate::byteutil::u32_le(data, 0).unwrap_or(0);
    macho::matches(magic) || &data[0..4] == b"\x7fELF" || &data[0..2] == b"MZ"
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
