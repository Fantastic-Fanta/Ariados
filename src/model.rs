//! Format-neutral representation of a parsed executable.
//!
//! Mach-O, ELF and PE all boil down to the same handful of things the analyzer
//! cares about: which architecture the code is, where the code and string bytes
//! live, where functions start, and a map from address to a human name (for
//! local functions and for imported library calls). Each format parser fills in
//! this structure, and everything downstream (disassembly, cross-referencing,
//! rules) works against it without knowing or caring which format it came from.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Format {
    MachO,
    Elf,
    Pe,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Format::MachO => "Mach-O",
            Format::Elf => "ELF",
            Format::Pe => "PE",
        };
        f.write_str(s)
    }
}

/// CPU architecture of a code object. The disassembler maps these to capstone
/// modes; `Unsupported` means we parsed the container but can't disassemble it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86_64,
    Aarch64,
    X86,
    Unsupported,
}

impl Arch {
    pub fn label(&self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "arm64",
            Arch::X86 => "i386",
            Arch::Unsupported => "unsupported-arch",
        }
    }
}

/// What kind of bytes a section holds, as far as analysis is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Executable machine code (e.g. `__text`, `.text`).
    Code,
    /// NUL-terminated C string literals (e.g. `__cstring`, `.rodata` strings).
    CString,
    /// Other readable data.
    Data,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub segment: String,
    pub vaddr: u64,
    pub size: u64,
    pub file_off: usize,
    pub kind: SectionKind,
    /// The section's bytes, copied out so the parsed object owns its data and
    /// isn't tied to the lifetime of the original file buffer.
    pub bytes: Vec<u8>,
}

impl Section {
    pub fn contains(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr < self.vaddr.saturating_add(self.size)
    }

    /// Returns the bytes starting at a virtual address, up to the section end.
    pub fn slice_from(&self, vaddr: u64) -> Option<&[u8]> {
        if !self.contains(vaddr) {
            return None;
        }
        let off = (vaddr - self.vaddr) as usize;
        self.bytes.get(off..)
    }
}

/// How an address got its name, which changes how much we trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NameKind {
    /// A function defined inside this binary (from the symbol table).
    LocalFunction,
    /// An imported library function, reached through a stub/PLT/IAT entry.
    Import,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamedAddr {
    pub name: String,
    pub kind: NameKind,
}

/// Code-signing status for a Mach-O. Other formats leave this `Unsigned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Signing {
    Unsigned,
    /// Has a code signature blob. Whether it's ad-hoc / notarized is filled in
    /// separately when we can afford to ask the OS (`codesign`/`spctl`).
    Signed,
}

/// One architecture slice of a binary, parsed into analyzable form.
pub struct Object {
    pub arch: Arch,
    pub entry: u64,
    pub little_endian: bool,
    pub sections: Vec<Section>,
    /// Sorted, de-duplicated function start addresses.
    pub functions: Vec<u64>,
    /// Address -> name, covering local functions and import stubs. This is what
    /// turns a raw `call 0x1040` into "calls `curl_easy_perform`".
    pub names: BTreeMap<u64, NamedAddr>,
    /// Address of an import pointer slot (Mach-O lazy/non-lazy pointers, ELF GOT,
    /// PE IAT) -> imported name. A load from one of these, or a jump through a
    /// stub that reads one, means the code is about to call that import.
    pub import_slots: BTreeMap<u64, String>,
    pub signing: Signing,
    /// Libraries this object links against (dylibs / DT_NEEDED / DLLs).
    pub libraries: Vec<String>,
}

impl Object {
    pub fn section_at(&self, vaddr: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(vaddr))
    }

    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.kind == SectionKind::Code)
    }

    /// Returns the raw bytes of the function starting at `start`, bounded by the
    /// next function start in the same code section. Shared by disassembly,
    /// stack-string recovery and the solver.
    pub fn function_bytes(&self, start: u64) -> Option<&[u8]> {
        let sec = self.section_at(start)?;
        if sec.kind != SectionKind::Code {
            return None;
        }
        let sec_end = sec.vaddr + sec.size;
        let end = self
            .functions
            .iter()
            .copied()
            .find(|&f| f > start && f <= sec_end)
            .unwrap_or(sec_end);
        let off = (start - sec.vaddr) as usize;
        let end_off = (end - sec.vaddr) as usize;
        sec.bytes.get(off..end_off.min(sec.bytes.len()))
    }

    /// Resolves an address referenced by code to an imported function name,
    /// whether the address is an import stub or a pointer slot.
    pub fn import_at(&self, vaddr: u64) -> Option<&str> {
        if let Some(n) = self.names.get(&vaddr)
            && n.kind == NameKind::Import
        {
            return Some(&n.name);
        }
        self.import_slots.get(&vaddr).map(|s| s.as_str())
    }

    /// Reads the NUL-terminated C string at a virtual address, if one lives
    /// there. Used to turn a data cross-reference into the actual string.
    pub fn cstring_at(&self, vaddr: u64) -> Option<String> {
        let sec = self.section_at(vaddr)?;
        if sec.kind == SectionKind::Code {
            return None;
        }
        let bytes = sec.slice_from(vaddr)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if end == 0 || end > 4096 {
            return None;
        }
        let raw = &bytes[..end];
        // Only accept mostly-printable runs; random data pointed at by a LEA
        // shouldn't be reported as a "string".
        let printable = raw
            .iter()
            .filter(|&&b| b == b'\t' || (0x20..=0x7e).contains(&b))
            .count();
        if printable * 10 < raw.len() * 9 {
            return None;
        }
        Some(String::from_utf8_lossy(raw).into_owned())
    }
}

/// A fully parsed program: one or more architecture slices (fat Mach-O has
/// several) plus file-level metadata.
pub struct Program {
    pub format: Format,
    pub sha256: String,
    pub size: u64,
    pub objects: Vec<Object>,
}
