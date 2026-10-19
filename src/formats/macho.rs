//! Mach-O parser (thin and fat), written by hand rather than via goblin.
//!
//! We parse Mach-O ourselves because the evidence trail depends on resolving
//! `bl <stub>` / `call [rip+got]` to the imported function name, and that needs
//! the section `reserved1`/`reserved2` fields plus the indirect symbol table —
//! which goblin's `Section` struct doesn't surface. Doing it ourselves also
//! gives exact control over `LC_FUNCTION_STARTS` decoding. ELF and PE lean on
//! goblin instead, where import resolution is simpler.

use crate::byteutil::Reader;
use crate::error::AnalyzeError;
use crate::model::*;
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, AnalyzeError>;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const MH_MAGIC_32: u32 = 0xfeed_face;
const MH_CIGAM_32: u32 = 0xcefa_edfe;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_MAIN: u32 = 0x8000_0028;
const LC_CODE_SIGNATURE: u32 = 0x1d;

const SECTION_TYPE: u32 = 0x0000_00ff;
const S_CSTRING_LITERALS: u32 = 0x2;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0xe;

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

/// Returns true if `data` starts with any Mach-O or fat magic.
pub fn matches(magic: u32) -> bool {
    matches!(
        magic,
        MH_MAGIC_64
            | MH_CIGAM_64
            | MH_MAGIC_32
            | MH_CIGAM_32
            | FAT_MAGIC
            | FAT_CIGAM
            | FAT_MAGIC_64
            | FAT_CIGAM_64
    )
}

/// Parses every architecture slice of a Mach-O file into `Object`s.
pub fn parse(data: &[u8]) -> Result<Vec<Object>> {
    let magic = crate::byteutil::u32_le(data, 0)?;
    match magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => parse_fat(data, magic),
        _ => Ok(vec![parse_thin(data, 0)?]),
    }
}

/// Fat binaries are a big-endian header listing architecture slices by offset.
fn parse_fat(data: &[u8], magic: u32) -> Result<Vec<Object>> {
    let is64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
    // Fat headers are always big-endian on disk.
    let mut r = Reader::new(data, false);
    r.skip(4)?; // magic
    let nfat = r.u32()?;
    let mut objects = Vec::new();
    for _ in 0..nfat {
        r.skip(8)?; // cputype, cpusubtype
        let (offset, size) = if is64 {
            let o = r.u64()?;
            let s = r.u64()?;
            r.skip(8)?; // align + reserved
            (o as usize, s as usize)
        } else {
            let o = r.u32()? as usize;
            let s = r.u32()? as usize;
            r.skip(4)?; // align
            (o, s)
        };
        let slice = data
            .get(offset..offset.saturating_add(size))
            .ok_or_else(|| AnalyzeError::Malformed("fat slice out of range".into()))?;
        // A slice is itself a thin Mach-O; offsets inside it are slice-relative.
        if let Ok(obj) = parse_thin(slice, 0) {
            objects.push(obj);
        }
    }
    if objects.is_empty() {
        return Err(AnalyzeError::Malformed(
            "no usable slices in fat binary".into(),
        ));
    }
    Ok(objects)
}

/// Raw section header fields we need and that goblin drops.
struct RawSection {
    name: String,
    segment: String,
    addr: u64,
    size: u64,
    offset: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

impl RawSection {
    fn sect_type(&self) -> u32 {
        self.flags & SECTION_TYPE
    }
    fn is_code(&self) -> bool {
        self.name == "__text"
            || self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }
}

fn parse_thin(data: &[u8], _base: usize) -> Result<Object> {
    let magic = crate::byteutil::u32_le(data, 0)?;
    let (little, is64) = match magic {
        MH_MAGIC_64 => (true, true),
        MH_CIGAM_64 => (false, true),
        MH_MAGIC_32 => (true, false),
        MH_CIGAM_32 => (false, false),
        other => return Err(AnalyzeError::UnknownFormat(other)),
    };
    if !is64 {
        // 32-bit Mach-O is rare on modern targets; parse enough to disassemble
        // i386 would need a separate header layout. Skip for now, clearly.
        return Err(AnalyzeError::Unsupported("32-bit Mach-O".into()));
    }

    let mut r = Reader::new(data, little);
    r.skip(4)?; // magic
    let cputype = r.u32()?;
    r.skip(4)?; // cpusubtype
    r.skip(4)?; // filetype
    let ncmds = r.u32()?;
    r.skip(4)?; // sizeofcmds
    r.skip(4)?; // flags
    r.skip(4)?; // reserved (64-bit header)

    let arch = match cputype {
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        CPU_TYPE_X86 => Arch::X86,
        _ => Arch::Unsupported,
    };

    let mut raw_sections: Vec<RawSection> = Vec::new();
    let mut libraries: Vec<String> = Vec::new();
    let mut text_base: Option<u64> = None;
    let mut entry = 0u64;

    let mut symoff = 0u32;
    let mut nsyms = 0u32;
    let mut stroff = 0u32;
    let mut strsize = 0u32;
    let mut indirectsymoff = 0u32;
    let mut nindirectsyms = 0u32;
    let mut func_starts: Option<(u32, u32)> = None;
    let mut signed = false;

    // Walk the load commands. Each has {cmd, cmdsize}; we advance by cmdsize
    // from the command's start so an unknown command is skipped cleanly.
    let mut cmd_off = r.pos;
    for _ in 0..ncmds {
        let mut lc = Reader::at(data, cmd_off, little);
        let cmd = lc.u32()?;
        let cmdsize = lc.u32()? as usize;
        if cmdsize < 8 {
            return Err(AnalyzeError::Malformed("zero-size load command".into()));
        }
        match cmd {
            LC_SEGMENT_64 => {
                let segname = lc.fixed_str(16)?;
                let vmaddr = lc.u64()?;
                lc.skip(8)?; // vmsize
                let fileoff = lc.u64()?;
                lc.skip(8)?; // filesize
                lc.skip(16)?; // maxprot, initprot, nsects, flags
                let nsects = {
                    // reread nsects: it sits right after the two prot u32s.
                    // layout: maxprot(4) initprot(4) nsects(4) flags(4)
                    let mut s = Reader::at(data, cmd_off + 8 + 16 + 8 + 8 + 8 + 8 + 8, little);
                    s.u32()?
                };
                if segname == "__TEXT" {
                    text_base = Some(vmaddr);
                }
                let _ = fileoff;
                // Section headers follow the 72-byte segment command body.
                let mut sec_r = Reader::at(data, cmd_off + 72, little);
                for _ in 0..nsects {
                    let name = sec_r.fixed_str(16)?;
                    let seg = sec_r.fixed_str(16)?;
                    let addr = sec_r.u64()?;
                    let size = sec_r.u64()?;
                    let offset = sec_r.u32()?;
                    sec_r.skip(4)?; // align
                    sec_r.skip(8)?; // reloff, nreloc
                    let flags = sec_r.u32()?;
                    let reserved1 = sec_r.u32()?;
                    let reserved2 = sec_r.u32()?;
                    sec_r.skip(4)?; // reserved3
                    raw_sections.push(RawSection {
                        name,
                        segment: seg,
                        addr,
                        size,
                        offset,
                        flags,
                        reserved1,
                        reserved2,
                    });
                }
            }
            LC_SYMTAB => {
                symoff = lc.u32()?;
                nsyms = lc.u32()?;
                stroff = lc.u32()?;
                strsize = lc.u32()?;
            }
            LC_DYSYMTAB => {
                // Skip to indirectsymoff: 8 u32 pairs precede it (see struct).
                let mut d = Reader::at(data, cmd_off + 8, little);
                for _ in 0..12 {
                    d.u32()?;
                }
                indirectsymoff = d.u32()?;
                nindirectsyms = d.u32()?;
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                // dylib command: name is at an offset given by the first u32.
                let name_off = lc.u32()? as usize;
                if let Some(slice) = data.get(cmd_off + name_off..cmd_off + cmdsize) {
                    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                    libraries.push(String::from_utf8_lossy(&slice[..end]).into_owned());
                }
            }
            LC_FUNCTION_STARTS => {
                let off = lc.u32()?;
                let sz = lc.u32()?;
                func_starts = Some((off, sz));
            }
            LC_MAIN => {
                entry = lc.u64()?; // entryoff; turned into a vaddr below
            }
            LC_CODE_SIGNATURE => signed = true,
            _ => {}
        }
        cmd_off += cmdsize;
    }

    // Build the symbol name table, indexed by symbol index, and collect defined
    // function symbols (address -> name).
    let (sym_names, defined) =
        parse_symbols(data, little, symoff, nsyms, stroff, strsize, &raw_sections);

    // Read the indirect symbol table (array of symbol indices).
    let indirect = read_indirect(data, little, indirectsymoff, nindirectsyms);

    // Resolve import names: stubs are call targets (kept in `names`); lazy and
    // non-lazy pointer slots are data-load targets (kept in `import_slots`).
    // Both come from the indirect symbol table.
    let mut names: BTreeMap<u64, NamedAddr> = BTreeMap::new();
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    for sec in &raw_sections {
        let stype = sec.sect_type();
        match stype {
            S_SYMBOL_STUBS => {
                let stub_size = sec.reserved2 as u64;
                if stub_size == 0 {
                    continue;
                }
                let count = sec.size / stub_size;
                for i in 0..count {
                    let idx = sec.reserved1 as usize + i as usize;
                    if let Some(name) = indirect_name(&indirect, &sym_names, idx) {
                        names.insert(
                            sec.addr + i * stub_size,
                            NamedAddr {
                                name,
                                kind: NameKind::Import,
                            },
                        );
                    }
                }
            }
            S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS => {
                let ptr_size = 8u64;
                let count = sec.size / ptr_size;
                for i in 0..count {
                    let idx = sec.reserved1 as usize + i as usize;
                    if let Some(name) = indirect_name(&indirect, &sym_names, idx) {
                        import_slots.insert(sec.addr + i * ptr_size, name);
                    }
                }
            }
            _ => {}
        }
    }

    // Local defined functions. Don't overwrite an import mapping.
    for (addr, name) in &defined {
        names.entry(*addr).or_insert_with(|| NamedAddr {
            name: name.clone(),
            kind: NameKind::LocalFunction,
        });
    }

    // Convert entry offset to a virtual address using the text base.
    if let Some(base) = text_base {
        entry = base.saturating_add(entry);
    }

    // Build analyzable sections (copy the bytes out of the file buffer).
    let mut sections = Vec::new();
    for sec in &raw_sections {
        let kind = if sec.is_code() {
            SectionKind::Code
        } else if sec.sect_type() == S_CSTRING_LITERALS {
            SectionKind::CString
        } else {
            SectionKind::Data
        };
        // Zerofill / bss sections have no file bytes (offset can be 0/size huge).
        let bytes = if sec.sect_type() == 0x1 {
            Vec::new()
        } else {
            data.get(sec.offset as usize..(sec.offset as usize).saturating_add(sec.size as usize))
                .map(|b| b.to_vec())
                .unwrap_or_default()
        };
        sections.push(Section {
            name: sec.name.clone(),
            segment: sec.segment.clone(),
            vaddr: sec.addr,
            size: sec.size,
            file_off: sec.offset as usize,
            kind,
            bytes,
        });
    }

    // Function starts: defined symbols plus the LC_FUNCTION_STARTS table.
    let mut functions: Vec<u64> = defined.iter().map(|(a, _)| *a).collect();
    if let (Some((off, sz)), Some(base)) = (func_starts, text_base) {
        decode_function_starts(data, off, sz, base, &mut functions);
    }
    functions.sort_unstable();
    functions.dedup();

    Ok(Object {
        arch,
        entry,
        little_endian: little,
        sections,
        functions,
        names,
        import_slots,
        signing: if signed {
            Signing::Signed
        } else {
            Signing::Unsigned
        },
        libraries,
    })
}

/// Reads the symbol table: returns (names-by-index, defined-functions).
fn parse_symbols(
    data: &[u8],
    little: bool,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    sections: &[RawSection],
) -> (Vec<String>, Vec<(u64, String)>) {
    let mut names = Vec::with_capacity(nsyms as usize);
    let mut defined = Vec::new();
    let str_start = stroff as usize;
    let str_end = str_start.saturating_add(strsize as usize);
    let strtab = data.get(str_start..str_end).unwrap_or(&[]);

    let read_name = |n_strx: u32| -> String {
        let s = n_strx as usize;
        if let Some(rest) = strtab.get(s..) {
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(&rest[..end]).into_owned()
        } else {
            String::new()
        }
    };

    for i in 0..nsyms as usize {
        let off = symoff as usize + i * 16; // nlist_64 is 16 bytes
        let mut nr = Reader::at(data, off, little);
        let n_strx = match nr.u32() {
            Ok(v) => v,
            Err(_) => {
                names.push(String::new());
                continue;
            }
        };
        let n_type = nr.u8().unwrap_or(0);
        let _n_sect = nr.u8().unwrap_or(0);
        let _n_desc = nr.u16().unwrap_or(0);
        let n_value = nr.u64().unwrap_or(0);
        let name = read_name(n_strx);

        // A defined symbol in a section, not a debug (STAB) entry, with a real
        // address and a name, is treated as a function/label start.
        let is_defined = n_type & N_STAB == 0 && n_type & N_TYPE == N_SECT && n_value != 0;
        if is_defined && !name.is_empty() {
            let in_code = sections
                .iter()
                .any(|s| s.is_code() && n_value >= s.addr && n_value < s.addr + s.size);
            if in_code {
                defined.push((n_value, clean_symbol(&name)));
            }
        }
        names.push(name);
    }
    (names, defined)
}

/// Strips the leading underscore the Mach-O C ABI adds to symbol names, so
/// `_malloc` reads as `malloc` in reports.
fn clean_symbol(name: &str) -> String {
    name.strip_prefix('_').unwrap_or(name).to_string()
}

fn read_indirect(data: &[u8], little: bool, off: u32, count: u32) -> Vec<u32> {
    let mut out = Vec::with_capacity(count as usize);
    let mut r = Reader::at(data, off as usize, little);
    for _ in 0..count {
        match r.u32() {
            Ok(v) => out.push(v),
            Err(_) => break,
        }
    }
    out
}

fn indirect_name(indirect: &[u32], sym_names: &[String], idx: usize) -> Option<String> {
    let sym_idx = *indirect.get(idx)?;
    if sym_idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
        return None;
    }
    let name = sym_names.get(sym_idx as usize)?;
    if name.is_empty() {
        None
    } else {
        Some(clean_symbol(name))
    }
}

/// Decodes the delta-encoded LC_FUNCTION_STARTS table into absolute addresses.
fn decode_function_starts(data: &[u8], off: u32, size: u32, base: u64, out: &mut Vec<u64>) {
    let start = off as usize;
    let end = start.saturating_add(size as usize);
    let Some(table) = data.get(start..end) else {
        return;
    };
    let mut r = Reader::new(table, true);
    let mut addr = base;
    while r.remaining() > 0 {
        match r.uleb128() {
            Ok(0) => break, // trailing padding
            Ok(delta) => {
                addr = addr.saturating_add(delta);
                out.push(addr);
            }
            Err(_) => break,
        }
    }
}
