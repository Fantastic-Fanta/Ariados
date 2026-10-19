//! ELF parser, built on goblin.
//!
//! ELF import resolution is simpler than Mach-O: PLT relocations map a GOT slot
//! address directly to a dynamic-symbol name. We record those slots in
//! `import_slots`; the disassembly pass later attributes PLT thunks that jump
//! through a slot to the imported name.

use crate::error::AnalyzeError;
use crate::model::*;
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS};
use goblin::elf::Elf;
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, AnalyzeError>;

const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

pub fn parse(data: &[u8]) -> Result<Vec<Object>> {
    let elf = Elf::parse(data).map_err(|e| AnalyzeError::Malformed(format!("elf: {e}")))?;

    let arch = match elf.header.e_machine {
        EM_X86_64 => Arch::X86_64,
        EM_AARCH64 => Arch::Aarch64,
        EM_386 => Arch::X86,
        _ => Arch::Unsupported,
    };

    // Sections, copying bytes out of the mapped file.
    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let kind = if sh.sh_flags as u32 & SHF_EXECINSTR != 0 {
            SectionKind::Code
        } else {
            SectionKind::Data
        };
        let bytes = if sh.sh_type == SHT_NOBITS {
            Vec::new()
        } else {
            data.get(sh.sh_offset as usize..(sh.sh_offset as usize).saturating_add(sh.sh_size as usize))
                .map(|b| b.to_vec())
                .unwrap_or_default()
        };
        sections.push(Section {
            name,
            segment: String::new(),
            vaddr: sh.sh_addr,
            size: sh.sh_size,
            file_off: sh.sh_offset as usize,
            kind,
            bytes,
        });
    }

    // Function starts and names, from both the static and dynamic symbol tables.
    let mut names: BTreeMap<u64, NamedAddr> = BTreeMap::new();
    let mut functions: Vec<u64> = Vec::new();
    for (symtab, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        for sym in symtab.iter() {
            if sym.is_function() && sym.st_value != 0 {
                let name = strtab.get_at(sym.st_name).unwrap_or("").to_string();
                functions.push(sym.st_value);
                if !name.is_empty() {
                    names.entry(sym.st_value).or_insert(NamedAddr {
                        name,
                        kind: NameKind::LocalFunction,
                    });
                }
            }
        }
    }

    // Import slots: PLT relocations and GLOB_DAT point a slot address at a
    // dynamic symbol. Collect dynsym names by index first.
    let dynsym_names: Vec<String> = elf
        .dynsyms
        .iter()
        .map(|s| elf.dynstrtab.get_at(s.st_name).unwrap_or("").to_string())
        .collect();

    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    for relocs in [&elf.pltrelocs, &elf.dynrelas, &elf.dynrels] {
        for r in relocs.iter() {
            if let Some(name) = dynsym_names.get(r.r_sym) {
                if !name.is_empty() {
                    import_slots.insert(r.r_offset, name.clone());
                }
            }
        }
    }

    functions.sort_unstable();
    functions.dedup();

    let libraries = elf.libraries.iter().map(|s| s.to_string()).collect();

    Ok(vec![Object {
        arch,
        entry: elf.entry,
        little_endian: elf.little_endian,
        sections,
        functions,
        names,
        import_slots,
        // ELF has no Mach-O-style code signature; treat as unsigned.
        signing: Signing::Unsigned,
        libraries,
    }])
}
