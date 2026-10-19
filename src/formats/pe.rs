//! PE parser, built on goblin.
//!
//! PE support is the most limited of the three: Windows binaries are usually
//! stripped of local symbols, so function discovery leans on exports and the
//! entry point, and linear-swept code near import calls. Import resolution is
//! solid, though: the import table maps each IAT slot RVA to a name.

use crate::error::AnalyzeError;
use crate::model::*;
use goblin::pe::PE;
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, AnalyzeError>;

pub fn parse(data: &[u8]) -> Result<Vec<Object>> {
    let pe = PE::parse(data).map_err(|e| AnalyzeError::Malformed(format!("pe: {e}")))?;
    let image_base = pe.image_base;

    let arch = match pe.header.coff_header.machine {
        COFF_MACHINE_X86_64 => Arch::X86_64,
        COFF_MACHINE_ARM64 => Arch::Aarch64,
        COFF_MACHINE_X86 => Arch::X86,
        _ => Arch::Unsupported,
    };

    let mut sections = Vec::new();
    for s in &pe.sections {
        let name = s.name().unwrap_or("").to_string();
        let is_code = s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
        let kind = if is_code {
            SectionKind::Code
        } else {
            SectionKind::Data
        };
        let start = s.pointer_to_raw_data as usize;
        let raw = s.size_of_raw_data as usize;
        let bytes = data
            .get(start..start.saturating_add(raw))
            .map(|b| b.to_vec())
            .unwrap_or_default();
        sections.push(Section {
            name,
            segment: String::new(),
            vaddr: image_base + s.virtual_address as u64,
            size: s.virtual_size as u64,
            file_off: start,
            kind,
            bytes,
        });
    }

    let mut names: BTreeMap<u64, NamedAddr> = BTreeMap::new();
    let mut functions: Vec<u64> = Vec::new();
    for e in &pe.exports {
        let addr = image_base + e.rva as u64;
        functions.push(addr);
        if let Some(n) = e.name {
            names.entry(addr).or_insert(NamedAddr {
                name: n.to_string(),
                kind: NameKind::LocalFunction,
            });
        }
    }
    let entry = image_base + pe.entry as u64;
    functions.push(entry);

    // Import slots: the IAT entry's RVA is goblin's `offset` field (import
    // address table RVA + index*ptr size). Its `rva` field is the hint/name
    // table RVA instead, which is not where code loads the pointer from.
    let mut import_slots: BTreeMap<u64, String> = BTreeMap::new();
    for imp in &pe.imports {
        import_slots.insert(image_base + imp.offset as u64, imp.name.to_string());
    }

    functions.sort_unstable();
    functions.dedup();

    let libraries = pe.libraries.iter().map(|s| s.to_string()).collect();

    Ok(vec![Object {
        arch,
        entry,
        little_endian: true,
        sections,
        functions,
        names,
        import_slots,
        signing: Signing::Unsigned,
        libraries,
    }])
}
