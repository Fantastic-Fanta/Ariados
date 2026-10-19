//! The evidence graph: per-function facts plus the call edges between them.
//!
//! This is the structure rules run against. Each function carries the strings
//! it uses and the imports it calls; call edges let a behavior rule follow a
//! trail across functions ("decodes a URL *here*, then calls the function that
//! sends it *there*").

use crate::disasm::Disassembler;
use crate::model::{Arch, NameKind, Object, SectionKind};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub addr: u64,
    pub name: String,
    /// Strings this function references, in address order.
    pub strings: Vec<String>,
    /// Imported functions this function calls or loads.
    pub imports: Vec<String>,
    /// Addresses of local functions it directly calls.
    pub calls: Vec<u64>,
}

pub struct Graph {
    pub arch: Arch,
    pub functions: BTreeMap<u64, FunctionInfo>,
}

impl Graph {
    /// Returns a display name for an address: its symbol, or `sub_<addr>`.
    pub fn name_of(&self, addr: u64) -> String {
        self.functions
            .get(&addr)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("sub_{addr:x}"))
    }
}

/// Builds the evidence graph for one object by disassembling each function.
pub fn build(obj: &Object) -> Graph {
    let mut functions = BTreeMap::new();
    let dis = match Disassembler::new(obj.arch) {
        Ok(d) => d,
        Err(_) => return Graph { arch: obj.arch, functions },
    };

    for &start in &obj.functions {
        let Some(sec) = obj.section_at(start) else { continue };
        if sec.kind != SectionKind::Code {
            continue;
        }
        let sec_end = sec.vaddr + sec.size;
        // End the function at the next function start inside the same section,
        // falling back to the section end for the last one.
        let end = obj
            .functions
            .iter()
            .copied()
            .find(|&f| f > start && f <= sec_end)
            .unwrap_or(sec_end);

        let off = (start - sec.vaddr) as usize;
        let end_off = (end - sec.vaddr) as usize;
        let Some(bytes) = sec.bytes.get(off..end_off.min(sec.bytes.len())) else { continue };
        if bytes.is_empty() {
            continue;
        }

        let xref = dis.xref_range(obj, start, bytes);
        let name = match obj.names.get(&start) {
            Some(n) if n.kind == NameKind::LocalFunction => n.name.clone(),
            _ => format!("sub_{start:x}"),
        };
        functions.insert(
            start,
            FunctionInfo {
                addr: start,
                name,
                strings: xref.strings.into_iter().map(|(_, s)| s).collect(),
                imports: xref.imports,
                calls: xref.calls,
            },
        );
    }

    Graph { arch: obj.arch, functions }
}
