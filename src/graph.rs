//! The evidence graph: per-function facts plus the call edges between them.
//!
//! This is the structure rules run against. Each function carries the strings
//! it uses and the imports it calls; call edges let a behavior rule follow a
//! trail across functions ("decodes a URL *here*, then calls the function that
//! sends it *there*").

use crate::disasm::Disassembler;
use crate::model::{Arch, NameKind, Object};
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
    /// Strings this function builds on the stack byte by byte. Computed in the
    /// same disassembly pass so hidden-string detection needs no second one.
    pub stack_strings: Vec<String>,
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
///
/// Functions are independent, so they disassemble in parallel — each worker
/// thread keeps its own capstone handle (which isn't shareable). Each function
/// yields its cross-references and stack strings from a single disassembly.
pub fn build(obj: &Object) -> Graph {
    use rayon::prelude::*;

    let analyze = |dis: &mut Option<Disassembler>, &start: &u64| -> Option<(u64, FunctionInfo)> {
        let dis = dis.as_ref()?;
        let bytes = obj.function_bytes(start)?;
        if bytes.is_empty() {
            return None;
        }
        let xref = dis.xref_range(obj, start, bytes);
        let name = match obj.names.get(&start) {
            Some(n) if n.kind == NameKind::LocalFunction => n.name.clone(),
            _ => format!("sub_{start:x}"),
        };
        Some((
            start,
            FunctionInfo {
                addr: start,
                name,
                strings: xref.strings.into_iter().map(|(_, s)| s).collect(),
                imports: xref.imports,
                calls: xref.calls,
                stack_strings: xref.stack_strings,
            },
        ))
    };

    let functions: BTreeMap<u64, FunctionInfo> = obj
        .functions
        .par_iter()
        .map_init(|| Disassembler::new(obj.arch).ok(), analyze)
        .flatten()
        .collect();

    Graph {
        arch: obj.arch,
        functions,
    }
}
