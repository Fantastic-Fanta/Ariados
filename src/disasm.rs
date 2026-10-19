//! Disassembly and cross-referencing.
//!
//! For each function we disassemble its bytes and extract two kinds of
//! reference that the evidence trail is built from:
//!
//!   * **string references** — a `lea`/`adrp+add`/`mov` that computes the
//!     address of a C string, giving "this function uses the string X";
//!   * **import/call references** — a direct `call`/`bl` to an import stub, a
//!     load from an import pointer slot, or a direct call to another local
//!     function, giving "this function calls Y".
//!
//! We decode operands with capstone's detail mode. x86-64 string/import refs
//! are RIP-relative memory operands; arm64 refs are an `adrp` that sets a
//! register to a page address followed by an `add`/`ldr` that adds the low
//! bits, so we track the last `adrp` value per register.

use crate::error::AnalyzeError;
use crate::model::{Arch, NameKind, Object};
use capstone::arch::{arm64, x86, BuildsCapstone};
use capstone::prelude::*;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, AnalyzeError>;

/// References found inside one function.
#[derive(Debug, Default, Clone)]
pub struct Xref {
    /// (address of the string, its text).
    pub strings: Vec<(u64, String)>,
    /// Imported function names this function reaches (call or load).
    pub imports: Vec<String>,
    /// Addresses of local functions this function directly calls.
    pub calls: Vec<u64>,
}

pub struct Disassembler {
    cs: Capstone,
    arch: Arch,
}

impl Disassembler {
    pub fn new(arch: Arch) -> Result<Self> {
        let cs = match arch {
            Arch::X86_64 => Capstone::new().x86().mode(x86::ArchMode::Mode64).detail(true).build(),
            Arch::X86 => Capstone::new().x86().mode(x86::ArchMode::Mode32).detail(true).build(),
            Arch::Aarch64 => Capstone::new().arm64().mode(arm64::ArchMode::Arm).detail(true).build(),
            Arch::Unsupported => return Err(AnalyzeError::Unsupported("architecture".into())),
        };
        let cs = cs.map_err(|e| AnalyzeError::Disasm(e.to_string()))?;
        Ok(Disassembler { cs, arch })
    }

    /// Disassembles `[start, start+bytes.len())` and extracts references.
    /// `obj` supplies the address→name and address→string maps.
    pub fn xref_range(&self, obj: &Object, start: u64, bytes: &[u8]) -> Xref {
        let mut out = Xref::default();
        let Ok(insns) = self.cs.disasm_all(bytes, start) else {
            return out;
        };

        // arm64: remembers the page address an `adrp` last wrote to a register.
        let mut adrp_page: HashMap<String, u64> = HashMap::new();

        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            let Ok(detail) = self.cs.insn_detail(insn) else { continue };
            let arch_detail = detail.arch_detail();

            match self.arch {
                Arch::X86_64 | Arch::X86 => {
                    let Some(x) = arch_detail.x86() else { continue };
                    let ops: Vec<_> = x.operands().collect();
                    let is_branch = matches!(mnem, "call" | "jmp" | "je" | "jne" | "jg" | "jl");
                    for op in &ops {
                        match &op.op_type {
                            x86::X86OperandType::Imm(target) if mnem == "call" || mnem == "jmp" => {
                                self.record_call(obj, *target as u64, &mut out);
                            }
                            x86::X86OperandType::Mem(mem) => {
                                let base = self.cs.reg_name(mem.base()).unwrap_or_default();
                                if base == "rip" {
                                    let ea = next.wrapping_add(mem.disp() as u64);
                                    self.record_data(obj, ea, &mut out);
                                }
                            }
                            _ => {}
                        }
                    }
                    let _ = is_branch;
                }
                Arch::Aarch64 => {
                    let Some(a) = arch_detail.arm64() else { continue };
                    let ops: Vec<_> = a.operands().collect();
                    match mnem {
                        "bl" | "b" => {
                            if let Some(arm64::Arm64OperandType::Imm(t)) =
                                ops.first().map(|o| o.op_type.clone())
                            {
                                self.record_call(obj, t as u64, &mut out);
                            }
                        }
                        "adrp" => {
                            if let (Some(dst), Some(arm64::Arm64OperandType::Imm(page))) = (
                                ops.first().and_then(|o| self.reg(&o.op_type)),
                                ops.get(1).map(|o| o.op_type.clone()),
                            ) {
                                adrp_page.insert(dst, page as u64);
                            }
                        }
                        "add" => {
                            // add dst, src, #imm — combine with src's adrp page.
                            if let (Some(src), Some(arm64::Arm64OperandType::Imm(imm))) = (
                                ops.get(1).and_then(|o| self.reg(&o.op_type)),
                                ops.get(2).map(|o| o.op_type.clone()),
                            ) {
                                if let Some(page) = adrp_page.get(&src) {
                                    self.record_data(obj, page.wrapping_add(imm as u64), &mut out);
                                }
                            }
                        }
                        m if m.starts_with("ldr") => {
                            // ldr dst, [base, #off] — base may hold an adrp page.
                            if let Some(arm64::Arm64OperandType::Mem(mem)) =
                                ops.get(1).map(|o| o.op_type.clone())
                            {
                                if let Some(base) = self.cs.reg_name(mem.base()) {
                                    if let Some(page) = adrp_page.get(&base) {
                                        self.record_data(obj, page.wrapping_add(mem.disp() as u64), &mut out);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Arch::Unsupported => {}
            }
        }

        out.strings.sort();
        out.strings.dedup();
        out.imports.sort();
        out.imports.dedup();
        out.calls.sort_unstable();
        out.calls.dedup();
        out
    }

    fn reg(&self, op: &arm64::Arm64OperandType) -> Option<String> {
        match op {
            arm64::Arm64OperandType::Reg(r) => self.cs.reg_name(*r),
            _ => None,
        }
    }

    /// A direct branch target: an import stub, or a local function to link in
    /// the call graph.
    fn record_call(&self, obj: &Object, target: u64, out: &mut Xref) {
        if let Some(name) = obj.names.get(&target) {
            match name.kind {
                NameKind::Import => out.imports.push(name.name.clone()),
                NameKind::LocalFunction => out.calls.push(target),
            }
            return;
        }
        if obj.functions.binary_search(&target).is_ok() {
            out.calls.push(target);
        }
    }

    /// A computed data address: either an import pointer slot (→ import use) or
    /// a C string (→ string use).
    fn record_data(&self, obj: &Object, ea: u64, out: &mut Xref) {
        if let Some(name) = obj.import_at(ea) {
            out.imports.push(name.to_string());
            return;
        }
        if let Some(s) = obj.cstring_at(ea) {
            out.strings.push((ea, s));
        }
    }
}

/// Attributes ELF/PE PLT/IAT thunks to the import they jump through, so a
/// `call <plt stub>` in real code resolves to the library name.
///
/// Mach-O stubs are already named during parsing, so this is only needed for
/// the goblin-backed formats. A thunk is a short run of code ending in an
/// indirect branch that loads exactly one import pointer slot; we map the run's
/// start address to that import name.
pub fn resolve_stub_names(obj: &mut Object) {
    let Ok(dis) = Disassembler::new(obj.arch) else { return };
    let mut discovered: Vec<(u64, String)> = Vec::new();

    for sec in obj.code_sections() {
        // Only bother with sections that look like a procedure-linkage table.
        if !sec.name.contains("plt") && !sec.name.contains("stub") {
            continue;
        }
        let Ok(insns) = dis.cs.disasm_all(&sec.bytes, sec.vaddr) else { continue };
        let mut stub_start = sec.vaddr;
        let mut candidate: Option<String> = None;
        let mut adrp_page: HashMap<String, u64> = HashMap::new();

        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            if let Ok(detail) = dis.cs.insn_detail(insn) {
                let ad = detail.arch_detail();
                if let Some(x) = ad.x86() {
                    for op in x.operands() {
                        if let x86::X86OperandType::Mem(mem) = &op.op_type {
                            if dis.cs.reg_name(mem.base()).as_deref() == Some("rip") {
                                let ea = next.wrapping_add(mem.disp() as u64);
                                if let Some(n) = obj.import_slots.get(&ea) {
                                    candidate = Some(n.clone());
                                }
                            }
                        }
                    }
                } else if let Some(a) = ad.arm64() {
                    let ops: Vec<_> = a.operands().collect();
                    if mnem == "adrp" {
                        if let (Some(dst), Some(arm64::Arm64OperandType::Imm(page))) =
                            (ops.first().and_then(|o| dis.reg(&o.op_type)), ops.get(1).map(|o| o.op_type.clone()))
                        {
                            adrp_page.insert(dst, page as u64);
                        }
                    } else if mnem.starts_with("ldr") {
                        if let Some(arm64::Arm64OperandType::Mem(mem)) = ops.get(1).map(|o| o.op_type.clone()) {
                            if let Some(base) = dis.cs.reg_name(mem.base()) {
                                if let Some(page) = adrp_page.get(&base) {
                                    let ea = page.wrapping_add(mem.disp() as u64);
                                    if let Some(n) = obj.import_slots.get(&ea) {
                                        candidate = Some(n.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // A terminator ends the thunk.
            if matches!(mnem, "jmp" | "br" | "ret" | "bx") || mnem.starts_with("ret") {
                if let Some(name) = candidate.take() {
                    if next.saturating_sub(stub_start) <= 32 {
                        discovered.push((stub_start, name));
                    }
                }
                stub_start = next;
                adrp_page.clear();
            }
        }
    }

    for (addr, name) in discovered {
        obj.names.entry(addr).or_insert(crate::model::NamedAddr { name, kind: NameKind::Import });
    }
}
