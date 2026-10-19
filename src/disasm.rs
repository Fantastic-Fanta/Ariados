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
use capstone::arch::{BuildsCapstone, arm64, x86};
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
            Arch::X86_64 => Capstone::new()
                .x86()
                .mode(x86::ArchMode::Mode64)
                .detail(true)
                .build(),
            Arch::X86 => Capstone::new()
                .x86()
                .mode(x86::ArchMode::Mode32)
                .detail(true)
                .build(),
            Arch::Aarch64 => Capstone::new()
                .arm64()
                .mode(arm64::ArchMode::Arm)
                .detail(true)
                .build(),
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
            let Ok(detail) = self.cs.insn_detail(insn) else {
                continue;
            };
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
                    let Some(a) = arch_detail.arm64() else {
                        continue;
                    };
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
                            ) && let Some(page) = adrp_page.get(&src)
                            {
                                self.record_data(obj, page.wrapping_add(imm as u64), &mut out);
                            }
                        }
                        m if m.starts_with("ldr") => {
                            // ldr dst, [base, #off] — base may hold an adrp page.
                            if let Some(arm64::Arm64OperandType::Mem(mem)) =
                                ops.get(1).map(|o| o.op_type.clone())
                                && let Some(base) = self.cs.reg_name(mem.base())
                                && let Some(page) = adrp_page.get(&base)
                            {
                                self.record_data(
                                    obj,
                                    page.wrapping_add(mem.disp() as u64),
                                    &mut out,
                                );
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

    /// Produces an annotated disassembly listing for a function: each line is
    /// `addr: mnemonic operands`, with resolved import names and referenced
    /// strings appended as comments. This is what `solve` shows and what it
    /// sends to the LLM, so the reasoning works on named calls and visible
    /// strings rather than raw addresses.
    pub fn listing(&self, obj: &Object, start: u64, bytes: &[u8]) -> String {
        let mut out = String::new();
        let Ok(insns) = self.cs.disasm_all(bytes, start) else {
            return out;
        };
        let mut adrp_page: HashMap<String, u64> = HashMap::new();
        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let ops = insn.op_str().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            let mut note = String::new();

            if let Ok(detail) = self.cs.insn_detail(insn) {
                let ad = detail.arch_detail();
                if let Some(x) = ad.x86() {
                    for op in x.operands() {
                        match &op.op_type {
                            x86::X86OperandType::Imm(t) if mnem == "call" || mnem == "jmp" => {
                                annotate(obj, *t as u64, &mut note);
                            }
                            x86::X86OperandType::Mem(mem)
                                if self.cs.reg_name(mem.base()).as_deref() == Some("rip") =>
                            {
                                annotate(obj, next.wrapping_add(mem.disp() as u64), &mut note);
                            }
                            _ => {}
                        }
                    }
                } else if let Some(a) = ad.arm64() {
                    let o: Vec<_> = a.operands().collect();
                    match mnem {
                        "bl" | "b" => {
                            if let Some(arm64::Arm64OperandType::Imm(t)) =
                                o.first().map(|x| x.op_type.clone())
                            {
                                annotate(obj, t as u64, &mut note);
                            }
                        }
                        "adrp" => {
                            if let (Some(d), Some(arm64::Arm64OperandType::Imm(p))) = (
                                o.first().and_then(|x| self.reg(&x.op_type)),
                                o.get(1).map(|x| x.op_type.clone()),
                            ) {
                                adrp_page.insert(d, p as u64);
                            }
                        }
                        "add" => {
                            if let (Some(s), Some(arm64::Arm64OperandType::Imm(i))) = (
                                o.get(1).and_then(|x| self.reg(&x.op_type)),
                                o.get(2).map(|x| x.op_type.clone()),
                            ) && let Some(p) = adrp_page.get(&s)
                            {
                                annotate(obj, p.wrapping_add(i as u64), &mut note);
                            }
                        }
                        m if m.starts_with("ldr") => {
                            if let Some(arm64::Arm64OperandType::Mem(mem)) =
                                o.get(1).map(|x| x.op_type.clone())
                                && let Some(base) = self.cs.reg_name(mem.base())
                                && let Some(p) = adrp_page.get(&base)
                            {
                                annotate(obj, p.wrapping_add(mem.disp() as u64), &mut note);
                            }
                        }
                        _ => {}
                    }
                }
            }
            out.push_str(&format!(
                "{:#010x}: {:<7} {}{}\n",
                insn.address(),
                mnem,
                ops,
                note
            ));
        }
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

/// Appends a `; -> name` or `; "string"` comment for an address a disassembly
/// line references, if it resolves to an import, local function or string.
fn annotate(obj: &Object, ea: u64, note: &mut String) {
    if let Some(name) = obj.import_at(ea) {
        note.push_str(&format!("  ; -> {name}"));
        return;
    }
    if let Some(n) = obj.names.get(&ea) {
        note.push_str(&format!("  ; -> {}", n.name));
        return;
    }
    if let Some(s) = obj.cstring_at(ea) {
        let shown: String = s.chars().take(60).collect();
        note.push_str(&format!("  ; {shown:?}"));
    }
}

/// Recursive-descent function discovery: starting from known entry points,
/// follows direct `call`/`bl` targets to find functions that a stripped binary
/// has no symbols for. Essential for PE (usually symbol-free) and helpful for
/// any stripped Mach-O/ELF. Returns the expanded, sorted function-start list.
pub fn discover_functions(obj: &Object) -> Vec<u64> {
    let Ok(dis) = Disassembler::new(obj.arch) else {
        return obj.functions.clone();
    };
    let mut known: std::collections::BTreeSet<u64> = obj.functions.iter().copied().collect();
    if obj.entry != 0 {
        known.insert(obj.entry);
    }

    // Linearly sweep every code section, collecting anything that looks like a
    // function start: a direct `call`/`bl` target, or a computed code pointer
    // (`lea`/`adrp+add`), which catches callbacks and `main` that are only ever
    // referenced by address, never called directly.
    for sec in obj.code_sections() {
        let Ok(insns) = dis.cs.disasm_all(&sec.bytes, sec.vaddr) else {
            continue;
        };
        let mut adrp_page: HashMap<String, u64> = HashMap::new();
        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            let Ok(detail) = dis.cs.insn_detail(insn) else {
                continue;
            };
            let ad = detail.arch_detail();

            let mut candidate: Option<u64> = None;
            if let Some(x) = ad.x86() {
                for op in x.operands() {
                    match &op.op_type {
                        x86::X86OperandType::Imm(v) if mnem == "call" => {
                            candidate = Some(*v as u64)
                        }
                        x86::X86OperandType::Mem(mem)
                            if mnem == "lea"
                                && dis.cs.reg_name(mem.base()).as_deref() == Some("rip") =>
                        {
                            candidate = Some(next.wrapping_add(mem.disp() as u64));
                        }
                        _ => {}
                    }
                }
            } else if let Some(a) = ad.arm64() {
                let ops: Vec<_> = a.operands().collect();
                match mnem {
                    "bl" => {
                        if let Some(arm64::Arm64OperandType::Imm(v)) =
                            ops.first().map(|o| o.op_type.clone())
                        {
                            candidate = Some(v as u64);
                        }
                    }
                    "adrp" => {
                        if let (Some(d), Some(arm64::Arm64OperandType::Imm(p))) = (
                            ops.first().and_then(|o| dis.reg(&o.op_type)),
                            ops.get(1).map(|o| o.op_type.clone()),
                        ) {
                            adrp_page.insert(d, p as u64);
                        }
                    }
                    "add" => {
                        if let (Some(s), Some(arm64::Arm64OperandType::Imm(i))) = (
                            ops.get(1).and_then(|o| dis.reg(&o.op_type)),
                            ops.get(2).map(|o| o.op_type.clone()),
                        ) && let Some(p) = adrp_page.get(&s)
                        {
                            candidate = Some(p.wrapping_add(i as u64));
                        }
                    }
                    _ => {}
                }
            }

            if let Some(t) = candidate {
                // Only addresses inside a code section, not already an import stub.
                if obj.names.get(&t).map(|n| n.kind) != Some(NameKind::Import)
                    && obj.section_at(t).map(|s| s.kind) == Some(crate::model::SectionKind::Code)
                {
                    known.insert(t);
                }
            }
        }
    }

    let mut out: Vec<u64> = known.into_iter().collect();
    out.sort_unstable();
    out
}

/// Attributes ELF/PE PLT/IAT thunks to the import they jump through, so a
/// `call <plt stub>` in real code resolves to the library name.
///
/// Mach-O stubs are already named during parsing, so this is only needed for
/// the goblin-backed formats. A thunk is a short run of code ending in an
/// indirect branch that loads exactly one import pointer slot; we map the run's
/// start address to that import name.
pub fn resolve_stub_names(obj: &mut Object) {
    let Ok(dis) = Disassembler::new(obj.arch) else {
        return;
    };
    let mut discovered: Vec<(u64, String)> = Vec::new();

    for sec in obj.code_sections() {
        // Only bother with sections that look like a procedure-linkage table.
        if !sec.name.contains("plt") && !sec.name.contains("stub") {
            continue;
        }
        let Ok(insns) = dis.cs.disasm_all(&sec.bytes, sec.vaddr) else {
            continue;
        };
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
                        if let x86::X86OperandType::Mem(mem) = &op.op_type
                            && dis.cs.reg_name(mem.base()).as_deref() == Some("rip")
                        {
                            let ea = next.wrapping_add(mem.disp() as u64);
                            if let Some(n) = obj.import_slots.get(&ea) {
                                candidate = Some(n.clone());
                            }
                        }
                    }
                } else if let Some(a) = ad.arm64() {
                    let ops: Vec<_> = a.operands().collect();
                    if mnem == "adrp" {
                        if let (Some(dst), Some(arm64::Arm64OperandType::Imm(page))) = (
                            ops.first().and_then(|o| dis.reg(&o.op_type)),
                            ops.get(1).map(|o| o.op_type.clone()),
                        ) {
                            adrp_page.insert(dst, page as u64);
                        }
                    } else if mnem.starts_with("ldr")
                        && let Some(arm64::Arm64OperandType::Mem(mem)) =
                            ops.get(1).map(|o| o.op_type.clone())
                        && let Some(base) = dis.cs.reg_name(mem.base())
                        && let Some(page) = adrp_page.get(&base)
                    {
                        let ea = page.wrapping_add(mem.disp() as u64);
                        if let Some(n) = obj.import_slots.get(&ea) {
                            candidate = Some(n.clone());
                        }
                    }
                }
            }
            // A terminator ends the thunk.
            if matches!(mnem, "jmp" | "br" | "ret" | "bx") || mnem.starts_with("ret") {
                if let Some(name) = candidate.take()
                    && next.saturating_sub(stub_start) <= 32
                {
                    discovered.push((stub_start, name));
                }
                stub_start = next;
                adrp_page.clear();
            }
        }
    }

    for (addr, name) in discovered {
        obj.names.entry(addr).or_insert(crate::model::NamedAddr {
            name,
            kind: NameKind::Import,
        });
    }
}
