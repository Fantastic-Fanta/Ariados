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
    /// Strings built byte by byte on the stack, recovered in the same pass.
    pub stack_strings: Vec<String>,
}

/// Sign-extends the low `bits` of `value` to a full 64-bit two's-complement.
fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Extracts the integer register id from a Reg operand, allocation-free.
fn reg_id(op: &arm64::Arm64OperandType) -> Option<u16> {
    match op {
        arm64::Arm64OperandType::Reg(r) => Some(r.0),
        _ => None,
    }
}

const NO_REG: u16 = u16::MAX;
const REG_TABLE: usize = 768;

pub struct Disassembler {
    cs: Capstone,
    arch: Arch,
    /// Register id of the instruction pointer (x86 RIP), or `NO_REG`.
    rip: u16,
    /// Register ids of the stack/frame pointers, resolved once so the hot loop
    /// compares integers instead of allocating a `String` per operand via
    /// capstone's `reg_name`.
    stack_regs: [u16; 6],
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

        // Resolve the register ids we care about by name, once. capstone's
        // register ids are small and dense, so a short scan covers them.
        let mut rip = NO_REG;
        let mut stack_regs = [NO_REG; 6];
        let mut si = 0;
        for id in 1u16..REG_TABLE as u16 {
            let Some(name) = cs.reg_name(RegId(id)) else {
                continue;
            };
            match name.as_str() {
                "rip" | "eip" => rip = id,
                "rbp" | "rsp" | "ebp" | "esp" | "sp" | "x29" if si < stack_regs.len() => {
                    stack_regs[si] = id;
                    si += 1;
                }
                _ => {}
            }
        }
        Ok(Disassembler {
            cs,
            arch,
            rip,
            stack_regs,
        })
    }

    fn is_stack(&self, id: u16) -> bool {
        id != NO_REG && self.stack_regs.contains(&id)
    }

    /// Disassembles `[start, start+bytes.len())` and extracts references.
    /// `obj` supplies the address→name and address→string maps.
    pub fn xref_range(&self, obj: &Object, start: u64, bytes: &[u8]) -> Xref {
        // arm64 is fixed-width; a hand decoder of the few instruction classes we
        // care about is ~100x faster than capstone and gives identical results.
        if self.arch == Arch::Aarch64 {
            return self.arm64_xref(obj, start, bytes);
        }
        // x86 only (arm64 took the fast path above). x86 is variable-length, so
        // capstone does the decoding; `slots` collects stack-string bytes.
        let mut out = Xref::default();
        let Ok(insns) = self.cs.disasm_all(bytes, start) else {
            return out;
        };
        let mut slots: std::collections::BTreeMap<(u16, i64), u8> =
            std::collections::BTreeMap::new();

        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            let Ok(detail) = self.cs.insn_detail(insn) else {
                continue;
            };
            let arch_detail = detail.arch_detail();
            let Some(x) = arch_detail.x86() else { continue };
            let is_mov = mnem.starts_with("mov");
            let mut stack_mem: Option<(u16, i64, u8)> = None;
            let mut stack_imm: Option<i64> = None;
            for op in x.operands() {
                match &op.op_type {
                    x86::X86OperandType::Imm(target) if mnem == "call" || mnem == "jmp" => {
                        self.record_call(obj, *target as u64, &mut out);
                    }
                    x86::X86OperandType::Imm(v) if is_mov => stack_imm = Some(*v),
                    x86::X86OperandType::Mem(mem) => {
                        let base = mem.base().0;
                        if base == self.rip {
                            let ea = next.wrapping_add(mem.disp() as u64);
                            self.record_data(obj, ea, &mut out);
                        } else if is_mov && self.is_stack(base) {
                            stack_mem = Some((base, mem.disp(), op.size));
                        }
                    }
                    _ => {}
                }
            }
            // Stack string: `mov [rbp/rsp + disp], imm`.
            if let (Some((base, disp, size)), Some(v)) = (stack_mem, stack_imm)
                && (1..=8).contains(&size)
            {
                write_bytes(&mut slots, base, disp, v as u64, size as usize);
            }
        }

        out.strings.sort();
        out.strings.dedup();
        out.imports.sort();
        out.imports.dedup();
        out.calls.sort_unstable();
        out.calls.dedup();
        out.stack_strings = reassemble(&slots, 6);
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
        let mut adrp_page: HashMap<u16, u64> = HashMap::new();
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
                            x86::X86OperandType::Mem(mem) if mem.base().0 == self.rip => {
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
                                o.first().map(|x| &x.op_type)
                            {
                                annotate(obj, *t as u64, &mut note);
                            }
                        }
                        "adrp" => {
                            if let (Some(d), Some(arm64::Arm64OperandType::Imm(p))) = (
                                o.first().and_then(|x| reg_id(&x.op_type)),
                                o.get(1).map(|x| &x.op_type),
                            ) {
                                adrp_page.insert(d, *p as u64);
                            }
                        }
                        "add" => {
                            if let (Some(s), Some(arm64::Arm64OperandType::Imm(i))) = (
                                o.get(1).and_then(|x| reg_id(&x.op_type)),
                                o.get(2).map(|x| &x.op_type),
                            ) && let Some(p) = adrp_page.get(&s)
                            {
                                annotate(obj, p.wrapping_add(*i as u64), &mut note);
                            }
                        }
                        m if m.starts_with("ldr") => {
                            if let Some(arm64::Arm64OperandType::Mem(mem)) =
                                o.get(1).map(|x| x.op_type.clone())
                                && let Some(p) = adrp_page.get(&mem.base().0)
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

    /// Fast arm64 cross-referencing: decode the fixed 4-byte instructions by
    /// hand instead of invoking capstone. Handles exactly the classes that
    /// produce cross-references — `bl`/`b` (calls), `adrp`+`add`/`ldr` (data and
    /// import refs), and `movz`/`movk`+`str` (stack strings) — matching the
    /// capstone path's output.
    fn arm64_xref(&self, obj: &Object, start: u64, bytes: &[u8]) -> Xref {
        let mut out = Xref::default();
        // Per-register state (ids 0..31; 31 = sp/zr depending on instruction).
        let mut page = [0u64; 32]; // adrp page per register
        let mut page_valid = 0u32; // bitmask of which `page[r]` are set
        let mut regval = [0u64; 32]; // last immediate moved into a register
        let mut slots: std::collections::BTreeMap<(u16, i64), u8> =
            std::collections::BTreeMap::new();

        let mut addr = start;
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let w = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);

            if w & 0xFC00_0000 == 0x9400_0000 || w & 0xFC00_0000 == 0x1400_0000 {
                // bl / b imm26
                let off = sign_extend((w & 0x03FF_FFFF) as u64, 26) << 2;
                self.record_call(obj, addr.wrapping_add(off), &mut out);
            } else if w & 0x9F00_0000 == 0x9000_0000 {
                // adrp Rd, imm
                let immlo = ((w >> 29) & 0x3) as u64;
                let immhi = ((w >> 5) & 0x7_FFFF) as u64;
                let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
                let rd = (w & 0x1F) as usize;
                page[rd] = (addr & !0xFFF).wrapping_add(imm);
                page_valid |= 1 << rd;
            } else if w & 0x7F00_0000 == 0x1100_0000 {
                // add Rd, Rn, #imm  (ADD immediate, op=0 S=0)
                let rn = ((w >> 5) & 0x1F) as usize;
                if page_valid & (1 << rn) != 0 {
                    let sh = if (w >> 22) & 1 == 1 { 12 } else { 0 };
                    let imm = (((w >> 10) & 0xFFF) as u64) << sh;
                    self.record_data(obj, page[rn].wrapping_add(imm), &mut out);
                }
            } else if w & 0x3F00_0000 == 0x3900_0000 {
                // load/store, unsigned offset (integer)
                let size = (w >> 30) & 0x3;
                let is_load = (w >> 22) & 0x3 != 0;
                let imm = (((w >> 10) & 0xFFF) as u64) << size;
                let rn = ((w >> 5) & 0x1F) as usize;
                let rt = (w & 0x1F) as usize;
                if is_load {
                    if page_valid & (1 << rn) != 0 {
                        self.record_data(obj, page[rn].wrapping_add(imm), &mut out);
                    }
                } else if rn == 31 || rn == 29 {
                    // store to stack: recover a constant byte run
                    let width = 1usize << size;
                    let val = if rt == 31 { 0 } else { regval[rt] };
                    write_bytes(&mut slots, rn as u16, imm as i64, val, width);
                }
            } else if w & 0x1F80_0000 == 0x1280_0000 {
                // movz / movk (wide immediate)
                let opc = (w >> 29) & 0x3;
                let shift = (((w >> 21) & 0x3) * 16) as u64;
                let imm16 = ((w >> 5) & 0xFFFF) as u64;
                let rd = (w & 0x1F) as usize;
                if opc == 0b10 {
                    regval[rd] = imm16 << shift; // movz
                } else if opc == 0b11 {
                    regval[rd] = (regval[rd] & !(0xFFFFu64 << shift)) | (imm16 << shift); // movk
                }
            }

            addr = addr.wrapping_add(4);
            i += 4;
        }

        out.strings.sort();
        out.strings.dedup();
        out.imports.sort();
        out.imports.dedup();
        out.calls.sort_unstable();
        out.calls.dedup();
        out.stack_strings = reassemble(&slots, 6);
        out
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

/// Writes `width` little-endian bytes of `val` into the slot map at `disp`.
fn write_bytes(
    slots: &mut std::collections::BTreeMap<(u16, i64), u8>,
    base: u16,
    disp: i64,
    val: u64,
    width: usize,
) {
    for i in 0..width.min(8) {
        let byte = (val >> (i * 8)) as u8;
        slots.insert((base, disp + i as i64), byte);
    }
}

/// Walks slot bytes in offset order (per base register), splitting on gaps and
/// NULs, and returns printable runs of at least `min_len`.
fn reassemble(slots: &std::collections::BTreeMap<(u16, i64), u8>, min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur_base: Option<u16> = None;
    let mut prev_off: Option<i64> = None;
    let mut run: Vec<u8> = Vec::new();

    let flush = |run: &mut Vec<u8>, out: &mut Vec<String>| {
        if run.len() >= min_len {
            let text: String = run.iter().map(|&b| b as char).collect();
            if text.chars().filter(|c| c.is_ascii_alphabetic()).count() >= min_len / 2 {
                out.push(text);
            }
        }
        run.clear();
    };

    for (&(base, off), &byte) in slots {
        let contiguous = cur_base == Some(base) && prev_off == Some(off - 1);
        if !contiguous {
            flush(&mut run, &mut out);
        }
        if (0x20..=0x7e).contains(&byte) {
            run.push(byte);
        } else {
            flush(&mut run, &mut out);
        }
        cur_base = Some(base);
        prev_off = Some(off);
    }
    flush(&mut run, &mut out);
    out
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
        let mut adrp_page: HashMap<u16, u64> = HashMap::new();
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
                            if mnem == "lea" && mem.base().0 == dis.rip =>
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
                            ops.first().map(|o| &o.op_type)
                        {
                            candidate = Some(*v as u64);
                        }
                    }
                    "adrp" => {
                        if let (Some(d), Some(arm64::Arm64OperandType::Imm(p))) = (
                            ops.first().and_then(|o| reg_id(&o.op_type)),
                            ops.get(1).map(|o| &o.op_type),
                        ) {
                            adrp_page.insert(d, *p as u64);
                        }
                    }
                    "add" => {
                        if let (Some(s), Some(arm64::Arm64OperandType::Imm(i))) = (
                            ops.get(1).and_then(|o| reg_id(&o.op_type)),
                            ops.get(2).map(|o| &o.op_type),
                        ) && let Some(p) = adrp_page.get(&s)
                        {
                            candidate = Some(p.wrapping_add(*i as u64));
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
        let mut adrp_page: HashMap<u16, u64> = HashMap::new();

        for insn in insns.iter() {
            let mnem = insn.mnemonic().unwrap_or("");
            let next = insn.address().wrapping_add(insn.len() as u64);
            if let Ok(detail) = dis.cs.insn_detail(insn) {
                let ad = detail.arch_detail();
                if let Some(x) = ad.x86() {
                    for op in x.operands() {
                        if let x86::X86OperandType::Mem(mem) = &op.op_type
                            && mem.base().0 == dis.rip
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
                            ops.first().and_then(|o| reg_id(&o.op_type)),
                            ops.get(1).map(|o| &o.op_type),
                        ) {
                            adrp_page.insert(dst, *page as u64);
                        }
                    } else if mnem.starts_with("ldr")
                        && let Some(arm64::Arm64OperandType::Mem(mem)) =
                            ops.get(1).map(|o| o.op_type.clone())
                        && let Some(page) = adrp_page.get(&mem.base().0)
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
