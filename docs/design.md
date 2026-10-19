# Design

## Pipeline

```
file ─▶ parse ─▶ disassemble ─▶ cross-reference graph ─▶ match rules ─▶ score ─▶ report
```

1. **Parse** the container (Mach-O/ELF/PE) into a common model. Mach-O is parsed
   by hand so import stubs resolve via the indirect symbol table; ELF/PE use
   goblin.
2. **Disassemble** each function with capstone and record cross-references:
   strings used, imports called, local functions called.
3. **Rules** run in two layers — *capabilities* tag what a function does
   (`network`, `credential-access`, …); *behaviors* combine them into findings,
   within a function or chained across a call edge. Every finding carries the
   strings/imports that triggered it: the evidence trail.
4. **Policy** turns findings into a verdict with a transparent weighted score.

Detection content lives in [`../rules/`](../rules/) (TOML), separate from the
engine, so rules and scoring tune without touching code.

## Reading guide

Read the source in this order; each file builds on the last.

| # | File | What you'll learn |
|---|------|-------------------|
| 1 | `src/model.rs` | The shared data model. Enums, structs, borrowing. |
| 2 | `src/byteutil.rs` | Safe binary parsing. `Result`, slices, `?`. |
| 3 | `src/formats/macho.rs` | Executable layout; finding imports and functions. |
| 4 | `src/disasm.rs` | Bytes → instructions → string/call references. The core. |
| 5 | `src/graph.rs` | Per-function evidence and call edges. |
| 6 | `src/rules.rs` + `rules/*.toml` | Capability/behavior matching. |
| 7 | `src/analysis.rs`, `policy.rs`, `report.rs` | Findings, scoring, rendering. |
| 8 | `src/scan.rs` | How it all composes. |
| 9 | `src/decode.rs`, `diff.rs`, `solve.rs`, `llm.rs` | The extra features. |

## Accuracy

`ariados eval` over ~960 system binaries: ~2.9% false positives at the default
threshold. The flagged ones are mostly system security tools (`codesign`,
`hdiutil`) that genuinely do credential/exec/persistence work.

## Limitations

- No data-flow analysis; chained behaviors use a short call-graph reach.
- Hidden strings: single-byte XOR and stack-constructed only. Multi-byte XOR and
  emulation-recovered strings are future work.
- PE function names stay `sub_<addr>` (stripped); imports still resolve via IAT.
- A triage and learning tool, not a replacement for AV or a sandbox.
