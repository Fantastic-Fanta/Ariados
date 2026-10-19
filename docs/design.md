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

Alongside the behavioral engine, Ariados runs **YARA** rules (via the pure-Rust
`yara-x`) over the raw file bytes; a match becomes a finding, with severity and
description from the rule's `meta`. A small set ships in `rules/yara/`; point it
at community rule sets with `--yara <dir>`.

Detection content lives in [`../rules/`](../rules/) (TOML), separate from the
engine, so rules and scoring tune without touching code.

## Beyond binary scanning

The same evidence-first idea extends past executables: `audit` checks macOS
persistence (LaunchAgents/Daemons, cron, shell profiles) for unsigned or
fetch-and-run items; `supplychain` scans a directory for install-script
droppers, npm lifecycle hooks, MCP server configs running remote commands, and
prompt injection in agent/skill files; `yara-gen` builds a YARA rule from a
sample and validates it against clean files; `explain` turns the findings into a
plain-language analyst assessment via an LLM.

## Accuracy

`ariados eval` over ~960 system binaries: ~2.9% false positives at the default
threshold. The flagged ones are mostly system security tools (`codesign`,
`hdiutil`) that genuinely do credential/exec/persistence work.

Large GUI apps legitimately network, use the keychain and install launch
agents, so the verdict is **signing-aware**: a binary signed by a verified Apple
developer (Developer ID / Apple authority, or Gatekeeper-accepted) is capped at
low-risk for behavioral findings, while packing or hidden strings still flag it.
Unsigned and ad-hoc binaries — the untrusted downloads this tool is really for —
get full scrutiny. Across a real `/Applications` (93 apps), this takes the
flag count from ~37 to a handful, all unsigned apps.

## Limitations

- No data-flow analysis; chained behaviors use a short call-graph reach.
- Static only. Strings obfuscated at runtime (custom decoder loops, runtime-
  derived keys) need an emulator (Unicorn-grade) to recover; that dynamic
  deobfuscation pass is the main planned frontier. Compile-time-folded and
  single-byte/stack obfuscation are already recovered statically.
- Hidden strings: single-byte XOR and stack-constructed only. Multi-byte XOR and
  emulation-recovered strings are future work.
- PE function names stay `sub_<addr>` (stripped); imports still resolve via IAT.
- A triage and learning tool, not a replacement for AV or a sandbox.
