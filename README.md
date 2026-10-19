# Ariados

A static binary triage tool. Point it at a Mach-O, ELF or PE executable (or a
`.app` bundle) and it tells you what the program *does* that looks dangerous —
and shows you the exact code, strings and library calls that prove it.

It is written in Rust, built to be read. If you're learning reverse engineering
and Rust at the same time, the ["Reading guide"](#reading-guide-learn-the-code)
below walks the source in a sensible order.

> Ariados does **static** analysis only: it never runs the file it examines.
> Even so, keep real malware samples inside a VM, password-zipped, the way
> [MalwareBazaar](https://bazaar.abuse.ch/) distributes them.

## The idea: evidence trails

Commercial antivirus gives you an opaque label like `Trojan.Generic.48213`.
Ariados instead shows the chain of code behind every finding, so you can jump
straight to those addresses in a disassembler and see for yourself:

```
● HIGH   Collects stored credentials and reaches network-sending code  (arm64)
  fn steal_credentials @ 0x100003c84
  ├─ string  "Library/Application Support/Google/Chrome/Default/Login Data"
  ├─ string  "Library/Keychains/login.keychain-db"
  ├─ calls   exfiltrate  ↓
  fn exfiltrate @ 0x100003c28
  └─ string  "http://185.199.111.1/collect"
```

## Commands

```bash
# Analyze a binary or .app bundle (text report, JSON, or just the verdict)
ariados scan ./suspicious
ariados scan /Applications/Some.app --json
ariados scan ./suspicious --verdict-only

# List plaintext strings and recover single-byte-XOR hidden strings
ariados strings ./suspicious
ariados strings ./suspicious --hidden-only

# Compare two builds of the same program (tampering check)
ariados diff ./Official.app/Contents/MacOS/App ./Downloaded/App

# Reverse a crackme: show the check function, and (opt-in) have an LLM solve it
ariados solve ./crackme --no-llm        # just the annotated disassembly
ariados solve ./crackme                 # ask the configured LLM

# Measure accuracy against your own system binaries (false positives) and,
# inside a VM, a malware corpus (detection rate)
ariados eval
ariados eval --benign /usr/bin --malicious /path/in/vm --flag-at low
```

`scan` exits `0` clean, `1` low-risk, `2` suspicious, `3` highly suspicious, so
it drops into scripts and CI.

## How it works

The pipeline is one direction, format-neutral after the first stage:

```
file ─▶ parse ─▶ disassemble ─▶ cross-reference graph ─▶ match rules ─▶ score ─▶ report
        (per format) (capstone)   (strings/imports/calls)  (capabilities   (policy)
                                                            + behaviors)
```

1. **Parse** the container into a common model (`Object`: arch, sections,
   functions, address→name map). Mach-O is parsed by hand so import stubs
   resolve via the indirect symbol table; ELF/PE use goblin.
2. **Disassemble** each function with capstone and extract cross-references:
   which strings it uses, which imports it calls, which local functions it calls.
3. **Rules** run in two layers: *capabilities* tag what a function does
   (`network`, `credential-access`, …); *behaviors* combine capabilities into
   findings, within a function or chained across a call edge. Every finding
   carries the strings/imports that triggered it — the evidence trail.
4. **Policy** turns findings into a verdict with a transparent weighted score.

Detection content lives in [`rules/`](rules/) (TOML), separate from the engine,
so you tune rules and scoring without touching code.

## Reading guide (learn the code)

Read the modules in this order; each builds on the last.

| # | File | What you'll learn |
|---|------|-------------------|
| 1 | [`src/model.rs`](src/model.rs) | The core data model everything shares. Rust enums, structs, borrowing. |
| 2 | [`src/byteutil.rs`](src/byteutil.rs) | Safe binary parsing with bounds checks. `Result`, slices, `?`. |
| 3 | [`src/formats/macho.rs`](src/formats/macho.rs) | How an executable is laid out, and how imports/functions are found. The meatiest parser. |
| 4 | [`src/disasm.rs`](src/disasm.rs) | Turning bytes into instructions and recovering string/call references. The heart of the tool. |
| 5 | [`src/graph.rs`](src/graph.rs) | Assembling per-function evidence and call edges. |
| 6 | [`src/rules.rs`](src/rules.rs) + [`rules/*.toml`](rules/) | Capability/behavior matching — where detections are expressed. |
| 7 | [`src/analysis.rs`](src/analysis.rs), [`src/policy.rs`](src/policy.rs), [`src/report.rs`](src/report.rs) | Findings, scoring and rendering. |
| 8 | [`src/scan.rs`](src/scan.rs) | How it all composes into one scan. |
| 9 | [`src/decode.rs`](src/decode.rs), [`src/diff.rs`](src/diff.rs), [`src/solve.rs`](src/solve.rs), [`src/llm.rs`](src/llm.rs) | The extra features, each self-contained. |

To learn reverse engineering alongside, compile a tiny C program, look at it
with `ariados solve ./a.out --no-llm`, and compare to [Compiler
Explorer](https://godbolt.org) and a real disassembler. Then try the
[crackmes.one](https://crackmes.one) challenges (do it in a VM).

## Setting up `solve`'s LLM

`solve` sends disassembly to an LLM only if you configure one. Nothing is sent
otherwise. Put keys in `~/Ariados/.env` (gitignored) or your shell:

```bash
LLM_PROVIDER=deepseek          # deepseek | openai | anthropic | ollama
LLM_API_KEY=sk-...             # not needed for ollama (local)
# LLM_MODEL=deepseek-chat      # optional override
```

See [`.env.example`](.env.example).

## Accuracy

Measured with `ariados eval` over this machine's ~960 system binaries:
**~2.9% false positives** at the default (`suspicious`) threshold. The files it
does flag are mostly system security tools (`codesign`, `hdiutil`, `launchctl`)
that genuinely do credential/exec/persistence work — expected on a system
binary, suspicious in a random download. Re-run `eval` after any rule change to
see the effect.

## Limitations (and honest future work)

- **No data-flow analysis.** Chained behaviors use a short call-graph reach, not
  taint tracking, so they're a heuristic.
- **Hidden strings**: single-byte XOR only. Stack-constructed strings need an
  emulator (à la Mandiant FLOSS) — not yet implemented.
- **PE** is the weakest format: Windows binaries are stripped, so functions are
  recovered by a code sweep rather than a symbol table. Imports now resolve
  through the IAT, so call-based findings work, but function *names* stay
  `sub_<addr>`.
- Not a replacement for a real AV or sandbox; it's a triage and learning tool.

## Testing

```bash
cargo test            # unit + integration tests over tests/fixtures/
cargo clippy          # clean
```

The fixtures in [`tests/fixtures/src/`](tests/fixtures/src/) are harmless
programs that only *look* malicious to the analyzer; they're compiled to
Mach-O, ELF and PE with `cc` and `zig cc`.

## License

MIT.
