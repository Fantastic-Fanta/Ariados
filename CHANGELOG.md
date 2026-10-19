# Changelog

## 0.1.0

First release. A static binary triage tool for Mach-O, ELF and PE.

### Features
- **Evidence trails** — every finding shows the exact functions, strings and
  library calls that prove it, not an opaque label.
- **Formats** — Mach-O (hand-written parser with import-stub resolution), ELF
  and PE (via goblin), including fat binaries and `.app` bundles.
- **Analysis** — a custom arm64 decoder plus capstone for x86; a cross-reference
  graph of strings, imports and call edges; capability + behavior rules (TOML).
- **Hidden strings** — single-byte XOR (fast delta search) and stack-constructed
  string recovery.
- **Packing detection** — high-entropy executable sections.
- **YARA** — run signatures over the raw bytes via pure-Rust `yara-x`;
  `--yara <dir>` for community rule sets.
- **Signing-aware verdict** — Developer ID / notarized apps aren't flagged on
  behavioral findings alone; unsigned downloads get full scrutiny.
- **Commands** — `scan` (text / `--json` / `--md`), `strings`, `diff`, `solve`
  (opt-in LLM for crackmes), `eval` (measure accuracy).
- **Fast** — parallel across files and functions; ~2.9% false positives on 959
  system binaries, 100% detection on a harmless technique corpus.

### Known limitations
- PE function names stay `sub_<addr>` (stripped binaries).
- No data-flow analysis; chained behaviors use a short call-graph reach.
- Prebuilt binary is macOS arm64 only; build from source for other targets.
