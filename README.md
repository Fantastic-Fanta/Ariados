# Ariados

[![CI](https://github.com/Fantastic-Fanta/Ariados/actions/workflows/ci.yml/badge.svg)](https://github.com/Fantastic-Fanta/Ariados/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static triage for Mach-O, ELF and PE executables. Ariados reports what a binary
*does* that looks dangerous and shows the exact code, strings and library calls
behind every finding — evidence you can verify, not an opaque verdict. It reads
files; it never runs them.

```
● HIGH   Collects stored credentials and reaches network-sending code  (arm64)
  fn steal_credentials @ 0x100003c84
  ├─ string  "Library/Application Support/Google/Chrome/Default/Login Data"
  ├─ string  "Library/Keychains/login.keychain-db"
  ├─ calls   exfiltrate  ↓
  fn exfiltrate @ 0x100003c28
  └─ string  "http://185.199.111.1/collect"
```

## Features

- **Evidence trails** — every finding cites the functions, strings and imports that triggered it.
- **Mach-O, ELF and PE** — fat binaries and `.app` bundles; a hand-written Mach-O parser and a custom arm64 decoder.
- **Hidden strings** — single-byte XOR and stack-constructed string recovery; high-entropy packing detection.
- **YARA** — run signatures via the pure-Rust `yara-x`, or generate and validate your own.
- **Signing-aware** — notarized apps aren't flagged on behavior alone; unsigned downloads get full scrutiny.
- **Beyond binaries** — `supplychain` (install scripts, npm/MCP/agent configs) and `audit` (macOS persistence).

## Install

```bash
cargo install --git https://github.com/Fantastic-Fanta/Ariados
```

Requires a Rust toolchain and a C compiler (for capstone). Prebuilt macOS
(arm64) binaries are on the [releases page](https://github.com/Fantastic-Fanta/Ariados/releases/latest).

## Usage

```bash
ariados scan ./suspicious              # triage a binary
ariados scan ./suspicious --yara ~/rules
ariados explain ./suspicious           # LLM-written assessment
ariados yara-gen ./sample              # generate and validate a YARA rule
ariados diff ./official ./downloaded   # tampering check
ariados supplychain ./project          # supply-chain / agent-config risks
ariados audit                          # macOS persistence & trust
```

See [docs/commands.md](docs/commands.md) for all commands and
[docs/design.md](docs/design.md) for how it works.

## Status

A triage and research tool, not a replacement for a sandbox or endpoint
protection. Detection has been measured against controlled fixtures and the
system's own binaries; it has not yet been validated against a live malware
corpus. Handle untrusted samples in a VM.

## License

MIT — see [LICENSE](LICENSE).
