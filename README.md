# Ariados

A static binary triage tool. Point it at a Mach-O, ELF or PE executable (or a
`.app` bundle) and it reports what the program *does* that looks dangerous —
and shows the exact code, strings and library calls that prove it.

```
● HIGH   Collects stored credentials and reaches network-sending code  (arm64)
  fn steal_credentials @ 0x100003c84
  ├─ string  "Library/Application Support/Google/Chrome/Default/Login Data"
  ├─ string  "Library/Keychains/login.keychain-db"
  ├─ calls   exfiltrate  ↓
  fn exfiltrate @ 0x100003c28
  └─ string  "http://185.199.111.1/collect"
```

It only reads files, never runs them. Still, keep real malware in a VM.

## Install

Build from source (needs a Rust toolchain and a C compiler for capstone):

```bash
cargo install --git https://github.com/Fantastic-Fanta/Ariados
```

Or grab the prebuilt macOS (arm64) binary from the
[latest release](https://github.com/Fantastic-Fanta/Ariados/releases/latest),
or clone and `cargo build --release`.

```bash
ariados scan ./suspicious
ariados scan ./suspicious --yara ~/yara-rules
```

## Documentation

- [Commands](docs/commands.md)
- [Design](docs/design.md)

## License

MIT — see [LICENSE](LICENSE).
