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

```bash
cargo build --release
./target/release/ariados scan ./suspicious
```

## Documentation

- [Commands](docs/commands.md)
- [Design](docs/design.md)

## License

MIT — see [LICENSE](LICENSE).
