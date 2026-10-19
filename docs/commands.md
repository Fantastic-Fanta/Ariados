# Commands

All commands take a binary or, for `scan`, an `.app` bundle.

## scan

Analyze a binary and report suspicious behavior with evidence trails.

```bash
ariados scan ./suspicious
ariados scan /Applications/Some.app --json
ariados scan ./suspicious --md > report.md
ariados scan ./suspicious --verdict-only
ariados scan ./suspicious --yara ~/yara-rules   # use a directory of YARA rules
ariados scan ./suspicious --no-yara
```

Exit codes: `0` clean, `1` low-risk, `2` suspicious, `3` highly suspicious —
so it fits in scripts and CI.

## strings

List plaintext strings and recover hidden ones (single-byte XOR and
stack-constructed).

```bash
ariados strings ./suspicious
ariados strings ./suspicious --hidden-only
```

## solve

Reverse a crackme: show the check function's annotated disassembly and, if an
LLM is configured, have it work out the input that passes.

```bash
ariados solve ./crackme --no-llm      # just the disassembly
ariados solve ./crackme               # ask the configured LLM
ariados solve ./crackme --show-prompt # print the prompt, send nothing
```

Configure a provider in `~/Ariados/.env` (see [.env.example](../.env.example)):

```bash
LLM_PROVIDER=deepseek      # deepseek | openai | anthropic | ollama
LLM_API_KEY=sk-...         # not needed for ollama (local)
```

## diff

Compare two builds of the same program; new imports, strings and findings in
the second are what an injected payload looks like.

```bash
ariados diff ./Official.app/Contents/MacOS/App ./Downloaded/App
```

## eval

Measure accuracy: false positives against the system's own binaries, and
detection rate against a malware corpus (point that only inside a VM).

```bash
ariados eval
ariados eval --benign /usr/bin --malicious /path/in/vm --flag-at low
```
