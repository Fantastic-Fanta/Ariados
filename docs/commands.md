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

## explain

Scan a binary, then have an LLM turn the evidence into a plain-language
assessment for a responder. Needs a provider (see `solve`); falls back to the
raw report when none is configured.

```bash
ariados explain ./suspicious
```

## yara-gen

Generate a YARA rule from a sample's most distinctive strings, then **validate**
it: the rule must match the sample and none of a set of known-clean binaries. A
too-generic rule is reported rather than shipped.

```bash
ariados yara-gen ./sample                 # rule to stdout, validation to stderr
ariados yara-gen ./sample --out sample.yar
ariados yara-gen ./sample --clean /usr/bin
```

## supplychain

Scan a directory for text-borne risks the binary scanner can't see: install
scripts that pipe a download into a shell, npm `preinstall`/`postinstall` hooks
that run code, MCP server configs launching remote commands, and prompt
injection / exfiltration phrasing in agent skill and rules files.

```bash
ariados supplychain ./some-project
ariados supplychain ./some-project --json
```

## audit

Audit macOS persistence — LaunchAgents/Daemons, cron and shell profiles —
resolving what each one runs and flagging the odd ones (temp/hidden locations
or fetch-and-run commands are suspicious; unsigned/unresolved programs are
notable). Read-only. Shows flagged items by default; `--all` for everything.

```bash
ariados audit
ariados audit --all
```
