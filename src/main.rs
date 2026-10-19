//! Ariados command-line interface.

use ariados::report;
use ariados::scan::{Engine, collect_targets};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "ariados",
    version,
    about = "Static binary triage with evidence trails"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a binary or .app bundle and report suspicious behavior.
    Scan {
        /// File or bundle to scan.
        path: PathBuf,
        /// Emit JSON instead of text.
        #[arg(long)]
        json: bool,
        /// Emit a Markdown report instead of text.
        #[arg(long)]
        md: bool,
        /// Print only the verdict line.
        #[arg(long)]
        verdict_only: bool,
        /// Directory of YARA rules (.yar/.yara) to use instead of the bundled set.
        #[arg(long)]
        yara: Option<PathBuf>,
        /// Disable YARA scanning.
        #[arg(long)]
        no_yara: bool,
    },
    /// Audit macOS persistence (LaunchAgents/Daemons, cron, shell profiles) for
    /// unsigned or dropper-like items. Read-only.
    Audit {
        /// Show every item, including signed ones that look fine.
        #[arg(long)]
        all: bool,
    },
    /// List plaintext strings and XOR-decoded hidden strings in a binary.
    Strings {
        /// File to inspect.
        path: PathBuf,
        /// Minimum string length.
        #[arg(long, default_value_t = 6)]
        min: usize,
        /// Only show XOR-decoded (hidden) strings.
        #[arg(long)]
        hidden_only: bool,
    },
    /// Reverse a crackme: find the check function and (opt-in) ask an LLM for
    /// the input that passes it. Configure a provider via LLM_PROVIDER/LLM_API_KEY.
    Solve {
        /// The crackme binary.
        path: PathBuf,
        /// Don't call any LLM; just show the candidate disassembly.
        #[arg(long)]
        no_llm: bool,
        /// Print the prompt that would be sent, without calling anything.
        #[arg(long)]
        show_prompt: bool,
    },
    /// Compare two binaries and show behavioral differences (tampering check).
    Diff {
        /// Reference binary (e.g. the official copy).
        a: PathBuf,
        /// Binary to compare against it (e.g. a downloaded copy).
        b: PathBuf,
    },
    /// Measure accuracy against benign (and optionally malicious) corpora.
    Eval {
        /// Benign directories (default: system binary dirs). Flagging any of
        /// these is a false positive.
        #[arg(long = "benign", num_args = 1..)]
        benign: Vec<PathBuf>,
        /// Malicious directories — only ever point these inside a VM.
        #[arg(long = "malicious", num_args = 1..)]
        malicious: Vec<PathBuf>,
        /// Verdict level at which a file counts as flagged.
        #[arg(long, default_value = "suspicious")]
        flag_at: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            json,
            md,
            verdict_only,
            yara,
            no_yara,
        } => cmd_scan(&path, json, md, verdict_only, yara, no_yara),
        Command::Audit { all } => cmd_audit(all),
        Command::Strings {
            path,
            min,
            hidden_only,
        } => cmd_strings(&path, min, hidden_only),
        Command::Solve {
            path,
            no_llm,
            show_prompt,
        } => cmd_solve(&path, no_llm, show_prompt),
        Command::Diff { a, b } => cmd_diff(&a, &b),
        Command::Eval {
            benign,
            malicious,
            flag_at,
        } => cmd_eval(&benign, &malicious, &flag_at),
    }
}

fn cmd_solve(path: &std::path::Path, no_llm: bool, show_prompt: bool) -> ExitCode {
    // Load ~/Ariados/.env and ./.env so keys can live in a gitignored file.
    if let Some(home) = std::env::var_os("HOME") {
        ariados::llm::load_dotenv(&std::path::Path::new(&home).join("Ariados/.env"));
    }
    ariados::llm::load_dotenv(std::path::Path::new(".env"));

    let opts = ariados::solve::Options {
        no_llm,
        show_prompt,
    };
    match ariados::solve::solve(path, &opts) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("solve error: {e}");
            ExitCode::from(4)
        }
    }
}

fn cmd_diff(a: &std::path::Path, b: &std::path::Path) -> ExitCode {
    let engine = Engine::builtin();
    match ariados::diff::diff(&engine, a, b) {
        Ok(gained) => ExitCode::from(if gained { 1 } else { 0 }),
        Err(e) => {
            eprintln!("diff error: {e}");
            ExitCode::from(4)
        }
    }
}

fn cmd_strings(path: &std::path::Path, min: usize, hidden_only: bool) -> ExitCode {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return ExitCode::from(2);
        }
    };
    let program = match ariados::formats::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::from(1);
        }
    };
    if !hidden_only {
        println!("# plaintext strings");
        for s in ariados::strings::extract(&data, min) {
            println!("{:#010x}  {}", s.offset, s.text);
        }
    }
    println!("\n# hidden (single-byte XOR) strings");
    let mut seen = std::collections::BTreeSet::new();
    for obj in &program.objects {
        for h in ariados::decode::xor_strings(obj, min) {
            if seen.insert((h.key, h.text.clone())) {
                let mark = ariados::decode::notable(&h.text)
                    .map(|l| format!("  <-- {l}"))
                    .unwrap_or_default();
                println!(
                    "[{}+{:#x} XOR {:#04x}]  {}{mark}",
                    h.section, h.offset, h.key, h.text
                );
            }
        }
    }

    println!("\n# hidden (stack-constructed) strings");
    let mut seen2 = std::collections::BTreeSet::new();
    for obj in &program.objects {
        let g = ariados::graph::build(obj);
        for f in g.functions.values() {
            for s in &f.stack_strings {
                if seen2.insert(s.clone()) {
                    let mark = ariados::decode::notable(s)
                        .map(|l| format!("  <-- {l}"))
                        .unwrap_or_default();
                    println!("[{:#x}]  {s}{mark}", f.addr);
                }
            }
        }
    }
    ExitCode::SUCCESS
}

fn cmd_eval(benign: &[PathBuf], malicious: &[PathBuf], flag_at: &str) -> ExitCode {
    use ariados::analysis::VerdictLevel;
    let level = match flag_at.to_ascii_lowercase().as_str() {
        "low" | "lowrisk" | "low_risk" => VerdictLevel::LowRisk,
        "high" | "highly" | "highly_suspicious" => VerdictLevel::HighlySuspicious,
        _ => VerdictLevel::Suspicious,
    };

    // Default benign corpus: the usual system binary locations.
    let default_benign = ["/bin", "/usr/bin", "/usr/sbin", "/sbin"];
    let benign_paths: Vec<PathBuf> = if benign.is_empty() {
        default_benign.iter().map(PathBuf::from).collect()
    } else {
        benign.to_vec()
    };
    let benign_refs: Vec<&std::path::Path> = benign_paths.iter().map(|p| p.as_path()).collect();
    let malicious_refs: Vec<&std::path::Path> = malicious.iter().map(|p| p.as_path()).collect();

    // Benign corpus is large: skip codesign subprocesses and the XOR sweep so
    // the run stays fast. Malicious corpus is small: run the full pipeline so
    // obfuscation-based detections count.
    let mut benign_engine = Engine::builtin();
    benign_engine.enrich_signing = false;
    benign_engine.decode_hidden = false;
    let mut mal_engine = Engine::builtin();
    mal_engine.enrich_signing = false; // detection, not signing, is what we measure
    ariados::eval::report(
        &benign_engine,
        &mal_engine,
        &benign_refs,
        &malicious_refs,
        level,
    );
    ExitCode::SUCCESS
}

fn cmd_audit(all: bool) -> ExitCode {
    use ariados::audit::Level;
    let items = ariados::audit::audit();
    let suspicious = items
        .iter()
        .filter(|i| i.level >= Level::Suspicious)
        .count();
    let flagged = items.iter().filter(|i| i.level >= Level::Notable).count();
    println!("ariados audit — macOS persistence & trust\n");
    if items.is_empty() {
        println!("No persistence items found.");
        return ExitCode::SUCCESS;
    }
    let shown: Vec<_> = items
        .iter()
        .filter(|i| all || i.level >= Level::Notable)
        .collect();
    for i in shown {
        let dot = match i.level {
            Level::Suspicious => "●",
            Level::Notable => "◆",
            Level::Ok => "○",
        };
        let lvl = match i.level {
            Level::Suspicious => "SUSPICIOUS",
            Level::Notable => "notable",
            Level::Ok => "ok",
        };
        println!("{dot} {lvl:<11} {}  ({})", i.label, i.kind);
        println!("   {}", i.detail);
        println!("   {}", i.source.display());
        for r in &i.reasons {
            println!("   - {r}");
        }
        println!();
    }
    println!(
        "{} persistence item(s): {suspicious} suspicious, {} notable, {} ok.",
        items.len(),
        flagged - suspicious,
        items.len() - flagged
    );
    if !all && flagged < items.len() {
        println!("(signed/ok items hidden; pass --all to see them)");
    }
    ExitCode::from(if suspicious > 0 {
        2
    } else if flagged > 0 {
        1
    } else {
        0
    })
}

fn cmd_scan(
    path: &std::path::Path,
    json: bool,
    md: bool,
    verdict_only: bool,
    yara: Option<PathBuf>,
    no_yara: bool,
) -> ExitCode {
    let mut engine = Engine::builtin();
    if no_yara {
        engine.set_yara(None);
    } else if let Some(dir) = &yara {
        match ariados::yara::YaraEngine::from_dir(dir) {
            Some(y) => engine.set_yara(Some(y)),
            None => {
                eprintln!("no usable YARA rules in {}", dir.display());
                return ExitCode::from(2);
            }
        }
    }
    let targets = collect_targets(path);
    if targets.is_empty() {
        eprintln!("no executable files found at {}", path.display());
        return ExitCode::from(2);
    }

    // Scan targets in parallel (order preserved by rayon's indexed collect),
    // then handle results sequentially so output and errors stay deterministic.
    use rayon::prelude::*;
    let outcomes: Vec<_> = targets
        .par_iter()
        .map(|t| (t, engine.scan_file(t)))
        .collect();

    let mut worst = 0u8;
    let mut reports = Vec::new();
    for (target, outcome) in outcomes {
        match outcome {
            Ok(r) => {
                worst = worst.max(r.verdict.level.exit_code());
                reports.push(r);
            }
            Err(e) => {
                // A directory scan shouldn't abort because one file is odd.
                if targets.len() == 1 {
                    eprintln!("error scanning {}: {e}", target.display());
                    return ExitCode::from(4);
                }
                eprintln!("skipping {}: {e}", target.display());
            }
        }
    }

    if md {
        print!("{}", report::render_markdown(&reports));
    } else if json {
        let joined: Vec<_> = reports.iter().collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&joined).unwrap_or_default()
        );
    } else {
        for (i, r) in reports.iter().enumerate() {
            if i > 0 {
                println!("\n{}\n", "─".repeat(60));
            }
            if verdict_only {
                let name = std::path::Path::new(&r.path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                println!(
                    "{}  {}  (score {})",
                    r.verdict.level.headline(),
                    name,
                    r.verdict.score
                );
            } else {
                print!("{}", report::render_text(r));
            }
        }
    }

    ExitCode::from(worst)
}
