//! Ariados command-line interface.

use ariados::report;
use ariados::scan::{collect_targets, Engine};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ariados", version, about = "Static binary triage with evidence trails")]
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
        /// Print only the verdict line.
        #[arg(long)]
        verdict_only: bool,
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
        Command::Scan { path, json, verdict_only } => cmd_scan(&path, json, verdict_only),
        Command::Strings { path, min, hidden_only } => cmd_strings(&path, min, hidden_only),
        Command::Eval { benign, malicious, flag_at } => cmd_eval(&benign, &malicious, &flag_at),
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
                let mark = ariados::decode::notable(&h.text).map(|l| format!("  <-- {l}")).unwrap_or_default();
                println!("[{}+{:#x} XOR {:#04x}]  {}{mark}", h.section, h.offset, h.key, h.text);
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

    let mut engine = Engine::builtin();
    engine.enrich_signing = false; // avoid thousands of codesign subprocesses
    engine.decode_hidden = false; // the XOR sweep would dominate a bulk run
    ariados::eval::report(&engine, &benign_refs, &malicious_refs, level);
    ExitCode::SUCCESS
}

fn cmd_scan(path: &std::path::Path, json: bool, verdict_only: bool) -> ExitCode {
    let engine = Engine::builtin();
    let targets = collect_targets(path);
    if targets.is_empty() {
        eprintln!("no executable files found at {}", path.display());
        return ExitCode::from(2);
    }

    let mut worst = 0u8;
    let mut reports = Vec::new();
    for target in &targets {
        match engine.scan_file(target) {
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

    if json {
        let joined: Vec<_> = reports.iter().collect();
        println!("{}", serde_json::to_string_pretty(&joined).unwrap_or_default());
    } else {
        for (i, r) in reports.iter().enumerate() {
            if i > 0 {
                println!("\n{}\n", "─".repeat(60));
            }
            if verdict_only {
                let name = std::path::Path::new(&r.path).file_name().unwrap_or_default().to_string_lossy();
                println!("{}  {}  (score {})", r.verdict.level.headline(), name, r.verdict.score);
            } else {
                print!("{}", report::render_text(r));
            }
        }
    }

    ExitCode::from(worst)
}
