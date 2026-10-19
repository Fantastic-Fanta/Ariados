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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { path, json, verdict_only } => cmd_scan(&path, json, verdict_only),
    }
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
