//! Temporary parsing harness — replaced by the real CLI once analysis lands.

use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: ariados <binary>");
            return ExitCode::from(2);
        }
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match ariados::formats::parse(&data) {
        Ok(prog) => {
            println!("{} ({} bytes)  sha256={}", prog.format, prog.size, &prog.sha256[..16]);
            for obj in &prog.objects {
                let strings = obj.import_slots.len();
                let imports_in_names =
                    obj.names.values().filter(|n| n.kind == ariados::model::NameKind::Import).count();
                println!(
                    "  arch={:<8} entry={:#x} sections={} functions={} named={} stub-imports={} slot-imports={} libs={} signing={:?}",
                    obj.arch.label(),
                    obj.entry,
                    obj.sections.len(),
                    obj.functions.len(),
                    obj.names.len(),
                    imports_in_names,
                    strings,
                    obj.libraries.len(),
                    obj.signing,
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("parse error: {e}");
            ExitCode::from(1)
        }
    }
}
