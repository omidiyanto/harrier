//! harrier: Wazuh agent identity, self-healing and inventory hygiene.
//!
//! Endpoint side (`setup`, `check`) holds no Wazuh credentials at all.
//! Server side (`setup-server`, `reconcile`) runs next to the manager and
//! is the only place that talks to the Wazuh API.

mod agent;
mod identity;
mod json;
mod reconcile;
mod sha256;
mod sys;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
Harrier - the fleet guardian for Wazuh
Hardware-bound agent identity, self-healing and inventory hygiene.

ENDPOINT (run as root / Administrator, no Wazuh credentials needed):
  harrier setup [--manager ADDR] [--group NAME] [--package FILE]
                [--package-sha256 HEX] [--agent-dir DIR]
      Install or upgrade Harrier, install the Wazuh agent from FILE (.msi,
      .deb, .rpm) if missing or upgrade it when FILE is a new package, bind
      the agent to this hardware and run the `harrier` background service
      (one pass every 5 minutes). Safe to re-run. Enrollment password, if
      your manager uses one: env WAZUH_REGISTRATION_PASSWORD.
  harrier check       One self-healing pass now (the service runs it too).
  harrier status      Show hardware identity and agent health.
  harrier name        Print the hardware-bound agent name.
  harrier uninstall   Remove the Harrier services (the agent stays installed).

SERVER (run as root on the Wazuh manager or a host that reaches its API):
  harrier setup-server --api-url URL --api-user USER
                [--api-ca-file FILE | --api-cert FILE | --api-pin sha256//B64
                 | --api-insecure (skip TLS verification: self-signed lab setups)]
                [--disconnected-days N] [--never-connected-days N] [--max-delete N]
      Store API settings (password: env HARRIER_API_PASSWORD), verify the
      connection and run the `harrier-reconcile` background service
      (`reconcile --apply` every 60 minutes). Safe to re-run.
  harrier reconcile [--apply]
      Remove duplicate/stale agents (dry-run unless --apply).

SERVICE (started by systemd / the Windows service manager):
  harrier daemon check|reconcile   Loop forever; interval_minutes in the config.

COMMON:  --config FILE   --version   --help
";

#[derive(Debug, Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

pub fn log(level: Level, msg: &str) {
    let tag = match level {
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Error => "error",
    };
    eprintln!("harrier {tag}: {msg}");
}

/// Log, and on Windows also write to the Application event log (which the
/// Wazuh agent forwards to the SIEM).
pub fn notify(level: Level, msg: &str) {
    log(level, msg);
    sys::event_log(level, msg);
}

/// Service command line: `daemon <task>`, plus `--config` for a non-default
/// path. The path ends up in a systemd `ExecStart` (expands `$` and `%`) or
/// the SCM image path, so only plain path characters are accepted.
pub fn service_args(task: &str, cfg: &Config, file: &str) -> Result<String, String> {
    let base = format!("daemon {task}");
    if cfg.path == sys::config_dir().join(file) {
        return Ok(base);
    }
    let p = cfg.path.display().to_string();
    let plain = |c: char| {
        c.is_ascii_alphanumeric() || "/._-".contains(c) || (cfg!(windows) && "\\: ()".contains(c))
    };
    if !p.chars().all(plain) {
        return Err(format!(
            "--config path may only contain letters, digits and / . _ - (got {p})"
        ));
    }
    Ok(if cfg!(windows) {
        format!("{base} --config \"{p}\"")
    } else {
        format!("{base} --config {p}")
    })
}

/// Service body: one pass every `interval_minutes`, re-reading the config
/// each time so edits apply without a restart. Repeated identical errors
/// are reported once, not every pass.
fn daemon(task: &str, path: &Path) {
    let (file, default_minutes) = match task {
        "check" => (agent::CONFIG_FILE, 5),
        _ => (reconcile::CONFIG_FILE, 60),
    };
    notify(
        Level::Info,
        &format!(
            "Harrier {} service started ({task})",
            env!("CARGO_PKG_VERSION")
        ),
    );
    let mut last_error = String::new();
    loop {
        let mut minutes = default_minutes;
        let result = sys::check_owner(path, file == reconcile::CONFIG_FILE)
            .and_then(|()| Config::load(path))
            .and_then(|cfg| {
                minutes = cfg.num("interval_minutes", default_minutes)?.max(1);
                match task {
                    "check" => agent::check(&cfg),
                    _ => reconcile::run(&cfg, true),
                }
            });
        match result {
            Ok(()) => last_error.clear(),
            Err(e) if e == last_error => log(Level::Error, &e),
            Err(e) => {
                notify(Level::Error, &e);
                last_error = e;
            }
        }
        if sys::sleep_or_stop(std::time::Duration::from_secs(minutes * 60)) {
            notify(Level::Info, &format!("Harrier service stopped ({task})"));
            return;
        }
    }
}

/// The Harrier mascot, same pixel grid as the icon (`assets/source/harrier.py`).
const MASCOT: [&str; 14] = [
    ".......######...",
    "......########..",
    ".....####kk###yy",
    ".....####kk###.y",
    "......########..",
    ".....#########..",
    "....##########..",
    "...###########..",
    "..############..",
    ".############...",
    "##..########....",
    "#....######.....",
    "......#..#......",
    ".....##.##......",
];

/// Mascot drawn with half blocks (two pixel rows per line) in 24-bit colour;
/// only on a Unix terminal, so pipes and older Windows consoles get plain text.
fn banner() -> String {
    use std::io::IsTerminal;
    if cfg!(windows) || !std::io::stdout().is_terminal() {
        return String::new();
    }
    let rgb = |c: u8| match c {
        b'#' => Some("255;122;26"),
        b'y' => Some("255;210;63"),
        _ => None, // eyes and background show the terminal background
    };
    let mut out = String::from("\n");
    for pair in MASCOT.chunks(2) {
        out.push_str("  ");
        for (top, bottom) in pair[0].bytes().zip(pair[1].bytes()) {
            let cell = match (rgb(top), rgb(bottom)) {
                (None, None) => " ".to_owned(),
                (Some(t), None) => format!("\x1b[38;2;{t}m\u{2580}"),
                (None, Some(b)) => format!("\x1b[38;2;{b}m\u{2584}"),
                (Some(t), Some(b)) => format!("\x1b[38;2;{t};48;2;{b}m\u{2580}"),
            };
            out.push_str(&cell);
            out.push_str("\x1b[0m");
        }
        out.push('\n');
    }
    out.push('\n');
    out
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `key = value` file (`#` comments). Used for config and local state.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub path: PathBuf,
    map: BTreeMap<String, String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let map = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            map,
        })
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    #[allow(clippy::needless_pass_by_value)] // convenience: set("n", 5)
    pub fn set(&mut self, key: &str, value: impl ToString) {
        self.map.insert(key.to_owned(), value.to_string());
    }

    pub fn remove(&mut self, key: &str) {
        self.map.remove(key);
    }

    /// `true`/`yes`/`1` or `false`/`no`/`0`; absent means false.
    pub fn flag(&self, key: &str) -> Result<bool, String> {
        match self.get(key).map(str::to_ascii_lowercase).as_deref() {
            None | Some("false" | "no" | "0") => Ok(false),
            Some("true" | "yes" | "1") => Ok(true),
            Some(v) => Err(format!(
                "{}: {key} must be true or false, not {v:?}",
                self.path.display()
            )),
        }
    }

    pub fn num(&self, key: &str, default: u64) -> Result<u64, String> {
        self.get(key).map_or(Ok(default), |v| {
            v.parse()
                .map_err(|_| format!("{}: {key} must be a number", self.path.display()))
        })
    }

    pub fn save(&self, mode: u32) -> Result<(), String> {
        let mut out = String::from("# managed by harrier\n");
        for (k, v) in &self.map {
            let _ = writeln!(out, "{k} = {v}");
        }
        sys::write_file(&self.path, &out, mode)
    }
}

#[derive(Debug, Default)]
struct Args {
    cmd: String,
    /// `daemon <task>` is the only command with a positional argument.
    task: String,
    opts: BTreeMap<String, String>,
    apply: bool,
}

fn parse_args(raw: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => a.cmd = "help".into(),
            "-V" | "--version" | "version" => a.cmd = "version".into(),
            "--apply" => a.apply = true,
            "--api-insecure" => {
                a.opts.insert("api-insecure".into(), "true".into());
            }
            s if s.starts_with("--") => {
                let (k, v) = match s[2..].split_once('=') {
                    Some((k, v)) => (k.to_owned(), v.to_owned()),
                    None => (
                        s[2..].to_owned(),
                        it.next().ok_or_else(|| format!("{s} needs a value"))?,
                    ),
                };
                a.opts.insert(k, v);
            }
            s if a.cmd.is_empty() => s.clone_into(&mut a.cmd),
            s if a.cmd == "daemon" && a.task.is_empty() => s.clone_into(&mut a.task),
            s => return Err(format!("unexpected argument {s:?}")),
        }
    }
    Ok(a)
}

fn allowed_options(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "setup" => &[
            "config",
            "manager",
            "group",
            "package",
            "package-sha256",
            "agent-dir",
        ],
        "setup-server" => &[
            "config",
            "api-url",
            "api-user",
            "api-ca-file",
            "api-cert",
            "api-pin",
            "api-insecure",
            "disconnected-days",
            "never-connected-days",
            "max-delete",
        ],
        _ => &["config"],
    }
}

fn run() -> Result<(), String> {
    let a = parse_args(std::env::args().skip(1))?;
    if let Some(bad) = a
        .opts
        .keys()
        .find(|k| !allowed_options(&a.cmd).contains(&k.as_str()))
    {
        return Err(format!(
            "unknown option --{bad} for `{}` (see --help)",
            a.cmd
        ));
    }
    if a.apply && a.cmd != "reconcile" {
        return Err("--apply only applies to `reconcile`".into());
    }
    let config_path = |file: &str| match a.opts.get("config") {
        Some(p) => std::path::absolute(p).map_err(|e| format!("--config {p}: {e}")),
        None => Ok(sys::config_dir().join(file)),
    };
    let config = |file: &str| -> Result<Config, String> {
        let path = config_path(file)?;
        // Before reading: harrier runs as root/SYSTEM on what this file says.
        sys::check_owner(&path, file == reconcile::CONFIG_FILE)?;
        Config::load(&path)
    };
    match a.cmd.as_str() {
        "" | "help" => {
            print!("{}{USAGE}", banner());
            Ok(())
        }
        "version" => {
            println!("{}harrier {}", banner(), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "setup" => agent::setup(&a.opts, config(agent::CONFIG_FILE)?),
        "check" => agent::check(&config(agent::CONFIG_FILE)?),
        "status" => agent::status(&config(agent::CONFIG_FILE)?),
        "name" => agent::print_name(),
        "uninstall" => agent::uninstall(),
        "setup-server" => reconcile::setup_server(&a.opts, config(reconcile::CONFIG_FILE)?),
        "reconcile" => reconcile::run(&config(reconcile::CONFIG_FILE)?, a.apply),
        "daemon" => {
            let file = match a.task.as_str() {
                "check" => agent::CONFIG_FILE,
                "reconcile" => reconcile::CONFIG_FILE,
                t => return Err(format!("daemon needs `check` or `reconcile`, not {t:?}")),
            };
            let path = config_path(file)?;
            let task = a.task.clone();
            sys::serve(Box::new(move || daemon(&task, &path)));
            Ok(())
        }
        other => Err(format!("unknown command {other:?} (see --help)")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            notify(Level::Error, &e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Args, String> {
        parse_args(s.split_whitespace().map(String::from))
    }

    #[test]
    fn cli_parsing() {
        let a = args("setup --manager 10.0.0.5 --group=it").unwrap();
        assert_eq!(a.cmd, "setup");
        assert_eq!(a.opts["manager"], "10.0.0.5");
        assert_eq!(a.opts["group"], "it");
        assert!(args("reconcile --apply").unwrap().apply);
        assert!(args("setup --manager").is_err());
        assert!(args("check extra").is_err());
        let d = args("daemon check --config /x").unwrap();
        assert_eq!((d.cmd.as_str(), d.task.as_str()), ("daemon", "check"));
        assert!(args("daemon check extra").is_err());
    }

    #[test]
    fn service_config_paths() {
        let cfg = |p: &str| Config {
            path: PathBuf::from(p),
            ..Config::default()
        };
        let default = cfg(&sys::config_dir().join("x.conf").display().to_string());
        assert_eq!(
            service_args("check", &default, "x.conf").unwrap(),
            "daemon check"
        );
        let custom = if cfg!(windows) {
            "daemon check --config \"/srv/harrier.conf\""
        } else {
            "daemon check --config /srv/harrier.conf"
        };
        assert_eq!(
            service_args("check", &cfg("/srv/harrier.conf"), "x.conf").unwrap(),
            custom
        );
        let mut bad = vec![
            "/tmp/a;reboot",
            "/tmp/$(id)",
            "/tmp/%h",
            "/tmp/`x`",
            "/tmp/a\"b",
        ];
        if !cfg!(windows) {
            bad.push("/tmp/a b"); // spaces are fine in a quoted Windows image path
        }
        for p in bad {
            assert!(service_args("check", &cfg(p), "x.conf").is_err(), "{p}");
        }
    }

    #[test]
    fn config_roundtrip() {
        let dir = std::env::temp_dir().join(format!("harrier-test-{}", std::process::id()));
        let path = dir.join("c.conf");
        let mut c = Config::load(&path).unwrap();
        assert!(!c.exists());
        c.set("api_password", "p=ss#word");
        c.set("max_delete", 7);
        c.save(0o600).unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.get("api_password"), Some("p=ss#word"));
        assert_eq!(c.num("max_delete", 1).unwrap(), 7);
        assert_eq!(c.num("missing", 3).unwrap(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
