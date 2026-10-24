//! Endpoint side: keep the local Wazuh agent bound to this hardware and
//! healthy. Holds no Wazuh credentials; every server-side cleanup is done by
//! `harrier reconcile` on the manager.
//!
//! Self-healing playbook (the case letters appear in the logs):
//! A healthy -> idle            B manager unreachable -> standby
//! C key rejected -> re-enroll  D other hardware (clone) -> re-enroll
//! E hostname changed -> re-enroll, server drops the old record
//! F local drift/missing key -> repair config, agent self-enrolls
//! G hung/stopped agent -> restart
//! H group drift -> server-authoritative (reconcile carries groups over)

use std::collections::BTreeMap;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::identity::{self, Fingerprint};
use crate::sys::{self, AGENT_FILES, SYNC_DB_DIRS, Service};
use crate::{Config, Level, log, notify, now, sha256};

pub const CONFIG_FILE: &str = "harrier.conf";
const STATE_FILE: &str = "state";
const LABEL_KEY: &str = "harrier_hwid";
const STALE_STATE: Duration = Duration::from_secs(300);
const GHOST_AFTER: u64 = 3600;
const REENROLL_MIN_INTERVAL: u64 = 3600;

// ------------------------------------------------------------- identity ----

#[derive(Debug)]
struct Ident {
    name: String,
    hash: String,
    fwid: String,
    host: String,
    fp: Fingerprint,
}

/// Compute the identity, keeping the stored one while it is still the same
/// machine. Records the result in `memo` (persisted by the caller).
fn identify(memo: &mut Config) -> Result<Ident, String> {
    let raw = sys::hostname();
    let host = identity::sanitize_host(&raw)
        .ok_or_else(|| format!("hostname {raw:?} has no usable characters"))?;
    let fp = Fingerprint::collect()?;
    let current = fp.hash(sys::machine_id)?;

    let stored = Fingerprint {
        uuid: memo.get("uuid").unwrap_or_default().to_owned(),
        serial: memo.get("serial").unwrap_or_default().to_owned(),
        macs: memo
            .get("macs")
            .unwrap_or_default()
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    let hash = identity::resolve(&current, &fp, memo.get("hwid").map(|h| (h, &stored)));
    if hash != current {
        log(
            Level::Info,
            "NIC set changed on the same board; identity kept",
        );
    }

    memo.set("hwid", &hash);
    memo.set("uuid", &fp.uuid);
    memo.set("serial", &fp.serial);
    if !fp.macs.is_empty() {
        memo.set("macs", fp.macs.join(","));
    }
    let fwid = fp.fwid(&hash);
    Ok(Ident {
        name: identity::agent_name(&host, &hash, &fwid),
        hash,
        fwid,
        host,
        fp,
    })
}

fn memo_load() -> Result<Config, String> {
    Config::load(&sys::data_dir().join(STATE_FILE))
}

// ---------------------------------------------------------------- agent ----

struct Agent {
    dir: PathBuf,
}

impl Agent {
    fn new(cfg: &Config) -> Self {
        Self {
            dir: cfg
                .get("agent_dir")
                .map_or_else(sys::default_agent_dir, PathBuf::from),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    fn installed(&self) -> bool {
        self.path(AGENT_FILES.ossec_conf).is_file()
    }

    fn read_conf(&self) -> Result<String, String> {
        let p = self.path(AGENT_FILES.ossec_conf);
        fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
    }

    fn enrolled_name(&self) -> Option<String> {
        fs::read_to_string(self.path(AGENT_FILES.client_keys))
            .ok()
            .and_then(|t| enrolled_name(&t))
    }

    /// `(state file fresh, status)`. The file is rewritten every 5 s while
    /// the agent runs and left stale when it stops (wazuh/wazuh#16253).
    fn state(&self) -> (bool, String) {
        let p = self.path(AGENT_FILES.state);
        let fresh = fs::metadata(&p)
            .and_then(|m| m.modified())
            .is_ok_and(|t| SystemTime::now().duration_since(t).unwrap_or_default() <= STALE_STATE);
        let status = fs::read_to_string(&p)
            .ok()
            .and_then(|t| state_status(&t))
            .unwrap_or_else(|| "missing".into());
        (fresh, status)
    }

    fn service(&self, action: Service) -> Result<(), String> {
        sys::service(&self.dir, action)
    }

    /// In-place rewrite (keeps owner/permissions) after a backup copy.
    fn write_conf(&self, xml: &str) -> Result<(), String> {
        let p = self.path(AGENT_FILES.ossec_conf);
        backup(&p)?;
        fs::write(&p, xml).map_err(|e| format!("cannot write {}: {e}", p.display()))
    }

    /// Drop the enrolled identity: back up and empty client.keys, and clear
    /// the local sync databases so the new agent id gets a full snapshot.
    fn drop_identity(&self) -> Result<(), String> {
        let keys = self.path(AGENT_FILES.client_keys);
        if keys.is_file() {
            backup(&keys)?;
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&keys)
                .map_err(|e| format!("cannot empty {}: {e}", keys.display()))?;
        }
        for dir in SYNC_DB_DIRS {
            let Ok(entries) = fs::read_dir(self.path(dir)) else {
                continue;
            };
            for f in entries.flatten().map(|e| e.path()).filter(|p| p.is_file()) {
                fs::remove_file(&f).map_err(|e| format!("cannot remove {}: {e}", f.display()))?;
            }
        }
        Ok(())
    }
}

fn backup(path: &Path) -> Result<(), String> {
    let mut b = path.as_os_str().to_owned();
    b.push(".harrier-bak");
    fs::copy(path, &b)
        .map(drop)
        .map_err(|e| format!("cannot back up {}: {e}", path.display()))
}

// ---------------------------------------------------------------- check ----

pub fn check(cfg: &Config) -> Result<(), String> {
    let agent = Agent::new(cfg);
    let mut memo = memo_load()?;
    let result = check_inner(cfg, &agent, &mut memo);
    memo.save(0o600)?;
    result
}

fn check_inner(cfg: &Config, agent: &Agent, memo: &mut Config) -> Result<(), String> {
    let id = identify(memo)?;
    if !agent.installed() {
        notify(Level::Warn, "Wazuh agent is not installed; reinstalling");
        install_agent(cfg, agent, &id)?;
    }

    let xml = agent.read_conf()?;
    let want = set_label(&set_agent_name(&xml, &id.name)?, LABEL_KEY, &id.hash)?;
    let enrolled = agent.enrolled_name();

    if let Some(from) = enrolled.as_deref().filter(|e| *e != id.name) {
        let why = match identity::parse_name(from) {
            Some(n) if id.hash.starts_with(n.hwid) => "case E: hostname changed",
            Some(n) if id.fwid.starts_with(n.fwid) => "case I: every network card changed",
            Some(_) => "case D: different hardware (cloned or moved disk)",
            None => "adopting the hardware-bound name",
        };
        return reenroll(agent, memo, &want, from, &id.name, why);
    }

    if want != xml {
        agent.write_conf(&want)?;
        notify(
            Level::Warn,
            &format!("case F: repaired agent_name/{LABEL_KEY} in ossec.conf; restarting agent"),
        );
        memo.set("last_restart", now());
        return agent.service(Service::Restart);
    }

    health(cfg, agent, memo, &xml, &id.name, enrolled.is_some())
}

fn reenroll(
    agent: &Agent,
    memo: &mut Config,
    xml: &str,
    from: &str,
    to: &str,
    why: &str,
) -> Result<(), String> {
    let t = now();
    if let Some(last) = memo
        .get("last_reenroll")
        .and_then(|v| v.parse::<u64>().ok())
    {
        if t.saturating_sub(last) < REENROLL_MIN_INTERVAL {
            return Err(format!(
                "{why}: re-enrolling {from} -> {to} postponed, last re-enrollment was {} min ago",
                t.saturating_sub(last) / 60
            ));
        }
    }
    notify(Level::Warn, &format!("{why}: re-enrolling {from} -> {to}"));
    memo.set("last_reenroll", t);
    memo.set("last_restart", t);
    let _ = agent.service(Service::Stop);
    let changed = agent.write_conf(xml).and_then(|()| agent.drop_identity());
    let started = agent.service(Service::Start);
    changed.and(started)
}

fn health(
    cfg: &Config,
    agent: &Agent,
    memo: &mut Config,
    xml: &str,
    name: &str,
    has_key: bool,
) -> Result<(), String> {
    let t = now();
    let (fresh, status) = agent.state();
    if fresh && status == "connected" {
        if memo.get("unhealthy_since").is_some() {
            notify(Level::Info, "case A: agent connected again");
            memo.remove("unhealthy_since");
        }
        return Ok(());
    }

    let since = memo
        .get("unhealthy_since")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(t);
    memo.set("unhealthy_since", since);
    let down = t.saturating_sub(since);
    let what = if fresh {
        format!("agent {status}")
    } else {
        "agent not running".to_owned()
    };
    if down < cfg.num("grace_minutes", 10)? * 60 {
        log(
            Level::Info,
            &format!("{what} for {} min; observing", down / 60),
        );
        return Ok(());
    }
    if fresh && !manager_reachable(xml) {
        log(
            Level::Info,
            &format!("case B: {what}, manager unreachable; standby"),
        );
        return Ok(());
    }

    let last_restart = memo.get("last_restart").and_then(|v| v.parse::<u64>().ok());
    let backoff = cfg.num("backoff_minutes", 30)? * 60;
    let in_backoff = last_restart.is_some_and(|r| t.saturating_sub(r) < backoff);
    let restarted_already = last_restart.is_some_and(|r| r >= since);

    if fresh && has_key && restarted_already && !in_backoff && down >= GHOST_AFTER {
        return reenroll(
            agent,
            memo,
            xml,
            name,
            name,
            "case C: manager keeps refusing this agent's key",
        );
    }
    if in_backoff {
        log(Level::Info, &format!("{what}; restart backoff"));
        return Ok(());
    }
    notify(
        Level::Warn,
        &format!("case G: {what} for {} min; restarting agent", down / 60),
    );
    memo.set("last_restart", t);
    agent.service(Service::Restart)
}

fn manager_reachable(xml: &str) -> bool {
    let endpoints = manager_endpoints(xml);
    endpoints.is_empty() || endpoints.iter().any(|(host, port)| reachable(host, *port))
}

fn reachable(host: &str, port: u16) -> bool {
    (host, port).to_socket_addrs().is_ok_and(|mut addrs| {
        addrs.any(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).is_ok())
    })
}

// ---------------------------------------------------------------- setup ----

pub const SERVICE: &str = "harrier";
const SERVICE_DESCRIPTION: &str = "Harrier - fleet guardian for Wazuh";

pub fn setup(opts: &BTreeMap<String, String>, mut cfg: Config) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate harrier: {e}"))?;
    // A running service keeps harrier.exe locked on Windows; it is restarted below.
    sys::stop_daemon(SERVICE);
    let bin = sys::install_self(&exe)?;

    for key in ["manager", "group", "agent-dir"] {
        if let Some(v) = opts.get(key) {
            validate_option(key, v)?;
            cfg.set(&key.replace('-', "_"), v);
        }
    }
    let package = opts
        .get("package")
        .map(|p| store_package(Path::new(p), opts.get("package-sha256")))
        .transpose()?;

    let agent = Agent::new(&cfg);
    let mut memo = memo_load()?;
    let id = identify(&mut memo)?;
    memo.save(0o600)?;

    // Same command installs, upgrades, or does nothing: the installer runs
    // only when the agent is missing or the package differs from the last
    // one harrier installed. Config is saved only after it succeeded, so a
    // failed run is retried by re-running the same command.
    let previous = cfg.get("package").map(PathBuf::from);
    let changed = package
        .as_ref()
        .is_some_and(|(_, digest)| cfg.get("package_sha256") != Some(digest.as_str()));
    if let Some((stored, digest)) = &package {
        cfg.set("package", stored.display());
        cfg.set("package_sha256", digest);
    }
    if !agent.installed() {
        install_agent(&cfg, &agent, &id)?;
    } else if changed {
        upgrade_agent(&cfg, &agent)?;
    } else {
        log(
            Level::Info,
            &format!("Wazuh agent found in {}", agent.dir.display()),
        );
    }
    cfg.save(0o644)?;
    if changed {
        remove_stale_package(previous, cfg.get("package"));
    }
    if let Ok(pass) = std::env::var("WAZUH_REGISTRATION_PASSWORD") {
        set_enrollment_password(&agent, pass.trim())?;
    }

    // One pass in the foreground so problems show up right here; the
    // service is installed either way and keeps retrying.
    let first_pass = check(&cfg);
    sys::wazuh_restart_on_failure()?;
    let service = sys::install_daemon(
        SERVICE,
        SERVICE_DESCRIPTION,
        &crate::service_args("check", &cfg, CONFIG_FILE)?,
    )?;
    println!("harrier installed: {}", bin.display());
    println!("agent name:      {}", id.name);
    println!("service:         {service}");
    first_pass
}

fn validate_option(key: &str, value: &str) -> Result<(), String> {
    let ok = match key {
        // One or more managers / groups, comma separated.
        "manager" => value.split(',').all(|m| {
            !m.is_empty()
                && m.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:_[]".contains(&b))
        }),
        "group" => value.split(',').all(identity::is_valid_name),
        _ => !value.is_empty(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("invalid --{key} value {value:?}"))
    }
}

/// Copy the agent package next to harrier (for self-healing reinstalls) and
/// pin its SHA-256.
fn store_package(src: &Path, expected: Option<&String>) -> Result<(PathBuf, String), String> {
    let data = fs::read(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    let digest = sha256::hex(&sha256::digest(&data));
    if let Some(want) = expected {
        if !want.eq_ignore_ascii_case(&digest) {
            return Err(format!(
                "{}: SHA-256 is {digest}, expected {want}",
                src.display()
            ));
        }
    }
    let name = src.file_name().ok_or("--package must be a file")?;
    supported_package(&name.to_string_lossy())?;
    let dest = sys::data_dir().join(name);
    if fs::read(&dest).ok().as_deref() != Some(data.as_slice()) {
        sys::write_bytes(&dest, &data, 0o600)?;
    }
    Ok((dest, digest))
}

/// Wazuh agent 4.x up to 4.14 only (5.x is untested). A package whose file
/// name carries no version is let through.
fn supported_package(file: &str) -> Result<(), String> {
    let Some(rest) = file
        .strip_prefix("wazuh-agent")
        .and_then(|r| r.strip_prefix(['-', '_']))
    else {
        return Ok(());
    };
    let mut v = rest.split(['.', '-', '_']).map(str::parse::<u32>);
    match (v.next(), v.next()) {
        (Some(Ok(major)), Some(Ok(minor))) if major != 4 || minor > 14 => Err(format!(
            "{file}: Wazuh agent {major}.{minor} is not supported \
             (4.x up to 4.14; 5.x is untested)"
        )),
        _ => Ok(()),
    }
}

/// Run the stored package after re-checking its pinned SHA-256.
fn run_installer(
    cfg: &Config,
    agent: &Agent,
    vars: &[(&str, String)],
    what: &str,
) -> Result<(), String> {
    let pkg = cfg.get("package").ok_or(
        "the Wazuh agent is not installed: pass --package FILE \
             (one-command installer: --wazuh-version / -WazuhVersion, e.g. 4.14.9)",
    )?;
    let data = fs::read(pkg).map_err(|e| format!("cannot read {pkg}: {e}"))?;
    if cfg.get("package_sha256") != Some(sha256::hex(&sha256::digest(&data)).as_str()) {
        return Err(format!(
            "{pkg} does not match its pinned SHA-256; refusing to install"
        ));
    }
    notify(Level::Warn, &format!("{what} Wazuh agent from {pkg}"));
    sys::install_package(Path::new(pkg), vars, &agent.dir)
}

/// Upgrade in place: no `WAZUH_*` settings, the installed config is kept.
fn upgrade_agent(cfg: &Config, agent: &Agent) -> Result<(), String> {
    run_installer(cfg, agent, &[], "upgrading")
}

/// Fresh install with the hardware-bound name already set.
fn install_agent(cfg: &Config, agent: &Agent, id: &Ident) -> Result<(), String> {
    let manager = cfg
        .get("manager")
        .ok_or("--manager is required to install the Wazuh agent")?;
    let mut vars = vec![
        ("WAZUH_MANAGER", manager.to_owned()),
        ("WAZUH_AGENT_NAME", id.name.clone()),
    ];
    if let Some(group) = cfg.get("group") {
        vars.push(("WAZUH_AGENT_GROUP", group.to_owned()));
    }
    run_installer(cfg, agent, &vars, &format!("installing ({})", id.name))
}

/// Drop the previous package copy once a newer one is installed.
fn remove_stale_package(previous: Option<PathBuf>, current: Option<&str>) {
    if let Some(old) = previous.filter(|p| p.starts_with(sys::data_dir()) && current != p.to_str())
    {
        let _ = fs::remove_file(old);
    }
}

/// Write `authd.pass` (never on a command line) and retry enrollment.
fn set_enrollment_password(agent: &Agent, pass: &str) -> Result<(), String> {
    if pass.is_empty() || pass.contains(['\n', '\r']) {
        return Err("WAZUH_REGISTRATION_PASSWORD must be a single non-empty line".into());
    }
    let path = agent.path(AGENT_FILES.authd_pass);
    if fs::read_to_string(&path).ok().as_deref().map(str::trim) == Some(pass) {
        return Ok(());
    }
    sys::write_file(&path, &format!("{pass}\n"), 0o600)?;
    sys::share_with_agent(&path)?;
    log(Level::Info, "enrollment password updated");
    if agent.enrolled_name().is_none() {
        agent.service(Service::Restart)?;
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    sys::remove_daemon(SERVICE)?;
    sys::remove_daemon(crate::reconcile::SERVICE)?;
    println!("harrier services removed; the Wazuh agent is untouched");
    Ok(())
}

pub fn print_name() -> Result<(), String> {
    println!("{}", identify(&mut memo_load()?)?.name);
    Ok(())
}

pub fn status(cfg: &Config) -> Result<(), String> {
    let id = identify(&mut memo_load()?)?;
    let agent = Agent::new(cfg);
    let dash = |s: &str| {
        if s.is_empty() {
            "-".to_owned()
        } else {
            s.to_owned()
        }
    };
    println!("hostname       : {}", id.host);
    println!("smbios uuid    : {}", dash(&id.fp.uuid));
    println!("bios serial    : {}", dash(&id.fp.serial));
    println!("physical macs  : {}", dash(&id.fp.macs.join(", ")));
    println!("identity source: {}", id.fp.source());
    println!("hardware id    : {} (UUID + serial + MACs)", id.hash);
    if id.fwid == id.hash {
        println!("firmware id    : - (no usable SMBIOS UUID and serial; hardware id used)");
    } else {
        println!("firmware id    : {} (UUID + serial)", id.fwid);
    }
    println!("agent name     : {}", id.name);
    println!("agent dir      : {}", agent.dir.display());
    if !agent.installed() {
        println!("agent          : NOT INSTALLED");
        return Ok(());
    }
    let xml = agent.read_conf()?;
    let enrolled = agent.enrolled_name();
    let configured = read_agent_name(&xml);
    let mark = |v: Option<&str>| match v {
        Some(v) if v == id.name => format!("{v} (ok)"),
        Some(v) => format!("{v} (will be fixed by `harrier check`)"),
        None => "- (will be fixed by `harrier check`)".to_owned(),
    };
    println!("enrolled as    : {}", mark(enrolled.as_deref()));
    println!("ossec.conf name: {}", mark(configured.as_deref()));
    let (fresh, state) = agent.state();
    println!(
        "agent state    : {state}{}",
        if fresh { "" } else { " (agent not running)" }
    );
    for (host, port) in manager_endpoints(&xml) {
        let up = reachable(&host, port);
        println!(
            "manager        : {host}:{port} {}",
            if up { "reachable" } else { "UNREACHABLE" }
        );
    }
    Ok(())
}

// ----------------------------------------------------- ossec.conf editing ---
// ossec.conf is machine-written and stable across 4.x, so a small,
// comment-aware element finder is enough; no XML library needed.

#[derive(Debug, Clone)]
struct Elem {
    start: usize,
    open_end: usize,
    inner: Range<usize>,
    end: usize,
}

/// Same byte length as `xml`, with `<!-- comments -->` blanked out.
fn mask_comments(xml: &str) -> String {
    let mut out = xml.as_bytes().to_vec();
    let mut pos = 0;
    while let Some(s) = xml[pos..].find("<!--").map(|i| i + pos) {
        let e = xml[s + 4..]
            .find("-->")
            .map_or(xml.len(), |i| s + 4 + i + 3);
        out[s..e].fill(b' ');
        pos = e;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find_all(m: &str, tag: &str, within: Range<usize>) -> Vec<Elem> {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut pos = within.start;
    while let Some(start) = m[pos..within.end].find(&open).map(|i| i + pos) {
        let after = start + open.len();
        if !matches!(
            m.as_bytes().get(after),
            Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')
        ) {
            pos = after;
            continue;
        }
        let Some(open_end) = m[after..within.end].find('>').map(|i| after + i + 1) else {
            break;
        };
        if m.as_bytes()[open_end - 2] == b'/' {
            out.push(Elem {
                start,
                open_end,
                inner: open_end..open_end,
                end: open_end,
            });
            pos = open_end;
            continue;
        }
        let Some(inner_end) = m[open_end..within.end].find(&close).map(|i| open_end + i) else {
            break;
        };
        let end = inner_end + close.len();
        out.push(Elem {
            start,
            open_end,
            inner: open_end..inner_end,
            end,
        });
        pos = end;
    }
    out
}

fn find(m: &str, tag: &str, within: Range<usize>) -> Option<Elem> {
    find_all(m, tag, within).into_iter().next()
}

fn splice(xml: &str, range: Range<usize>, with: &str) -> String {
    format!("{}{with}{}", &xml[..range.start], &xml[range.end..])
}

fn client(m: &str) -> Result<Elem, String> {
    find(m, "client", 0..m.len()).ok_or_else(|| "ossec.conf has no <client> section".to_owned())
}

fn read_agent_name(xml: &str) -> Option<String> {
    let m = mask_comments(xml);
    let c = client(&m).ok()?;
    let scope = find(&m, "enrollment", c.inner.clone()).map_or(c.inner, |e| e.inner);
    let e = find(&m, "agent_name", scope)?;
    Some(xml[e.inner].trim().to_owned()).filter(|s| !s.is_empty())
}

fn set_agent_name(xml: &str, name: &str) -> Result<String, String> {
    if !identity::is_valid_name(name) {
        return Err(format!("refusing invalid agent name {name:?}"));
    }
    let m = mask_comments(xml);
    let c = client(&m)?;
    let tag = format!("<agent_name>{name}</agent_name>");
    let Some(en) = find(&m, "enrollment", c.inner.clone()) else {
        let block = format!("  <enrollment>\n      {tag}\n    </enrollment>\n  ");
        return Ok(splice(xml, c.inner.end..c.inner.end, &block));
    };
    if let Some(e) = find(&m, "agent_name", en.inner.clone()) {
        return Ok(if xml[e.inner.clone()].trim() == name {
            xml.to_owned()
        } else {
            splice(xml, e.start..e.end, &tag)
        });
    }
    if en.end == en.open_end {
        let block = format!("<enrollment>\n      {tag}\n    </enrollment>");
        return Ok(splice(xml, en.start..en.end, &block));
    }
    Ok(splice(
        xml,
        en.open_end..en.open_end,
        &format!("\n      {tag}"),
    ))
}

fn label_elem(m: &str, key: &str) -> Option<Elem> {
    let attrs = [format!("key=\"{key}\""), format!("key='{key}'")];
    find_all(m, "labels", 0..m.len())
        .into_iter()
        .flat_map(|l| find_all(m, "label", l.inner))
        .find(|e| {
            attrs
                .iter()
                .any(|a| m[e.start..e.open_end].contains(a.as_str()))
        })
}

fn set_label(xml: &str, key: &str, value: &str) -> Result<String, String> {
    if !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!("refusing invalid label value {value:?}"));
    }
    let m = mask_comments(xml);
    let label = format!("<label key=\"{key}\">{value}</label>");
    if let Some(e) = label_elem(&m, key) {
        return Ok(if xml[e.inner.clone()].trim() == value {
            xml.to_owned()
        } else {
            splice(xml, e.start..e.end, &label)
        });
    }
    if let Some(l) = find(&m, "labels", 0..m.len()).filter(|l| l.end != l.open_end) {
        return Ok(splice(
            xml,
            l.open_end..l.open_end,
            &format!("\n    {label}"),
        ));
    }
    let close = m
        .find("</ossec_config>")
        .ok_or("ossec.conf has no </ossec_config>")?;
    let block = format!("  <labels>\n    {label}\n  </labels>\n");
    Ok(splice(xml, close..close, &block))
}

/// `(address, port)` of every `<client><server>` block.
fn manager_endpoints(xml: &str) -> Vec<(String, u16)> {
    let m = mask_comments(xml);
    let Ok(c) = client(&m) else {
        return Vec::new();
    };
    find_all(&m, "server", c.inner)
        .into_iter()
        .filter_map(|b| {
            let addr = find(&m, "address", b.inner.clone())?;
            let port = find(&m, "port", b.inner)
                .and_then(|p| xml[p.inner].trim().parse().ok())
                .unwrap_or(1514);
            Some((xml[addr.inner].trim().to_owned(), port))
        })
        .filter(|(a, _)| !a.is_empty())
        .collect()
}

/// Name from the first valid `ID NAME IP KEY` line of client.keys.
fn enrolled_name(keys: &str) -> Option<String> {
    keys.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let (id, name) = (f.next()?, f.next()?);
        let valid = id.bytes().all(|b| b.is_ascii_digit())
            && !name.starts_with(['#', '!'])
            && f.next().is_some()
            && f.next().is_some();
        valid.then(|| name.to_owned())
    })
}

/// `status='connected'` from wazuh-agentd.state.
fn state_status(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("status="))
        .map(|v| v.trim().trim_matches(['\'', '"']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = r#"<!-- Wazuh - Agent - Default configuration -->
<ossec_config>
  <client>
    <server>
      <address>10.0.0.5</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <!-- <enrollment><agent_name>commented</agent_name></enrollment> -->
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>OLD</agent_name>
      <groups>default</groups>
    </enrollment>
  </client>
  <labels>
    <label key="aws.instance-id">i-123</label>
  </labels>
</ossec_config>
"#;

    const BARE: &str = "<ossec_config>\n  <client>\n    <server>\n      <address>mgr.corp</address>\n    </server>\n  </client>\n</ossec_config>\n";

    #[test]
    fn edits_v4_config() {
        assert_eq!(read_agent_name(V4).as_deref(), Some("OLD"));
        let x = set_agent_name(V4, "PC-0a1b2c3d4e5f").unwrap();
        assert_eq!(read_agent_name(&x).as_deref(), Some("PC-0a1b2c3d4e5f"));
        assert!(
            x.contains("<agent_name>commented</agent_name>"),
            "comments untouched"
        );
        let x = set_label(&x, LABEL_KEY, "abc123").unwrap();
        assert!(x.contains("<label key=\"harrier_hwid\">abc123</label>"));
        assert!(x.contains("i-123"));
        // Idempotent: applying again changes nothing.
        let again = set_label(
            &set_agent_name(&x, "PC-0a1b2c3d4e5f").unwrap(),
            LABEL_KEY,
            "abc123",
        )
        .unwrap();
        assert_eq!(again, x);
        // Value change replaces in place.
        let y = set_label(&x, LABEL_KEY, "def456").unwrap();
        assert!(y.contains(">def456<") && !y.contains("abc123"));
        assert_eq!(manager_endpoints(V4), vec![("10.0.0.5".to_owned(), 1514)]);
    }

    #[test]
    fn edits_config_without_blocks() {
        assert_eq!(read_agent_name(BARE), None);
        let x = set_label(
            &set_agent_name(BARE, "SRV-0a1b2c3d4e5f").unwrap(),
            LABEL_KEY,
            "ff",
        )
        .unwrap();
        assert_eq!(read_agent_name(&x).as_deref(), Some("SRV-0a1b2c3d4e5f"));
        assert!(x.contains("<labels>") && x.trim_end().ends_with("</ossec_config>"));
        assert_eq!(manager_endpoints(BARE), vec![("mgr.corp".to_owned(), 1514)]);
        assert!(set_agent_name(BARE, "bad name").is_err());
        assert!(set_agent_name("<ossec_config/>", "X-1").is_err());
        let self_closing = BARE.replace("</server>", "</server><enrollment/>");
        let x = set_agent_name(&self_closing, "A-1").unwrap();
        assert_eq!(read_agent_name(&x).as_deref(), Some("A-1"));
    }

    #[test]
    fn agent_files() {
        assert_eq!(
            enrolled_name("001 PC-0a1b2c3d4e5f any 4e3c...\n").as_deref(),
            Some("PC-0a1b2c3d4e5f")
        );
        assert_eq!(enrolled_name(""), None);
        assert_eq!(enrolled_name("garbage\n"), None);
        let state = "# State file\nstatus='connected'\nlast_keepalive='2026-10-04 10:00:00'\n";
        assert_eq!(state_status(state).as_deref(), Some("connected"));
        assert_eq!(state_status("x"), None);
    }

    #[test]
    fn package_versions() {
        for ok in [
            "wazuh-agent_4.14.9-1_amd64.deb",
            "wazuh-agent-4.9.2-1.i386.rpm",
            "wazuh-agent-4.14.9-1.msi",
            "custom-build.msi",
        ] {
            assert!(supported_package(ok).is_ok(), "{ok}");
        }
        for bad in [
            "wazuh-agent_5.0.0-1_amd64.deb",
            "wazuh-agent-4.15.0-1.msi",
            "wazuh-agent-3.13.6-1.x86_64.rpm",
        ] {
            assert!(supported_package(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn option_validation() {
        assert!(validate_option("manager", "10.0.0.5,mgr-2.corp").is_ok());
        assert!(validate_option("manager", "x;rm -rf").is_err());
        assert!(validate_option("group", "it,windows").is_ok());
        assert!(validate_option("group", "it dept").is_err());
    }
}
