//! Server side: the only part of harrier that holds Wazuh API credentials.
//!
//! - duplicate records of the same hardware (rename, clone, re-image,
//!   lost key) -> keep the best one, delete the inactive rest;
//! - legacy plain-hostname records superseded by a harrier name;
//! - stale records (disconnected / never connected for N days);
//! - groups are carried over to the surviving record before the old one
//!   is deleted (make-before-break, server stays the source of truth).
//!
//! HTTPS goes through the system `curl` (TLS without linking a TLS stack).
//! Credentials and tokens are passed on curl's stdin, never on its argv.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;

use crate::identity::{is_valid_name, parse_name};
use crate::json::Json;
use crate::{Config, Level, log, notify, sha256, sys};

pub const CONFIG_FILE: &str = "server.conf";
pub const SERVICE: &str = "harrier-reconcile";
const PAGE: usize = 500;
const DELETE_BATCH: usize = 100;
const DEFAULT_CERTS: [&str; 2] = [
    "/var/ossec/api/configuration/ssl/server.crt",
    "/var/wazuh-manager/api/configuration/ssl/server.crt",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentRec {
    pub id: String,
    pub name: String,
    pub status: String,
    pub last_keepalive: String,
    pub groups: Vec<String>,
}

impl AgentRec {
    fn active(&self) -> bool {
        self.status == "active"
    }

    fn rank(&self) -> (u8, String, u64) {
        let s = match self.status.as_str() {
            "active" => 3,
            "pending" => 2,
            "disconnected" => 1,
            _ => 0,
        };
        (s, self.last_keepalive.clone(), self.id.parse().unwrap_or(0))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Regroup {
        id: String,
        name: String,
        groups: Vec<String>,
        from: String,
    },
    Delete {
        id: String,
        name: String,
        reason: String,
        /// Only delete once this keeper got the groups carried over.
        after_regroup_of: Option<String>,
    },
}

#[derive(Debug, Default)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub warnings: Vec<String>,
}

fn default_only(groups: &[String]) -> bool {
    groups.iter().all(|g| g == "default")
}

pub fn plan(all: &[AgentRec], stale: &[AgentRec]) -> Plan {
    let mut p = Plan::default();
    let mut regrouped = HashSet::new();
    let mut deleting = HashSet::new();
    let mut supersede = |p: &mut Plan, keeper: &AgentRec, old: &AgentRec, reason: String| {
        if !deleting.insert(old.id.clone()) {
            return;
        }
        let mut link = regrouped.contains(&keeper.id).then(|| keeper.id.clone());
        if link.is_none() && default_only(&keeper.groups) && !default_only(&old.groups) {
            p.actions.push(Action::Regroup {
                id: keeper.id.clone(),
                name: keeper.name.clone(),
                groups: old.groups.clone(),
                from: old.id.clone(),
            });
            regrouped.insert(keeper.id.clone());
            link = Some(keeper.id.clone());
        }
        p.actions.push(Action::Delete {
            id: old.id.clone(),
            name: old.name.clone(),
            reason,
            after_regroup_of: link,
        });
    };

    // One machine = one firmware id. Records sharing it are the same
    // machine re-enrolled (rename, re-image, lost key, new network cards).
    let mut by_fw: BTreeMap<&str, Vec<&AgentRec>> = BTreeMap::new();
    for a in all {
        if let Some(n) = parse_name(&a.name) {
            by_fw.entry(n.fwid).or_default().push(a);
        }
    }
    for (fw, mut same) in by_fw {
        if same.len() < 2 {
            continue;
        }
        same.sort_by_key(|a| Reverse(a.rank()));
        let live: Vec<&str> = same
            .iter()
            .filter(|a| a.active())
            .map(|a| a.name.as_str())
            .collect();
        if live.len() > 1 {
            p.warnings.push(format!(
                "machine {fw}: {} agents active at once ({}); VM cloned without a new BIOS UUID? left untouched",
                live.len(),
                live.join(", ")
            ));
        }
        let keeper = same[0];
        let keeper_hw = parse_name(&keeper.name).map(|n| n.hwid);
        for old in same[1..].iter().filter(|a| !a.active()) {
            let what = if parse_name(&old.name).map(|n| n.hwid) == keeper_hw {
                "duplicate of"
            } else {
                "network cards changed, now"
            };
            let reason = format!("{what} {} ({})", keeper.name, keeper.id);
            supersede(&mut p, keeper, old, reason);
        }
    }

    let live_hosts: HashMap<String, &AgentRec> = all
        .iter()
        .filter(|a| a.active())
        .filter_map(|a| parse_name(&a.name).map(|n| (n.host.to_ascii_lowercase(), a)))
        .collect();
    for old in all
        .iter()
        .filter(|a| !a.active() && parse_name(&a.name).is_none())
    {
        if let Some(keeper) = live_hosts.get(&old.name.to_ascii_lowercase()) {
            let reason = format!("legacy name, now {} ({})", keeper.name, keeper.id);
            supersede(&mut p, keeper, old, reason);
        }
    }

    for old in stale {
        if deleting.insert(old.id.clone()) {
            let seen = if old.last_keepalive.is_empty() {
                "never".to_owned()
            } else {
                old.last_keepalive.clone()
            };
            p.actions.push(Action::Delete {
                id: old.id.clone(),
                name: old.name.clone(),
                reason: format!("stale: {}, last seen {seen}", old.status),
                after_regroup_of: None,
            });
        }
    }
    p
}

// ------------------------------------------------------------------ API ----

pub struct Api {
    base: String,
    tls: Vec<String>,
    user: String,
    password: String,
    token: String,
}

impl Api {
    pub fn connect(cfg: &Config) -> Result<Self, String> {
        let need = |k: &str| {
            cfg.get(k).map(str::to_owned).ok_or_else(|| {
                format!(
                    "{k} is not set in {}; run `harrier setup-server`",
                    cfg.path.display()
                )
            })
        };
        let base = need("api_url")?.trim_end_matches('/').to_owned();
        if !base.starts_with("https://") || base.contains(char::is_whitespace) {
            return Err(format!("api_url must be an https:// URL (got {base:?})"));
        }
        let mut tls = Vec::new();
        if cfg.flag("api_insecure")? {
            if cfg.get("api_pin").is_some() || cfg.get("api_ca_file").is_some() {
                return Err("api_insecure cannot be combined with api_pin or api_ca_file".into());
            }
            notify(
                Level::Warn,
                "TLS verification is DISABLED (api_insecure): anyone who can intercept this \
                 traffic can steal the API password. api_pin also works with self-signed \
                 certificates and is safe.",
            );
            tls.push("-k".to_owned());
        }
        if let Some(ca) = cfg.get("api_ca_file") {
            tls.extend(["--cacert".to_owned(), ca.to_owned()]);
        }
        if let Some(pin) = cfg.get("api_pin") {
            if !pin.starts_with("sha256//") || pin.contains(char::is_whitespace) {
                return Err("api_pin must look like sha256//BASE64".into());
            }
            if cfg.get("api_ca_file").is_none() {
                // Self-signed API certificate: trust exactly this key.
                tls.push("-k".to_owned());
            }
            tls.extend(["--pinnedpubkey".to_owned(), pin.to_owned()]);
        }
        let mut api = Self {
            base,
            tls,
            user: need("api_user")?,
            password: need("api_password")?,
            token: String::new(),
        };
        api.login()?;
        Ok(api)
    }

    fn login(&mut self) -> Result<(), String> {
        let (code, body) = self.curl("POST", "/security/user/authenticate?raw=true", true)?;
        let token = body.trim();
        match code {
            200 if !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) =>
            {
                token.clone_into(&mut self.token);
                Ok(())
            }
            401 => Err(format!(
                "Wazuh API rejected the credentials of {:?}",
                self.user
            )),
            c => Err(format!(
                "Wazuh API login failed: HTTP {c}: {}",
                snippet(&body)
            )),
        }
    }

    fn curl(&self, method: &str, path: &str, basic: bool) -> Result<(u16, String), String> {
        let mut conf = format!(
            "url = \"{}\"\nrequest = \"{method}\"\n",
            quote(&format!("{}{path}", self.base))?
        );
        if basic {
            let creds = quote(&format!("{}:{}", self.user, self.password))?;
            let _ = writeln!(conf, "user = \"{creds}\"");
        } else {
            let _ = writeln!(conf, "header = \"Authorization: Bearer {}\"", self.token);
        }
        let args = [
            "-sS",
            "--proto",
            "=https",
            "--connect-timeout",
            "10",
            "--max-time",
            "300",
            "-w",
            "\n%{http_code}",
            "-K",
            "-",
        ];
        let mut child = sys::command("curl")
            .args(args)
            .args(&self.tls)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run curl (is it installed?): {e}"))?;
        child
            .stdin
            .take()
            .ok_or("curl: no stdin")?
            .write_all(conf.as_bytes())
            .map_err(|e| format!("curl: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{method} {}{path}: {}",
                self.base,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let (body, code) = text.rsplit_once('\n').ok_or("curl: unexpected output")?;
        let code = code.trim().parse().map_err(|_| "curl: no HTTP status")?;
        Ok((code, body.to_owned()))
    }

    pub fn call(&mut self, method: &str, path: &str) -> Result<Json, String> {
        let mut r = self.curl(method, path, false)?;
        if r.0 == 401 {
            self.login()?;
            r = self.curl(method, path, false)?;
        }
        if r.0 != 200 {
            return Err(format!("{method} {path}: HTTP {}: {}", r.0, snippet(&r.1)));
        }
        Json::parse(&r.1)
    }
}

fn quote(s: &str) -> Result<String, String> {
    if s.contains(['\n', '\r']) {
        return Err("API settings must not contain line breaks".into());
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn snippet(s: &str) -> String {
    s.chars().take(300).collect::<String>().trim().to_owned()
}

fn list(api: &mut Api, filter: &str) -> Result<Vec<AgentRec>, String> {
    let mut out = Vec::new();
    let mut offset = 0;
    loop {
        let j = api.call(
            "GET",
            &format!(
                "/agents?select=id,name,status,lastKeepAlive,group&sort=%2Bid&limit={PAGE}&offset={offset}{filter}"
            ),
        )?;
        let data = j.get("data");
        let items = data.get("affected_items").as_array();
        out.extend(
            items
                .iter()
                .map(|a| AgentRec {
                    id: a.get("id").as_str().unwrap_or_default().to_owned(),
                    name: a.get("name").as_str().unwrap_or_default().to_owned(),
                    status: a.get("status").as_str().unwrap_or_default().to_owned(),
                    last_keepalive: a
                        .get("lastKeepAlive")
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    groups: a
                        .get("group")
                        .as_array()
                        .iter()
                        .filter_map(Json::as_str)
                        .map(str::to_owned)
                        .collect(),
                })
                // 000 is the manager itself; ids are always numeric.
                .filter(|a| {
                    a.id != "000" && !a.id.is_empty() && a.id.bytes().all(|b| b.is_ascii_digit())
                }),
        );
        offset += items.len();
        let total = data.get("total_affected_items").as_u64().unwrap_or(0);
        if items.is_empty() || offset as u64 >= total {
            return Ok(out);
        }
    }
}

fn failures(j: &Json) -> Vec<String> {
    j.get("data")
        .get("failed_items")
        .as_array()
        .iter()
        .map(|f| {
            let ids: Vec<&str> = f
                .get("id")
                .as_array()
                .iter()
                .filter_map(Json::as_str)
                .collect();
            format!(
                "{}: {}",
                ids.join(","),
                f.get("error").get("message").as_str().unwrap_or("failed")
            )
        })
        .collect()
}

fn apply(api: &mut Api, plan: &Plan, max_delete: u64) -> Result<(), String> {
    let deletes = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Delete { .. }))
        .count();
    if deletes as u64 > max_delete {
        return Err(format!(
            "refusing to delete {deletes} agents in one run (max_delete = {max_delete}); \
             review `harrier reconcile` and raise max_delete if this is intended"
        ));
    }

    let mut failed = HashSet::new();
    let mut ids = Vec::new();
    for action in &plan.actions {
        match action {
            Action::Regroup {
                id, name, groups, ..
            } => {
                let result = groups.iter().enumerate().try_for_each(|(i, g)| {
                    if !is_valid_name(g) {
                        return Err(format!("invalid group name {g:?}"));
                    }
                    let single = if i == 0 {
                        "?force_single_group=true"
                    } else {
                        ""
                    };
                    let j = api.call("PUT", &format!("/agents/{id}/group/{g}{single}"))?;
                    let f = failures(&j);
                    if f.is_empty() {
                        Ok(())
                    } else {
                        Err(f.join("; "))
                    }
                });
                match result {
                    Ok(()) => notify(
                        Level::Info,
                        &format!(
                            "case H: {name} ({id}) assigned to groups {}",
                            groups.join(",")
                        ),
                    ),
                    Err(e) => {
                        notify(
                            Level::Error,
                            &format!("group carry-over to {name} ({id}) failed: {e}"),
                        );
                        failed.insert(id.clone());
                    }
                }
            }
            Action::Delete {
                id,
                after_regroup_of,
                ..
            } => {
                if after_regroup_of
                    .as_ref()
                    .is_none_or(|k| !failed.contains(k))
                {
                    ids.push(id.clone());
                }
            }
        }
    }

    for chunk in ids.chunks(DELETE_BATCH) {
        let j = api.call(
            "DELETE",
            &format!(
                "/agents?agents_list={}&status=all&older_than=0s",
                chunk.join(",")
            ),
        )?;
        let gone: Vec<&str> = j
            .get("data")
            .get("affected_items")
            .as_array()
            .iter()
            .filter_map(Json::as_str)
            .collect();
        if !gone.is_empty() {
            notify(Level::Info, &format!("deleted agents {}", gone.join(",")));
        }
        for f in failures(&j) {
            notify(Level::Error, &format!("delete failed for {f}"));
        }
    }
    Ok(())
}

pub fn run(cfg: &Config, apply_changes: bool) -> Result<(), String> {
    let mut api = Api::connect(cfg)?;
    let all = list(&mut api, "")?;
    let protect: Vec<&str> = cfg
        .get("protect_groups")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .collect();
    let mut stale = Vec::new();
    for (status, key, default) in [
        ("disconnected", "disconnected_days", 30),
        ("never_connected", "never_connected_days", 7),
    ] {
        let days = cfg.num(key, default)?;
        if days > 0 {
            stale.extend(
                list(&mut api, &format!("&status={status}&older_than={days}d"))?
                    .into_iter()
                    .filter(|a| !a.groups.iter().any(|g| protect.contains(&g.as_str()))),
            );
        }
    }

    let p = plan(&all, &stale);
    println!(
        "harrier reconcile: {} agents, {} actions",
        all.len(),
        p.actions.len()
    );
    for a in &p.actions {
        match a {
            Action::Regroup {
                id,
                name,
                groups,
                from,
            } => println!(
                "  REGROUP {id:>6} {name}: groups {} (carried over from {from})",
                groups.join(",")
            ),
            Action::Delete {
                id, name, reason, ..
            } => println!("  DELETE  {id:>6} {name}: {reason}"),
        }
    }
    for w in &p.warnings {
        notify(Level::Warn, w);
    }
    if apply_changes {
        apply(&mut api, &p, cfg.num("max_delete", 50)?)
    } else {
        if !p.actions.is_empty() {
            println!("dry-run: nothing changed; re-run with --apply");
        }
        Ok(())
    }
}

pub fn setup_server(opts: &BTreeMap<String, String>, mut cfg: Config) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate harrier: {e}"))?;
    sys::install_self(&exe)?;

    for (opt, value) in opts
        .iter()
        .filter(|(k, _)| k.as_str() != "config" && k.as_str() != "api-cert")
    {
        if opt.ends_with("-days") || opt == "max-delete" {
            value
                .parse::<u64>()
                .map_err(|_| format!("--{opt} must be a number"))?;
        }
        cfg.set(&opt.replace('-', "_"), value);
    }
    if let Ok(pass) = std::env::var("HARRIER_API_PASSWORD") {
        cfg.set("api_password", pass.trim());
    }
    if cfg.get("api_password").is_none() {
        return Err("set the API password in env HARRIER_API_PASSWORD".into());
    }
    let verify_opts = ["api-pin", "api-ca-file", "api-cert"];
    if cfg.flag("api_insecure")? {
        if verify_opts.iter().any(|o| opts.contains_key(*o)) {
            return Err(
                "--api-insecure cannot be combined with --api-pin/--api-ca-file/--api-cert".into(),
            );
        }
        cfg.remove("api_pin");
        cfg.remove("api_ca_file");
    } else {
        cfg.remove("api_insecure");
    }
    let cert = opts.get("api-cert").map(String::as_str).or_else(|| {
        (!cfg.flag("api_insecure").unwrap_or(false)
            && cfg.get("api_ca_file").is_none()
            && cfg.get("api_pin").is_none())
        .then(|| DEFAULT_CERTS.into_iter().find(|c| Path::new(c).is_file()))
        .flatten()
    });
    if let Some(cert) = cert {
        let pem = std::fs::read_to_string(cert).map_err(|e| format!("cannot read {cert}: {e}"))?;
        cfg.set("api_pin", spki_pin(&pem)?);
        log(
            Level::Info,
            &format!("pinned the API certificate key from {cert}"),
        );
    }
    for (k, v) in [
        ("disconnected_days", 30),
        ("never_connected_days", 7),
        ("max_delete", 50),
    ] {
        if cfg.get(k).is_none() {
            cfg.set(k, v);
        }
    }
    // Verify (and show the dry-run) before persisting anything.
    run(&cfg, false)?;
    cfg.save(0o600)?;
    let service = sys::install_daemon(
        SERVICE,
        "Harrier Reconciler - Wazuh inventory hygiene",
        &crate::service_args("reconcile", &cfg, CONFIG_FILE)?,
    )?;
    println!("config:  {} (mode 600)", cfg.path.display());
    println!("service: {service}");
    Ok(())
}

// -------------------------------------------------- certificate pinning ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = B64
            .iter()
            .position(|&x| x == c)
            .ok_or("bad base64 in certificate")?;
        acc = (acc << 6) | u32::try_from(v).unwrap_or(0);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One DER element: tag, the whole TLV, its content, and what follows it.
struct Tlv<'a> {
    tag: u8,
    whole: &'a [u8],
    content: &'a [u8],
    rest: &'a [u8],
}

fn der_next(b: &[u8]) -> Result<Tlv<'_>, String> {
    const BAD: &str = "malformed certificate";
    let (&tag, rest) = b.split_first().ok_or(BAD)?;
    let (&l0, rest) = rest.split_first().ok_or(BAD)?;
    let (len, rest) = if l0 < 0x80 {
        (usize::from(l0), rest)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return Err(BAD.into());
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(BAD.into());
    }
    let header = b.len() - rest.len();
    Ok(Tlv {
        tag,
        whole: &b[..header + len],
        content: &rest[..len],
        rest: &rest[len..],
    })
}

/// curl `--pinnedpubkey` value (`sha256//` + base64 SHA-256 of the
/// `SubjectPublicKeyInfo`) for a PEM certificate.
pub fn spki_pin(pem: &str) -> Result<String, String> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = b64_decode(&body)?;
    let cert = der_next(&der)?.content;
    let mut rest = der_next(cert)?.content; // tbsCertificate
    let first = der_next(rest)?;
    if first.tag == 0xA0 {
        rest = first.rest; // explicit version
    }
    for _ in 0..5 {
        rest = der_next(rest)?.rest; // serial, signature, issuer, validity, subject
    }
    let spki = der_next(rest)?;
    if spki.tag != 0x30 {
        return Err("certificate has no public key".into());
    }
    Ok(format!(
        "sha256//{}",
        b64_encode(&sha256::digest(spki.whole))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, name: &str, status: &str, seen: &str, groups: &[&str]) -> AgentRec {
        AgentRec {
            id: id.into(),
            name: name.into(),
            status: status.into(),
            last_keepalive: seen.into(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        }
    }

    fn deleted(p: &Plan) -> Vec<&str> {
        p.actions
            .iter()
            .filter_map(|a| match a {
                Action::Delete { id, .. } => Some(id.as_str()),
                Action::Regroup { .. } => None,
            })
            .collect()
    }

    #[test]
    fn rename_keeps_new_record_and_carries_groups() {
        let all = [
            rec(
                "010",
                "OLDNAME-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "disconnected",
                "2026-10-01T00:00:00+00:00",
                &["finance"],
            ),
            rec(
                "042",
                "NEWNAME-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "active",
                "2026-10-04T00:00:00+00:00",
                &["default"],
            ),
            rec(
                "043",
                "OTHER-111111111111-f11111111111",
                "active",
                "2026-10-04T00:00:00+00:00",
                &[],
            ),
        ];
        let p = plan(&all, &[]);
        assert_eq!(
            p.actions,
            vec![
                Action::Regroup {
                    id: "042".into(),
                    name: "NEWNAME-0a1b2c3d4e5f-fa1b2c3d4e5f".into(),
                    groups: vec!["finance".into()],
                    from: "010".into()
                },
                Action::Delete {
                    id: "010".into(),
                    name: "OLDNAME-0a1b2c3d4e5f-fa1b2c3d4e5f".into(),
                    reason: "duplicate of NEWNAME-0a1b2c3d4e5f-fa1b2c3d4e5f (042)".into(),
                    after_regroup_of: Some("042".into())
                },
            ]
        );
    }

    #[test]
    fn never_deletes_active_and_warns_on_live_clones() {
        let all = [
            rec(
                "001",
                "A-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "active",
                "2026-10-04T00:00:00+00:00",
                &[],
            ),
            rec(
                "002",
                "B-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "active",
                "2026-10-04T00:00:01+00:00",
                &[],
            ),
            rec(
                "003",
                "C-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "never_connected",
                "",
                &[],
            ),
        ];
        let p = plan(&all, &[]);
        assert_eq!(deleted(&p), vec!["003"]);
        assert_eq!(p.warnings.len(), 1);
    }

    #[test]
    fn new_network_cards_replace_old_record() {
        // Same firmware id, different hardware id: the old record goes.
        let all = [
            rec(
                "030",
                "SRV-0a1b2c3d4e5f-77a1c0de9f31",
                "disconnected",
                "2026-10-01T00:00:00+00:00",
                &["dc"],
            ),
            rec(
                "031",
                "SRV-9e8d7c6b5a49-77a1c0de9f31",
                "active",
                "2026-10-04T00:00:00+00:00",
                &["default"],
            ),
        ];
        let p = plan(&all, &[]);
        assert_eq!(deleted(&p), vec!["030"]);
        assert!(p.actions.iter().any(|a| matches!(a,
            Action::Delete { reason, .. } if reason.starts_with("network cards changed"))));
        assert!(p.actions.iter().any(
            |a| matches!(a, Action::Regroup { groups, .. } if groups == &vec!["dc".to_owned()])
        ));
    }

    #[test]
    fn reinstall_keeps_most_recent_and_legacy_and_stale() {
        let all = [
            rec(
                "005",
                "PC-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "disconnected",
                "2026-09-01T00:00:00+00:00",
                &[],
            ),
            rec(
                "009",
                "PC-0a1b2c3d4e5f-fa1b2c3d4e5f",
                "disconnected",
                "2026-10-01T00:00:00+00:00",
                &[],
            ),
            rec(
                "011",
                "laptop7",
                "disconnected",
                "2026-01-01T00:00:00+00:00",
                &["it"],
            ),
            rec(
                "012",
                "LAPTOP7-ffffffffffff-ffffffffffff",
                "active",
                "2026-10-04T00:00:00+00:00",
                &["it"],
            ),
            rec(
                "020",
                "printer",
                "disconnected",
                "2025-01-01T00:00:00+00:00",
                &[],
            ),
        ];
        let stale = [all[4].clone(), all[0].clone()];
        let p = plan(&all, &stale);
        assert_eq!(deleted(&p), vec!["005", "011", "020"]);
        assert!(
            !p.actions
                .iter()
                .any(|a| matches!(a, Action::Regroup { .. })),
            "keeper already grouped"
        );
    }

    #[test]
    fn pins_match_openssl() {
        assert_eq!(
            spki_pin(include_str!("../testdata/ec.crt")).unwrap(),
            "sha256//NokcMaPkwrzOK+U8v3Ton8KnrHQbnvyaeQaFStL6+sw="
        );
        assert_eq!(
            spki_pin(include_str!("../testdata/rsa.crt")).unwrap(),
            "sha256//W1I+E4wC0k1Sm5yHAmN/4wrTmMQ0y/KsSVrMsEKEymU="
        );
        assert!(spki_pin("garbage").is_err());
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");
    }

    #[test]
    fn curl_config_quoting() {
        assert_eq!(quote(r#"p"a\ss"#).unwrap(), r#"p\"a\\ss"#);
        assert!(quote("a\nurl = \"http://evil\"").is_err());
    }
}
