//! Everything that differs between Windows and Linux.
//!
//! Only `cfg(windows)` / `cfg(not(windows))` are used and the Windows side
//! avoids `std::os::windows`, so `--cfg windows` can type-check it on Linux.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Level;

#[derive(Debug, Clone, Copy)]
pub enum Service {
    Stop,
    Start,
    Restart,
}

/// Run a system tool and return stdout, or an error carrying its output.
pub fn run(program: &str, args: &[&str]) -> Result<String, String> {
    run_cmd(command(program).args(args), program, args, &[0])
}

fn run_cmd(cmd: &mut Command, program: &str, args: &[&str], ok: &[i32]) -> Result<String, String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.code().is_some_and(|c| ok.contains(&c)) {
        return Ok(stdout);
    }
    let detail = format!("{} {stdout}", String::from_utf8_lossy(&out.stderr));
    Err(format!(
        "{program} {} failed ({}): {}",
        args.join(" "),
        out.status,
        detail.trim()
    ))
}

#[cfg(not(windows))]
fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Copy the running binary to its fixed install location (idempotent).
/// That location runs as root/SYSTEM, so it must not be writable by others.
pub fn install_self(exe: &Path) -> Result<PathBuf, String> {
    let dir = install_dir();
    create_dir(&dir)?;
    check_owner(&dir, false)?;
    let target = dir.join(BIN_NAME);
    let data = fs::read(exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    if fs::read(&target).ok().as_deref() != Some(data.as_slice()) {
        write_bytes(&target, &data, 0o755)?;
    }
    Ok(target)
}

/// Create a directory harrier owns (0755 regardless of umask); existing
/// directories are left as they are.
pub fn create_dir(dir: &Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    set_mode(dir, 0o755)
}

pub fn write_file(path: &Path, content: &str, mode: u32) -> Result<(), String> {
    write_bytes(path, content.as_bytes(), mode)
}

/// Atomic write: a fresh temp file created with its final mode (a secret is
/// never readable by others, not even briefly), then renamed into place.
pub fn write_bytes(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        create_dir(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".harrier-tmp");
    let tmp = PathBuf::from(tmp);
    let fail = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
    let _ = fs::remove_file(&tmp);
    let mut f = new_file(&tmp, mode).map_err(fail)?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(fail)?;
    drop(f);
    set_mode(&tmp, mode)?;
    fs::rename(&tmp, path).map_err(fail)
}

#[cfg(not(windows))]
fn new_file(path: &Path, mode: u32) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

#[cfg(windows)]
fn new_file(path: &Path, _mode: u32) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

// ---------------------------------------------------------------- Linux ----

/// No `/usr/local`: on some Debian systems it is writable by group `staff`.
#[cfg(not(windows))]
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
#[cfg(not(windows))]
const BIN_NAME: &str = "harrier";
#[cfg(not(windows))]
const UNIT_DIR: &str = "/etc/systemd/system";

/// Tools are resolved through a fixed PATH, never the caller's.
#[cfg(not(windows))]
pub fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env("PATH", SAFE_PATH).env("LC_ALL", "C");
    c
}

#[cfg(not(windows))]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

#[cfg(not(windows))]
pub fn install_dir() -> PathBuf {
    PathBuf::from("/opt/harrier")
}

#[cfg(not(windows))]
pub fn config_dir() -> PathBuf {
    PathBuf::from("/etc/harrier")
}

#[cfg(not(windows))]
pub fn data_dir() -> PathBuf {
    PathBuf::from("/var/lib/harrier")
}

#[cfg(not(windows))]
pub fn default_agent_dir() -> PathBuf {
    PathBuf::from("/var/ossec")
}

#[cfg(not(windows))]
pub const AGENT_FILES: AgentFiles = AgentFiles {
    ossec_conf: "etc/ossec.conf",
    client_keys: "etc/client.keys",
    authd_pass: "etc/authd.pass",
    state: "var/run/wazuh-agentd.state",
};

#[cfg(not(windows))]
pub fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
        .or_else(|| read_trimmed("/etc/hostname"))
        .unwrap_or_default()
}

/// SMBIOS system UUID and serial. These files are root-only: a permission
/// error is fatal, because silently falling back would change the identity.
#[cfg(not(windows))]
pub fn smbios_ids() -> Result<(Option<String>, Option<String>), String> {
    let read = |name: &str| {
        let path = format!("/sys/class/dmi/id/{name}");
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {path}: {e} (run harrier as root)")),
        }
    };
    Ok((read("product_uuid")?, read("product_serial")?))
}

/// Burned-in MACs of physical, non-USB Ethernet/Wi-Fi interfaces.
#[cfg(not(windows))]
pub fn nic_macs() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("device").exists())
        .filter(|p| {
            let real = fs::canonicalize(p).unwrap_or_default();
            let real = real.to_string_lossy();
            !real.contains("/usb") && !real.contains("/virtual/")
        })
        .filter(|p| read_trimmed(p.join("type")).as_deref() == Some("1"))
        // NET_ADDR_PERM only: skips random/spoofed/stolen addresses.
        .filter(|p| {
            matches!(
                read_trimmed(p.join("addr_assign_type")).as_deref(),
                None | Some("0")
            )
        })
        .filter_map(|p| read_trimmed(p.join("address")))
        .collect()
}

#[cfg(not(windows))]
pub fn machine_id() -> Option<String> {
    read_trimmed("/etc/machine-id").or_else(|| read_trimmed("/var/lib/dbus/machine-id"))
}

#[cfg(not(windows))]
fn has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

#[cfg(not(windows))]
pub fn service(agent_dir: &Path, action: Service) -> Result<(), String> {
    let verb = match action {
        Service::Stop => "stop",
        Service::Start => "start",
        Service::Restart => "restart",
    };
    let control = agent_dir.join("bin/wazuh-control");
    let control = control.to_string_lossy();
    if !has_systemd() {
        return run(&control, &[verb]).map(drop);
    }
    if !matches!(action, Service::Start) {
        let _ = run("systemctl", &["stop", "wazuh-agent"]);
        // A stop that races the agent's own reload (new shared config from
        // the manager) can leave wazuh-agentd running outside the unit; the
        // next start then keeps it, with its old key. Stop what is left.
        let _ = run(&control, &["stop"]);
        if matches!(action, Service::Stop) {
            return Ok(());
        }
    }
    // A stopped agent may also have been disabled by a user.
    let _ = run("systemctl", &["enable", "wazuh-agent"]);
    run("systemctl", &["start", "wazuh-agent"]).map(drop)
}

/// Install or upgrade the Wazuh agent from a `.deb`/`.rpm`; the vendor
/// scripts read the `WAZUH_*` variables (empty on upgrade: config is kept).
#[cfg(not(windows))]
pub fn install_package(
    pkg: &Path,
    vars: &[(&str, String)],
    agent_dir: &Path,
) -> Result<(), String> {
    let p = pkg.to_string_lossy();
    let has = |tool: &str| {
        ["/usr/bin", "/bin", "/usr/sbin"]
            .iter()
            .any(|d| Path::new(d).join(tool).exists())
    };
    // Package managers pull in missing dependencies (e.g. lsb-release);
    // plain dpkg/rpm are the fallback.
    let (tool, args): (&str, Vec<&str>) = match pkg.extension().and_then(|e| e.to_str()) {
        Some("deb") if has("apt-get") => ("apt-get", vec!["install", "-y", &p]),
        Some("deb") => ("dpkg", vec!["-i", &p]),
        Some("rpm") if has("dnf") => ("dnf", vec!["install", "-y", &p]),
        Some("rpm") if has("yum") => ("yum", vec!["install", "-y", &p]),
        Some("rpm") => ("rpm", vec!["-Uvh", "--replacepkgs", &p]),
        _ => return Err(format!("{p}: expected a .deb or .rpm Wazuh agent package")),
    };
    let mut cmd = command(tool);
    cmd.args(&args).env("DEBIAN_FRONTEND", "noninteractive");
    for (k, v) in vars {
        cmd.env(k, v);
    }
    run_cmd(&mut cmd, tool, &args, &[0])?;
    if has_systemd() {
        run("systemctl", &["daemon-reload"])?;
    }
    service(agent_dir, Service::Restart)
}

/// Linux events go to stderr, which systemd/cron hand to the journal and
/// syslog that the Wazuh agent already ships.
#[cfg(not(windows))]
pub fn event_log(_level: Level, _msg: &str) {}

/// Reject files/directories a non-root user could have written (or, for
/// secrets, read). A path that does not exist yet is fine.
#[cfg(not(windows))]
pub fn check_owner(path: &Path, secret: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let forbidden = if secret { 0o077 } else { 0o022 };
    if m.uid() != 0 || m.mode() & forbidden != 0 {
        return Err(format!(
            "{} must be owned by root with mode {} (now uid {} mode {:o})",
            path.display(),
            if secret { "600" } else { "644/755" },
            m.uid(),
            m.mode() & 0o7777,
        ));
    }
    Ok(())
}

/// Give the agent's group read access to a file we wrote in its tree.
#[cfg(not(windows))]
pub fn share_with_agent(path: &Path) -> Result<(), String> {
    run("chown", &["root:wazuh", &path.to_string_lossy()])?;
    set_mode(path, 0o640)
}

/// Install (or update) and (re)start a systemd service running
/// `harrier <args>` in the background as root.
#[cfg(not(windows))]
pub fn install_daemon(name: &str, description: &str, args: &str) -> Result<String, String> {
    let exe = install_dir().join(BIN_NAME);
    if !has_systemd() {
        // ponytail: systemd only; add an init.d/OpenRC unit if such hosts matter.
        return Err(format!(
            "systemd not found: run `{} {args}` under your init system",
            exe.display()
        ));
    }
    let unit = format!(
        "[Unit]\nDescription={description}\nWants=network-online.target\n\
         After=network-online.target\n\n\
         [Service]\nExecStart={} {args}\nRestart=always\nRestartSec=30\n\
         NoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        exe.display()
    );
    write_file(
        &Path::new(UNIT_DIR).join(format!("{name}.service")),
        &unit,
        0o644,
    )?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", name])?;
    run("systemctl", &["restart", name])?;
    Ok(format!("systemd service {name} (enabled, running)"))
}

/// Best effort: stop our service if it exists.
#[cfg(not(windows))]
pub fn stop_daemon(name: &str) {
    if has_systemd() {
        let _ = run("systemctl", &["stop", name]);
    }
}

#[cfg(not(windows))]
pub fn remove_daemon(name: &str) -> Result<(), String> {
    if !has_systemd() {
        return Ok(());
    }
    let unit = Path::new(UNIT_DIR).join(format!("{name}.service"));
    if !unit.exists() {
        return Ok(());
    }
    let _ = run("systemctl", &["disable", "--now", name]);
    fs::remove_file(&unit).map_err(|e| format!("cannot remove {}: {e}", unit.display()))?;
    run("systemctl", &["daemon-reload"]).map(drop)
}

/// Linux: systemd restarts harrier, harrier restarts the agent.
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)] // same signature as the Windows version
pub fn wazuh_restart_on_failure() -> Result<(), String> {
    Ok(())
}

/// Run the service body. systemd supervises the process directly.
#[cfg(not(windows))]
pub fn serve(body: Box<dyn FnOnce() + Send>) {
    body();
}

/// Sleep; returns true when the service is being stopped (never on Linux:
/// systemd's SIGTERM ends the process, and every write harrier makes is atomic).
#[cfg(not(windows))]
pub fn sleep_or_stop(d: std::time::Duration) -> bool {
    std::thread::sleep(d);
    false
}

// -------------------------------------------------------------- Windows ----

#[cfg(windows)]
const WAZUH_SERVICE: &str = "WazuhSvc";
#[cfg(windows)]
const BIN_NAME: &str = "harrier.exe";

/// System tools always run from System32 by absolute path (no PATH
/// hijacking). A 32-bit build transparently gets `SysWOW64`, which is fine.
#[cfg(windows)]
pub fn command(program: &str) -> Command {
    Command::new(system32().join(format!("{program}.exe")))
}

#[cfg(windows)]
fn system32() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Path::new(&root).join("System32")
}

/// Windows ACLs come from the parent: everything harrier writes lives under
/// Program Files (admin-only), never `%ProgramData%` (user-writable).
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // same signature as the Linux version
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn program_files() -> PathBuf {
    std::env::var("ProgramFiles").map_or_else(|_| PathBuf::from(r"C:\Program Files"), PathBuf::from)
}

#[cfg(windows)]
pub fn install_dir() -> PathBuf {
    program_files().join("Harrier")
}

#[cfg(windows)]
pub fn config_dir() -> PathBuf {
    install_dir()
}

#[cfg(windows)]
pub fn data_dir() -> PathBuf {
    install_dir()
}

#[cfg(windows)]
pub fn default_agent_dir() -> PathBuf {
    std::env::var("ProgramFiles(x86)")
        .map_or_else(|_| program_files(), PathBuf::from)
        .join("ossec-agent")
}

#[cfg(windows)]
pub const AGENT_FILES: AgentFiles = AgentFiles {
    ossec_conf: "ossec.conf",
    client_keys: "client.keys",
    authd_pass: "authd.pass",
    state: "wazuh-agent.state",
};

#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub type Hkey = isize;
    // ((HKEY)(ULONG_PTR)((LONG)0x80000002)): sign-extended on 64-bit.
    #[allow(clippy::cast_possible_wrap)]
    pub const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002_u32 as i32 as isize;
    pub const KEY_READ: u32 = 0x0002_0019;
    pub const KEY_WOW64_64KEY: u32 = 0x0100;
    pub const REG_SZ: u32 = 1;
    pub const COMPUTER_NAME_DNS_HOSTNAME: i32 = 1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetSystemFirmwareTable(provider: u32, id: u32, buf: *mut c_void, size: u32) -> u32;
        pub fn GetComputerNameExW(kind: i32, buf: *mut u16, size: *mut u32) -> i32;
        pub fn LoadLibraryW(name: *const u16) -> isize;
        pub fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
    }

    pub type GetIfTable2 = unsafe extern "system" fn(table: *mut *mut u8) -> u32;
    pub type FreeMibTable = unsafe extern "system" fn(memory: *const c_void);

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn RegOpenKeyExW(key: Hkey, sub: *const u16, opt: u32, sam: u32, out: *mut Hkey)
        -> i32;
        pub fn RegQueryValueExW(
            key: Hkey,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        pub fn RegCloseKey(key: Hkey) -> i32;
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `REG_SZ` from HKLM (64-bit view, so 32-bit builds see the same data).
#[cfg(windows)]
fn reg_string(sub_key: &str, value: &str) -> Option<String> {
    let (sub, name) = (wide(sub_key), wide(value));
    let mut key: ffi::Hkey = 0;
    // SAFETY: NUL-terminated strings and a valid out-pointer.
    let rc = unsafe {
        ffi::RegOpenKeyExW(
            ffi::HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            0,
            ffi::KEY_READ | ffi::KEY_WOW64_64KEY,
            &raw mut key,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = [0u16; 512];
    let mut len = u32::try_from(size_of_val(&buf)).unwrap_or(0);
    let mut kind = 0u32;
    // SAFETY: `buf` is writable for `len` bytes and `key` is open.
    let rc = unsafe {
        let rc = ffi::RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            &raw mut kind,
            buf.as_mut_ptr().cast(),
            &raw mut len,
        );
        ffi::RegCloseKey(key);
        rc
    };
    if rc != 0 || kind != ffi::REG_SZ {
        return None;
    }
    let chars = (len as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..chars]);
    Some(s.trim_end_matches('\0').trim().to_owned()).filter(|s| !s.is_empty())
}

/// Full DNS host name (`COMPUTERNAME` is the 15-char `NetBIOS` name).
#[cfg(windows)]
pub fn hostname() -> String {
    let mut buf = [0u16; 256];
    let mut len = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` holds `len` UTF-16 units.
    let ok = unsafe {
        ffi::GetComputerNameExW(
            ffi::COMPUTER_NAME_DNS_HOSTNAME,
            buf.as_mut_ptr(),
            &raw mut len,
        )
    };
    if ok != 0 && len > 0 {
        return String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
    }
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// SMBIOS via `GetSystemFirmwareTable('RSMB')`: no WMI, no admin needed,
/// available since Vista (so Windows 7 is fine).
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // same signature as the Linux version
pub fn smbios_ids() -> Result<(Option<String>, Option<String>), String> {
    const RSMB: u32 = u32::from_be_bytes(*b"RSMB");
    // SAFETY: a null buffer with size 0 only queries the required size.
    let size = unsafe { ffi::GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
    if size < 8 {
        return Ok((None, None));
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` is writable for exactly `size` bytes.
    let got = unsafe { ffi::GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr().cast(), size) };
    if got < 8 || got > size {
        return Ok((None, None));
    }
    // RawSMBIOSData: u8 method, u8 major, u8 minor, u8 rev, u32 length, table.
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let end = (got as usize).min(8 + len);
    Ok(crate::identity::parse_smbios(&buf[8..end], buf[1], buf[2]))
}

/// Burned-in MACs of physical, non-USB adapters (`GetIfTable2`, Vista+).
#[cfg(windows)]
pub fn nic_macs() -> Vec<String> {
    use crate::identity::if_row;
    const NET_CLASS: &str =
        r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    const SKIP_BUS: [&str; 5] = ["USB\\", "ROOT\\", "SWD\\", "BTH", "{"];

    // iphlpapi.dll is not a KnownDLL: load it by absolute path so a planted
    // copy next to harrier.exe (e.g. in Downloads) is never picked up.
    let dll = wide(&system32().join("iphlpapi.dll").to_string_lossy());
    // SAFETY: NUL-terminated absolute path and symbol names; the module stays
    // loaded for the life of the process; signatures match iphlpapi.h.
    let (get_table, free_table) = unsafe {
        let module = ffi::LoadLibraryW(dll.as_ptr());
        if module == 0 {
            return Vec::new();
        }
        let get = ffi::GetProcAddress(module, c"GetIfTable2".as_ptr().cast());
        let free = ffi::GetProcAddress(module, c"FreeMibTable".as_ptr().cast());
        if get.is_null() || free.is_null() {
            return Vec::new();
        }
        (
            std::mem::transmute::<*const std::ffi::c_void, ffi::GetIfTable2>(get),
            std::mem::transmute::<*const std::ffi::c_void, ffi::FreeMibTable>(free),
        )
    };
    let mut table: *mut u8 = std::ptr::null_mut();
    // SAFETY: valid out-pointer; freed with FreeMibTable below.
    if unsafe { get_table(&raw mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    // SAFETY: MIB_IF_TABLE2 = u32 count, then `count` rows from offset 8.
    let rows = unsafe {
        let count = table.cast::<u32>().read_unaligned() as usize;
        std::slice::from_raw_parts(table, if_row::TABLE_ROWS_OFFSET + count * if_row::SIZE)
            [if_row::TABLE_ROWS_OFFSET..]
            .chunks_exact(if_row::SIZE)
            .filter_map(if_row::physical_nic)
            .collect::<Vec<_>>()
    };
    // SAFETY: `table` came from GetIfTable2 and is no longer borrowed.
    unsafe { free_table(table.cast()) };

    rows.into_iter()
        .filter(|(guid, _)| {
            let pnp = reg_string(&format!(r"{NET_CLASS}\{guid}\Connection"), "PnPInstanceID")
                .unwrap_or_default()
                .to_ascii_uppercase();
            !SKIP_BUS.iter().any(|b| pnp.starts_with(b))
        })
        .map(|(_, mac)| mac)
        .collect()
}

#[cfg(windows)]
pub fn machine_id() -> Option<String> {
    reg_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
}

#[cfg(windows)]
pub fn service(_agent_dir: &Path, action: Service) -> Result<(), String> {
    // A user may have disabled the service; `net` waits for state changes
    // and its exit codes are locale independent.
    if !matches!(action, Service::Stop) {
        let _ = run("sc", &["config", WAZUH_SERVICE, "start=", "auto"]);
    }
    if matches!(action, Service::Stop | Service::Restart) {
        let stopped = run("net", &["stop", WAZUH_SERVICE]);
        if matches!(action, Service::Stop) {
            return stopped.map(drop);
        }
    }
    run("net", &["start", WAZUH_SERVICE]).map(drop)
}

/// Install or upgrade the Wazuh agent MSI silently with the given `WAZUH_*`
/// properties (empty on upgrade: the existing ossec.conf is kept).
#[cfg(windows)]
pub fn install_package(
    pkg: &Path,
    vars: &[(&str, String)],
    agent_dir: &Path,
) -> Result<(), String> {
    let p = pkg.to_string_lossy().to_string();
    if !p.to_ascii_lowercase().ends_with(".msi") {
        return Err(format!("{p}: expected a Wazuh agent .msi"));
    }
    let props: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut args = vec!["/i", p.as_str(), "/qn", "/norestart"];
    args.extend(props.iter().map(String::as_str));
    // 3010 = success, reboot required.
    run_cmd(command("msiexec").args(&args), "msiexec", &args, &[0, 3010])?;
    service(agent_dir, Service::Restart)
}

/// Windows events land in the Application log, which the Wazuh agent
/// collects by default, so the SOC sees every harrier action.
#[cfg(windows)]
pub fn event_log(level: Level, msg: &str) {
    let kind = match level {
        Level::Info => "INFORMATION",
        Level::Warn => "WARNING",
        Level::Error => "ERROR",
    };
    let msg: String = msg.chars().take(1000).collect();
    let _ = run(
        "eventcreate",
        &[
            "/L",
            "APPLICATION",
            "/T",
            kind,
            "/SO",
            "harrier",
            "/ID",
            "100",
            "/D",
            &msg,
        ],
    );
}

/// Windows ACLs are inherited, so trust is enforced by location: anything
/// harrier reads as SYSTEM must live in its admin-only install directory.
#[cfg(windows)]
pub fn check_owner(path: &Path, _secret: bool) -> Result<(), String> {
    let lower = |p: &Path| p.to_string_lossy().to_ascii_lowercase();
    let (path_l, dir_l) = (lower(path), lower(&install_dir()));
    if path_l == dir_l || path_l.starts_with(&format!("{dir_l}\\")) {
        Ok(())
    } else {
        Err(format!(
            "{} must be inside {} (admin-only), because harrier runs as SYSTEM",
            path.display(),
            install_dir().display()
        ))
    }
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // same signature as the Linux version
pub fn share_with_agent(_path: &Path) -> Result<(), String> {
    Ok(()) // inherits the agent directory ACL
}

/// Install (or update) and (re)start a Windows service running
/// `harrier.exe <args>` as `LocalSystem`, delayed auto-start, restarted by the
/// SCM if it ever dies.
#[cfg(windows)]
pub fn install_daemon(name: &str, description: &str, args: &str) -> Result<String, String> {
    let bin = format!("\"{}\" {args}", install_dir().join(BIN_NAME).display());
    let verb = if run("sc", &["query", name]).is_ok() {
        "config"
    } else {
        "create"
    };
    run(
        "sc",
        &[
            verb,
            name,
            "binPath=",
            &bin,
            "start=",
            "delayed-auto",
            "DisplayName=",
            description,
        ],
    )?;
    run("sc", &["description", name, description])?;
    restart_on_failure(name)?;
    let _ = run("net", &["stop", name]);
    run("net", &["start", name])?;
    Ok(format!("Windows service {name} (automatic, running)"))
}

#[cfg(windows)]
fn restart_on_failure(name: &str) -> Result<(), String> {
    run(
        "sc",
        &[
            "failure",
            name,
            "reset=",
            "86400",
            "actions=",
            "restart/60000/restart/60000/restart/60000",
        ],
    )
    .map(drop)
}

/// Let the service manager restart a crashed Wazuh agent too.
#[cfg(windows)]
pub fn wazuh_restart_on_failure() -> Result<(), String> {
    restart_on_failure(WAZUH_SERVICE)
}

/// Best effort: stop our service if it exists (frees harrier.exe for upgrade).
#[cfg(windows)]
pub fn stop_daemon(name: &str) {
    let _ = run("net", &["stop", name]);
}

#[cfg(windows)]
pub fn remove_daemon(name: &str) -> Result<(), String> {
    if run("sc", &["query", name]).is_err() {
        return Ok(());
    }
    let _ = run("net", &["stop", name]);
    run("sc", &["delete", name]).map(drop)
}

#[cfg(windows)]
pub use svc::{serve, sleep_or_stop};

/// Minimal Service Control Manager integration (advapi32, NT 4+).
#[cfg(windows)]
mod svc {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::{Condvar, Mutex, PoisonError};
    use std::time::Duration;

    #[repr(C)]
    struct TableEntry {
        name: *const u16,
        main: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }

    #[repr(C)]
    struct Status {
        kind: u32,
        state: u32,
        accepted: u32,
        exit_code: u32,
        specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    type Handler = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const TableEntry) -> i32;
        fn RegisterServiceCtrlHandlerExW(name: *const u16, f: Handler, ctx: *mut c_void) -> isize;
        fn SetServiceStatus(handle: isize, status: *const Status) -> i32;
    }

    const OWN_PROCESS: u32 = 0x10;
    const STOPPED: u32 = 1;
    const STOP_PENDING: u32 = 3;
    const RUNNING: u32 = 4;
    const ACCEPT_STOP_AND_SHUTDOWN: u32 = 0x1 | 0x4;
    const CONTROL_STOP: u32 = 1;
    const CONTROL_INTERROGATE: u32 = 4;
    const CONTROL_SHUTDOWN: u32 = 5;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

    type Body = Box<dyn FnOnce() + Send>;
    static HANDLE: AtomicIsize = AtomicIsize::new(0);
    static BODY: Mutex<Option<Body>> = Mutex::new(None);
    static STOP: Mutex<bool> = Mutex::new(false);
    static WAKE: Condvar = Condvar::new();

    fn report(state: u32, wait_hint_ms: u32) {
        let status = Status {
            kind: OWN_PROCESS,
            state,
            accepted: if state == RUNNING {
                ACCEPT_STOP_AND_SHUTDOWN
            } else {
                0
            },
            exit_code: 0,
            specific_exit_code: 0,
            check_point: u32::from(state == STOP_PENDING),
            wait_hint: wait_hint_ms,
        };
        // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and
        // `status` is a valid SERVICE_STATUS for the duration of the call.
        unsafe { SetServiceStatus(HANDLE.load(Ordering::SeqCst), &raw const status) };
    }

    fn take_body() -> Option<Body> {
        BODY.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    unsafe extern "system" fn handler(control: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
        match control {
            CONTROL_STOP | CONTROL_SHUTDOWN => {
                // A pass in progress (e.g. an agent restart) may take a while.
                report(STOP_PENDING, 120_000);
                *STOP.lock().unwrap_or_else(PoisonError::into_inner) = true;
                WAKE.notify_all();
                0
            }
            CONTROL_INTERROGATE => 0,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = super::wide("harrier"); // ignored for SERVICE_WIN32_OWN_PROCESS
        // SAFETY: NUL-terminated name and a handler with the HandlerEx ABI.
        let handle =
            unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), handler, std::ptr::null_mut()) };
        if handle == 0 {
            return;
        }
        HANDLE.store(handle, Ordering::SeqCst);
        report(RUNNING, 0);
        if let Some(body) = take_body() {
            body();
        }
        report(STOPPED, 0);
    }

    /// Run `body` as the service; when not started by the SCM (e.g. from a
    /// console), run it in the foreground instead.
    pub fn serve(body: Body) {
        *BODY.lock().unwrap_or_else(PoisonError::into_inner) = Some(body);
        let name = super::wide("harrier");
        let table = [
            TableEntry {
                name: name.as_ptr(),
                main: Some(service_main),
            },
            TableEntry {
                name: std::ptr::null(),
                main: None,
            },
        ];
        // SAFETY: NULL-terminated table that outlives the blocking call.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            if let Some(body) = take_body() {
                body();
            }
        }
    }

    /// Sleep, waking early when the SCM asks the service to stop.
    pub fn sleep_or_stop(d: Duration) -> bool {
        let guard = STOP.lock().unwrap_or_else(PoisonError::into_inner);
        let (stop, _) = WAKE
            .wait_timeout_while(guard, d, |stop| !*stop)
            .unwrap_or_else(PoisonError::into_inner);
        *stop
    }
}

// --------------------------------------------------------------- shared ----

/// Agent files relative to the agent install directory.
#[derive(Debug)]
pub struct AgentFiles {
    pub ossec_conf: &'static str,
    pub client_keys: &'static str,
    pub authd_pass: &'static str,
    pub state: &'static str,
}

/// Local sync databases cleared on re-enrollment so the agent sends a full
/// inventory/FIM/SCA snapshot under its new id (wazuh/wazuh#38601).
pub const SYNC_DB_DIRS: [&str; 3] = ["queue/fim/db", "queue/syscollector/db", "queue/sca/db"];
