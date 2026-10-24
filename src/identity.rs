//! Hardware-bound agent identity.
//!
//! The fingerprint combines the SMBIOS system UUID, the BIOS serial and the
//! sorted list of *physical, built-in* NIC MAC addresses, and is built to
//! stay stable in the real world:
//! - burned-in (permanent) MACs only, so Wi-Fi MAC randomisation, spoofing
//!   and USB docks never change the identity;
//! - a NIC appearing/disappearing (driver late at boot, adapter disabled)
//!   keeps the previous identity as long as UUID + serial are unchanged and
//!   at least one MAC is still shared (see [`Fingerprint::same_machine`]).
//!
//! Agent name = `<HOST>-<hwid>-<fwid>`, 12 hex digits each:
//! - `hwid`: UUID + serial + MACs, the full hardware fingerprint;
//! - `fwid`: UUID + serial only, the tag that stays with a machine when all
//!   its network cards change, so the server can tie old and new records.

use crate::{sha256, sys};

pub const ID_LEN: usize = 12;
const HOST_MAX: usize = 63;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// Normalised, junk-filtered values; empty means "not available".
    pub uuid: String,
    pub serial: String,
    pub macs: Vec<String>,
}

impl Fingerprint {
    pub fn collect() -> Result<Self, String> {
        let (uuid, serial) = sys::smbios_ids()?;
        Ok(Self::new(
            uuid.as_deref().unwrap_or_default(),
            serial.as_deref().unwrap_or_default(),
            sys::nic_macs(),
        ))
    }

    pub fn new(uuid: &str, serial: &str, macs: impl IntoIterator<Item = String>) -> Self {
        let uuid = uuid.trim().to_ascii_lowercase();
        let serial: String = serial
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .trim()
            .to_owned();
        let mut macs: Vec<String> = macs.into_iter().filter_map(|m| normalize_mac(&m)).collect();
        macs.sort();
        macs.dedup();
        Self {
            uuid: if is_junk_uuid(&uuid) {
                String::new()
            } else {
                uuid
            },
            serial: if is_junk_serial(&serial) {
                String::new()
            } else {
                serial
            },
            macs,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.uuid.is_empty() && self.serial.is_empty() && self.macs.is_empty()
    }

    /// Full SHA-256 hex. Falls back to the OS machine id only when the
    /// firmware exposes nothing usable at all.
    pub fn hash(&self, machine_id: impl FnOnce() -> Option<String>) -> Result<String, String> {
        let body = if self.is_empty() {
            let id = machine_id()
                .map(|m| m.trim().to_ascii_lowercase())
                .filter(|m| !m.is_empty())
                .ok_or("no SMBIOS UUID/serial, no physical NIC and no OS machine id")?;
            format!("machine-id|{id}")
        } else {
            format!("{}|{}|{}", self.uuid, self.serial, self.macs.join(","))
        };
        let input = format!("harrier-v1|{}|{body}", std::env::consts::OS);
        Ok(sha256::hex(&sha256::digest(input.as_bytes())))
    }

    /// Firmware id: SHA-256 of the SMBIOS UUID and serial alone. Only
    /// firmware that exposes both is trusted; otherwise this is the hardware
    /// id itself, so machines with placeholder firmware never look related.
    pub fn fwid(&self, hwid: &str) -> String {
        if self.uuid.is_empty() || self.serial.is_empty() {
            return hwid.to_owned();
        }
        let input = format!(
            "harrier-v1|{}|firmware|{}|{}",
            std::env::consts::OS,
            self.uuid,
            self.serial
        );
        sha256::hex(&sha256::digest(input.as_bytes()))
    }

    pub fn source(&self) -> &'static str {
        if self.is_empty() {
            "os-machine-id"
        } else {
            "smbios+nic"
        }
    }

    /// Same board (UUID + serial) and the NIC sets still overlap, or one
    /// side saw no NIC at all. A cloned disk on other hardware fails this.
    pub fn same_machine(&self, other: &Self) -> bool {
        self.uuid == other.uuid
            && self.serial == other.serial
            && (self.macs.is_empty()
                || other.macs.is_empty()
                || self.macs.iter().any(|m| other.macs.contains(m)))
    }
}

/// Keep the previously enrolled hash when the hardware is still the same
/// machine, otherwise adopt the freshly computed one.
pub fn resolve(
    current_hash: &str,
    current: &Fingerprint,
    stored: Option<(&str, &Fingerprint)>,
) -> String {
    match stored {
        Some((hash, fp)) if hash.len() == 64 && fp.same_machine(current) => hash.to_owned(),
        _ => current_hash.to_owned(),
    }
}

pub fn agent_name(host: &str, hwid: &str, fwid: &str) -> String {
    format!("{host}-{}-{}", &hwid[..ID_LEN], &fwid[..ID_LEN])
}

/// `AA:BB:CC:DD:EE:FF` for a unicast, globally administered (burned-in)
/// address; `None` for zero, multicast or locally administered (random,
/// virtual) addresses.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 12
        || raw
            .chars()
            .any(|c| !(c.is_ascii_hexdigit() || ":-. ".contains(c)))
    {
        return None;
    }
    let first = u8::from_str_radix(&hex[..2], 16).ok()?;
    if first & 0b11 != 0 || hex.bytes().all(|b| b == b'0') {
        return None;
    }
    let up = hex.to_ascii_uppercase();
    Some(
        (0..6)
            .map(|i| &up[i * 2..i * 2 + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Short hostname reduced to the characters Wazuh accepts in agent names.
pub fn sanitize_host(raw: &str) -> Option<String> {
    let short = raw.trim().split('.').next().unwrap_or_default();
    let cleaned: String = short
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(HOST_MAX)
        .collect();
    let cleaned = cleaned.trim_matches('-');
    (!cleaned.is_empty()).then(|| cleaned.to_owned())
}

/// A parsed Harrier agent name `<HOST>-<hwid>-<fwid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    pub host: &'a str,
    pub hwid: &'a str,
    pub fwid: &'a str,
}

pub fn parse_name(name: &str) -> Option<Name<'_>> {
    let id = |s: &str| {
        s.len() == ID_LEN
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let (rest, fwid) = name.rsplit_once('-')?;
    let (host, hwid) = rest.rsplit_once('-')?;
    (!host.is_empty() && id(hwid) && id(fwid)).then_some(Name { host, hwid, fwid })
}

/// Characters Wazuh accepts in agent/group names (also XML-safe).
pub fn is_valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_junk_uuid(u: &str) -> bool {
    let hex: String = u.chars().filter(char::is_ascii_hexdigit).collect();
    hex.len() != 32
        || hex.bytes().all(|b| b == b'0')
        || hex.bytes().all(|b| b == b'f')
        // Placeholder burned into many cheap boards (both byte orders).
        || hex == "03000200040005000006000700080009"
        || hex == "00020003000400050006000700080009"
}

fn is_junk_serial(s: &str) -> bool {
    const JUNK: [&str; 17] = [
        "none",
        "n/a",
        "na",
        "null",
        "oem",
        "invalid",
        "unknown",
        "serial",
        "default string",
        "to be filled by o.e.m.",
        "system serial number",
        "chassis serial number",
        "not specified",
        "not applicable",
        "not available",
        "123456789",
        "0123456789",
    ];
    let lower = s.trim().to_ascii_lowercase();
    let mut chars = lower.chars();
    let first = chars.next();
    lower.len() < 3 || JUNK.contains(&lower.as_str()) || chars.all(|c| Some(c) == first)
}

/// Extract `(uuid, serial)` from the SMBIOS type-1 (System Information)
/// structure of a raw SMBIOS table (Windows; Linux reads sysfs instead).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_smbios(table: &[u8], major: u8, minor: u8) -> (Option<String>, Option<String>) {
    let mut i = 0;
    while i + 4 <= table.len() {
        let kind = table[i];
        let len = usize::from(table[i + 1]);
        if len < 4 || i + len > table.len() {
            break;
        }
        let formatted = &table[i..i + len];
        let strings_start = i + len;
        let mut end = strings_start;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        if kind == 1 {
            let strings = &table[strings_start..end.min(table.len())];
            let serial = formatted.get(7).and_then(|&n| smbios_string(strings, n));
            // SMBIOS >= 2.6 stores the first three UUID fields little-endian.
            let uuid = formatted
                .get(8..24)
                .map(|b| format_uuid(b, (major, minor) >= (2, 6)));
            return (uuid, serial);
        }
        if kind == 127 {
            break;
        }
        i = end + 2;
    }
    (None, None)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn smbios_string(strings: &[u8], index: u8) -> Option<String> {
    let s = strings
        .split(|&b| b == 0)
        .nth(usize::from(index).checked_sub(1)?)?;
    let s = String::from_utf8_lossy(s).trim().to_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn format_uuid(b: &[u8], little_endian: bool) -> String {
    let mut v = b.to_vec();
    if little_endian {
        v[0..4].reverse();
        v[4..6].reverse();
        v[6..8].reverse();
    }
    let h = sha256::hex(&v);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Windows `MIB_IF_ROW2` (netioapi.h) layout: 1352 bytes on x86 and x64.
#[cfg_attr(not(windows), allow(dead_code))]
pub mod if_row {
    pub const SIZE: usize = 1352;
    pub const TABLE_ROWS_OFFSET: usize = 8;
    const GUID: usize = 12;
    const DESCRIPTION: usize = 542;
    const DESCRIPTION_END: usize = 1056;
    const ADDR_LEN: usize = 1056;
    const ADDR: usize = 1060;
    const PERM_ADDR: usize = 1092;
    const TYPE: usize = 1128;
    const PHYSICAL_MEDIUM: usize = 1140;
    const FLAGS: usize = 1152;

    const IF_TYPE_ETHERNET: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;
    const MEDIUM_BLUETOOTH: u32 = 10;
    const SKIP_WORDS: [&str; 9] = [
        "virtual",
        "vpn",
        "tap-",
        "loopback",
        "wi-fi direct",
        "bluetooth",
        "multiplexor",
        "pseudo",
        "miniport",
    ];

    fn u32_at(row: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([row[off], row[off + 1], row[off + 2], row[off + 3]])
    }

    /// `(interface GUID, raw MAC)` for a physical Ethernet/Wi-Fi adapter,
    /// preferring the burned-in address over the current one.
    pub fn physical_nic(row: &[u8]) -> Option<(String, String)> {
        if row.len() < SIZE {
            return None;
        }
        let flags = row[FLAGS];
        let (hardware, filter) = (flags & 1 != 0, flags & 2 != 0);
        let kind = u32_at(row, TYPE);
        if !hardware
            || filter
            || !(kind == IF_TYPE_ETHERNET || kind == IF_TYPE_IEEE80211)
            || u32_at(row, PHYSICAL_MEDIUM) == MEDIUM_BLUETOOTH
            || u32_at(row, ADDR_LEN) != 6
        {
            return None;
        }
        let desc: Vec<u16> = row[DESCRIPTION..DESCRIPTION_END]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let desc = String::from_utf16_lossy(&desc).to_ascii_lowercase();
        if SKIP_WORDS.iter().any(|w| desc.contains(w)) {
            return None;
        }
        let perm = &row[PERM_ADDR..PERM_ADDR + 6];
        let mac = if perm.iter().any(|&b| b != 0) {
            perm
        } else {
            &row[ADDR..ADDR + 6]
        };
        let g = &row[GUID..GUID + 16];
        let guid = format!(
            "{{{:08X}-{:04X}-{:04X}-{}}}",
            u32_at(g, 0),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8..]
                .iter()
                .enumerate()
                .map(|(i, b)| if i == 2 {
                    format!("-{b:02X}")
                } else {
                    format!("{b:02X}")
                })
                .collect::<String>()
        );
        let mac = mac
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        Some((guid, mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(uuid: &str, serial: &str, macs: &[&str]) -> Fingerprint {
        Fingerprint::new(uuid, serial, macs.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn names() {
        assert_eq!(
            sanitize_host("Laptop 01.corp.local").as_deref(),
            Some("Laptop-01")
        );
        assert_eq!(sanitize_host("..."), None);
        assert_eq!(
            parse_name("LAPTOP-01-0a1b2c3d4e5f-77a1c0de9f31"),
            Some(Name {
                host: "LAPTOP-01",
                hwid: "0a1b2c3d4e5f",
                fwid: "77a1c0de9f31"
            })
        );
        assert_eq!(parse_name("LAPTOP-01"), None);
        assert_eq!(parse_name("LAPTOP-01-0a1b2c3d4e5f"), None, "one id only");
        assert_eq!(parse_name("-0a1b2c3d4e5f-77a1c0de9f31"), None);
        assert_eq!(parse_name("X-0A1B2C3D4E5F-77A1C0DE9F31"), None);
        assert!(is_valid_name("PC-1_a.b"));
        assert!(!is_valid_name("PC<1>"));
        let (hw, fw) = ("ab".repeat(32), "cd".repeat(32));
        assert_eq!(agent_name("PC", &hw, &fw), "PC-abababababab-cdcdcdcdcdcd");
        let name = agent_name("A-B", &hw, &fw);
        assert_eq!(parse_name(&name).map(|n| n.host), Some("A-B"));
    }

    #[test]
    fn macs() {
        assert_eq!(
            normalize_mac("00-1a-2b-3c-4d-5e").as_deref(),
            Some("00:1A:2B:3C:4D:5E")
        );
        assert_eq!(
            normalize_mac("001a2b3c4d5e").as_deref(),
            Some("00:1A:2B:3C:4D:5E")
        );
        assert_eq!(
            normalize_mac("02:00:00:00:00:01"),
            None,
            "locally administered"
        );
        assert_eq!(normalize_mac("01:00:5e:00:00:01"), None, "multicast");
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert_eq!(normalize_mac("zz:00:00:00:00:01"), None);
    }

    #[test]
    fn junk_detection() {
        assert!(is_junk_serial("To Be Filled By O.E.M."));
        assert!(is_junk_serial("00000000"));
        assert!(!is_junk_serial("5CG1234XYZ"));
        assert!(is_junk_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(is_junk_uuid("03000200-0400-0500-0006-000700080009"));
        assert!(!is_junk_uuid("4c4c4544-0042-3510-8048-b3c04f4a4d32"));
        let f = fp(
            "03000200-0400-0500-0006-000700080009",
            "Default string",
            &[],
        );
        assert!(f.is_empty());
    }

    #[test]
    fn hashing_and_stability() {
        let uuid = "4C4C4544-0042-3510-8048-B3C04F4A4D32";
        let a = fp(uuid, "5CG1", &["00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5F"]);
        let order = fp(uuid, "5CG1", &["00-1A-2B-3C-4D-5F", "00:1a:2b:3c:4d:5e"]);
        let ha = a.hash(|| None).unwrap();
        assert_eq!(ha.len(), 64);
        assert_eq!(
            ha,
            order.hash(|| None).unwrap(),
            "MAC order/format must not matter"
        );

        // Wi-Fi disabled: one MAC gone, still the same machine.
        let wifi_off = fp(uuid, "5CG1", &["00:1A:2B:3C:4D:5E"]);
        assert_ne!(wifi_off.hash(|| None).unwrap(), ha);
        assert_eq!(
            resolve(&wifi_off.hash(|| None).unwrap(), &wifi_off, Some((&ha, &a))),
            ha
        );
        // Driver not loaded yet: no NIC at all, still the same machine.
        let none = fp(uuid, "5CG1", &[]);
        assert_eq!(resolve("x", &none, Some((&ha, &a))), ha);

        // Disk cloned to another laptop: different board -> new identity.
        let other = fp(
            "4c4c4544-0000-0000-0000-000000000001",
            "5CG2",
            &["00:AA:BB:CC:DD:EE"],
        );
        let ho = other.hash(|| None).unwrap();
        assert_eq!(resolve(&ho, &other, Some((&ha, &a))), ho);
        // Firmware id: same machine keeps it even when every NIC changes
        // (the hwid changes then), and it never equals the hwid.
        let new_nics = fp(uuid, "5CG1", &["00:15:5D:01:02:03"]);
        let hn = new_nics.hash(|| None).unwrap();
        assert_eq!(resolve(&hn, &new_nics, Some((&ha, &a))), hn, "new hwid");
        assert_eq!(new_nics.fwid(&hn), a.fwid(&ha), "same fwid");
        assert_ne!(a.fwid(&ha), ha);
        assert_ne!(other.fwid(&ho), a.fwid(&ha));
        // Weak firmware (no serial): no firmware id, it is the hwid itself.
        let vm = fp(
            "6f1d3c2a-9b8e-4d7c-a1b2-c3d4e5f60718",
            "",
            &["00:16:3E:00:00:01"],
        );
        let hvm = vm.hash(|| None).unwrap();
        assert_eq!(vm.fwid(&hvm), hvm);
        // Junk board, same junk UUID, disjoint NICs -> new identity.
        let j1 = fp("", "", &["00:11:11:11:11:11"]);
        let j2 = fp("", "", &["00:22:22:22:22:22"]);
        let hj2 = j2.hash(|| None).unwrap();
        assert_eq!(
            resolve(&hj2, &j2, Some((&j1.hash(|| None).unwrap(), &j1))),
            hj2
        );

        // Nothing at all -> OS machine id, else error.
        assert!(Fingerprint::default().hash(|| None).is_err());
        assert_eq!(
            Fingerprint::default()
                .hash(|| Some("ABC".into()))
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn smbios_type1() {
        let mut t = Vec::new();
        t.extend_from_slice(&[0, 4, 0, 0]);
        t.extend_from_slice(b"Vendor\0\0");
        let mut s1 = vec![1u8, 0x1b, 1, 0, 1, 0, 0, 2];
        s1.extend(0u8..16);
        s1.extend_from_slice(&[0, 0, 0]);
        t.extend_from_slice(&s1);
        t.extend_from_slice(b"Maker\0SN-42\0\0");
        t.extend_from_slice(&[127, 4, 0, 0, 0, 0]);

        let (uuid, serial) = parse_smbios(&t, 3, 4);
        assert_eq!(serial.as_deref(), Some("SN-42"));
        assert_eq!(
            uuid.as_deref(),
            Some("03020100-0504-0706-0809-0a0b0c0d0e0f")
        );
        let (old, _) = parse_smbios(&t, 2, 4);
        assert_eq!(old.as_deref(), Some("00010203-0405-0607-0809-0a0b0c0d0e0f"));
        assert_eq!(parse_smbios(&[1, 2], 3, 0), (None, None));
    }

    #[test]
    fn windows_if_row() {
        let mut row = vec![0u8; if_row::SIZE];
        row[12..28].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        for (i, c) in "Intel(R) Ethernet".encode_utf16().enumerate() {
            row[542 + i * 2..544 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        row[1056] = 6;
        row[1060..1066].copy_from_slice(&[0x02, 0, 0, 0, 0, 9]); // random current MAC
        row[1092..1098].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        row[1128] = 6;
        row[1140] = 14;
        row[1152] = 1;
        assert_eq!(
            if_row::physical_nic(&row),
            Some((
                "{12345678-9ABC-DEF0-0102-030405060708}".into(),
                "00:1A:2B:3C:4D:5E".into()
            ))
        );
        row[1152] = 0; // not a hardware interface
        assert_eq!(if_row::physical_nic(&row), None);
        row[1152] = 1;
        row[1140] = 10; // Bluetooth PAN
        assert_eq!(if_row::physical_nic(&row), None);
    }
}
