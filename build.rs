//! Windows (MSVC) builds: embed `assets/harrier.ico` as the executable icon.
//!
//! The resource file is written here directly (a `.res` is a short list of
//! headers plus the icon images) and handed to link.exe, which accepts `.res`
//! inputs, so no resource compiler or extra crate is needed.

use std::env;
use std::fs;
use std::path::PathBuf;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const LANG_EN_US: u16 = 0x0409;
const MOVEABLE_DISCARDABLE: u16 = 0x1010;
const MOVEABLE_PURE_DISCARDABLE: u16 = 0x1030;

fn main() {
    println!("cargo:rerun-if-changed=assets/harrier.ico");
    let windows_msvc = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !windows_msvc {
        return;
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ico = fs::read(root.join("assets/harrier.ico")).expect("read assets/harrier.ico");
    let res = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("harrier.res");
    fs::write(&res, icon_res(&ico)).expect("write harrier.res");
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> usize {
    let v = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    usize::try_from(v).expect("32-bit size")
}

/// One resource with a numeric type and id (fixed 32-byte header), padded
/// to a 4-byte boundary.
fn push_resource(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, lang: u16, data: &[u8]) {
    let size = u32::try_from(data.len()).expect("resource too large");
    for word in [size, 32] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for half in [0xFFFF, kind, 0xFFFF, id] {
        out.extend_from_slice(&half.to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // data version
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&lang.to_le_bytes());
    out.extend_from_slice(&[0; 8]); // version, characteristics
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// `.ico` file -> `.res` with one `RT_ICON` per image and an `RT_GROUP_ICON`
/// (id 1) that Explorer uses as the executable's icon.
fn icon_res(ico: &[u8]) -> Vec<u8> {
    assert!(
        ico.len() >= 6 && u16_at(ico, 2) == 1,
        "assets/harrier.ico is not an icon"
    );
    let count = u16_at(ico, 4);
    let mut res = Vec::new();
    push_resource(&mut res, 0, 0, 0, 0, &[]); // mandatory empty first entry
    let mut group = vec![0, 0, 1, 0];
    group.extend_from_slice(&count.to_le_bytes());
    for id in 1..=count {
        let entry = 6 + usize::from(id - 1) * 16;
        let (size, offset) = (u32_at(ico, entry + 8), u32_at(ico, entry + 12));
        let image = &ico[offset..offset + size];
        push_resource(
            &mut res,
            RT_ICON,
            id,
            MOVEABLE_DISCARDABLE,
            LANG_EN_US,
            image,
        );
        // GRPICONDIRENTRY = the first 12 bytes of ICONDIRENTRY + resource id.
        group.extend_from_slice(&ico[entry..entry + 12]);
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_resource(
        &mut res,
        RT_GROUP_ICON,
        1,
        MOVEABLE_PURE_DISCARDABLE,
        LANG_EN_US,
        &group,
    );
    res
}
