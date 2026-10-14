//! AUD-024 secrets-native harness: mhfe's swap inventory (src/bin/mhfe/protect/swap.rs, see
//! build.rs) on made-up /proc, /dev and /sys trees under a scratch folder (the first argument, or
//! the system's temporary folder).
//!
//! A: a zram swap device whose sysfs entry is there without a backing_dev attribute, as when the
//!    kernel has no writeback: in memory, nothing to warn about.
//! B: the same zram device listed in /proc/swaps and present in /dev, with no /sys at all, as in a
//!    chroot that mounts /proc and /dev only: whether it writes back to a disk cannot be told, so
//!    the area must be listed as unknown, and the tool must warn.
//! C: control for B, a plain partition in the same tree without /sys: listed.
//!
//! Exits 1 when B is not listed (the defect of AUD-024), 0 otherwise.

#[derive(Debug, PartialEq, Eq)]
pub struct SwapArea {
    pub name: String,
    pub unknown: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwapInventory {
    Available(Vec<SwapArea>),
    Unavailable,
}

#[allow(dead_code, reason = "the harness calls only the accessor")]
mod swap {
    include!(concat!(env!("OUT_DIR"), "/swap_copy.rs"));
}

use std::fs;
use std::path::{Path, PathBuf};

fn tree(base: &Path, name: &str, swaps: &str, sysfs_device: Option<&str>) -> PathBuf {
    let root = base.join(name);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("proc")).unwrap();
    fs::create_dir_all(root.join("dev")).unwrap();
    fs::write(root.join("proc/swaps"), format!("Filename\tType\tSize\tUsed\tPriority\n{swaps}")).unwrap();
    for device in ["zram0", "sda5"] {
        fs::write(root.join("dev").join(device), "").unwrap();
    }
    if let Some(device) = sysfs_device {
        fs::create_dir_all(root.join("sys/class/block").join(device).join("slaves")).unwrap();
    }
    root
}

fn main() {
    let scratch = std::env::args_os().nth(1).map_or_else(std::env::temp_dir, PathBuf::from);
    let base = scratch.join(format!("aud024-zram-no-sysfs-{}", std::process::id()));
    let zram = "/dev/zram0 partition 1024 0 100\n";
    let plain = "/dev/sda5 partition 1024 0 -2\n";
    let a = swap::probe_under(&tree(&base, "a", zram, Some("zram0")));
    let b = swap::probe_under(&tree(&base, "b", zram, None));
    let c = swap::probe_under(&tree(&base, "c", plain, None));
    let _ = fs::remove_dir_all(&base);
    println!("A zram0, sysfs entry without backing_dev: {a:?}");
    println!("B zram0, no /sys at all:                   {b:?}");
    println!("C sda5, no /sys at all (control):          {c:?}");
    let b_listed = matches!(&b, SwapInventory::Available(areas) if areas.len() == 1);
    if b_listed {
        println!("PASS: a zram area whose writeback cannot be read is listed");
    } else {
        println!("FAIL: a zram area whose writeback cannot be read is taken as in memory, no warning");
    }
    std::process::exit(i32::from(!b_listed));
}
