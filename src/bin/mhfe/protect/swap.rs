//! Whether swap can write the tool's memory to a disk without encryption: the swap areas of
//! /proc/swaps, and the devices under each, followed through /sys.

use std::fs;
use std::path::{Path, PathBuf};

use super::{SwapArea, SwapInventory};

/// The swap areas that are not encrypted by dm-crypt, or whose encryption cannot be told. An
/// area in memory (zram) is safe only without a writeback device, or with an encrypted one. A
/// readable empty inventory is distinct from a failed read.
pub(crate) fn unprotected_swap() -> SwapInventory {
    inventory_on(std::env::consts::OS)
}

/// The platform policy is testable without pretending that a Linux probe read a Windows host.
fn inventory_on(os: &str) -> SwapInventory {
    if os == "linux" {
        unprotected_swap_under(Path::new("/"))
    } else if os == "macos" {
        // macOS encrypts swap. No pagefile protection is inspected on other systems.
        SwapInventory::Available(Vec::new())
    } else {
        SwapInventory::Unavailable
    }
}

/// [`unprotected_swap`] with /proc and /sys under `root`, so that a test can supply its own.
fn unprotected_swap_under(root: &Path) -> SwapInventory {
    swap_inventory(fs::read_to_string(root.join("proc/swaps")), root)
}

fn swap_inventory(read: std::io::Result<String>, root: &Path) -> SwapInventory {
    let Ok(swaps) = read else {
        return SwapInventory::Unavailable;
    };
    // "Filename Type Size Used Priority", one line per area after the heading; spaces in a name
    // are written as \040.
    let areas = swaps
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.replace("\\040", " "),
                fields.next()?.to_owned(),
            ))
        })
        .filter_map(|(name, kind)| {
            let device = match kind.as_str() {
                "partition" => device_of_node(root, &name),
                _ => device_of_file(root, &name),
            };
            match device.map(|device| protected(root, &device, 0)) {
                Some(Some(true)) => None,
                Some(Some(false)) => Some(SwapArea::new(name, false)),
                Some(None) | None => Some(SwapArea::new(name, true)),
            }
        })
        .collect();
    SwapInventory::Available(areas)
}

/// The kernel's name of the block device at a path such as /dev/sda2 or /dev/mapper/swap.
fn device_of_node(root: &Path, node: &str) -> Option<String> {
    let path = root.join(node.trim_start_matches('/'));
    let resolved = fs::canonicalize(path).ok()?;
    Some(resolved.file_name()?.to_string_lossy().into_owned())
}

/// The kernel's name of the block device that holds a swap file. /sys/dev/block is Linux's, and
/// so is the type of the device number that libc::major and libc::minor take.
fn device_of_file(root: &Path, file: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let device = fs::metadata(root.join(file.trim_start_matches('/')))
            .ok()?
            .dev();
        let (major, minor) = (libc::major(device), libc::minor(device));
        let link = root.join(format!("sys/dev/block/{major}:{minor}"));
        let resolved = fs::canonicalize(link).ok()?;
        Some(resolved.file_name()?.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, file);
        None
    }
}

/// Deepest stack of devices followed: LUKS under LVM under RAID is three.
const MAX_DEVICE_DEPTH: usize = 8;

/// Whether memory swapped to a block device stays off a disk unencrypted: it is encrypted with
/// dm-crypt, directly or through the devices it is built on (LVM on LUKS), or lies in memory
/// (zram) without a writeback device or with a protected one. `None` when that cannot be told,
/// as for a zram writeback device that cannot be resolved (AUD-023-SEC002), or a device whose
/// entry in /sys cannot be seen, as when /sys is not mounted (AUD-024-SEC011).
fn protected(root: &Path, device: &str, depth: usize) -> Option<bool> {
    let sysfs = root.join("sys/class/block").join(device);
    fs::metadata(&sysfs).ok()?;
    if device.starts_with("zram") {
        // zram writes idle or incompressible pages to its backing device, if it has one; the
        // attribute is world-readable, and absent from the device's entry where writeback is not
        // built in.
        return match fs::read_to_string(sysfs.join("backing_dev")) {
            // An entry without the attribute: no writeback. Any other error leaves the device
            // unknown.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(true),
            Err(_) => None,
            Ok(text) if matches!(text.trim(), "" | "none") => Some(true),
            Ok(text) if depth < MAX_DEVICE_DEPTH => {
                protected(root, &device_of_node(root, text.trim())?, depth + 1)
            }
            Ok(_) => None,
        };
    }
    Some(encrypted(root, device, depth))
}

/// Whether a block device is encrypted with dm-crypt, directly or through the devices it is
/// built on (LVM on LUKS).
fn encrypted(root: &Path, device: &str, depth: usize) -> bool {
    let sysfs = root.join("sys/class/block").join(device);
    // dm-crypt gives its devices a UUID starting with CRYPT-.
    if let Ok(uuid) = fs::read_to_string(sysfs.join("dm/uuid")) {
        if uuid.starts_with("CRYPT-") {
            return true;
        }
    }
    if depth >= MAX_DEVICE_DEPTH {
        return false;
    }
    let below: Vec<PathBuf> = fs::read_dir(sysfs.join("slaves"))
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    // A device built on others is encrypted only if all of them are.
    !below.is_empty()
        && below.iter().all(|path| {
            path.file_name()
                .is_some_and(|name| encrypted(root, &name.to_string_lossy(), depth + 1))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn an_uninspected_windows_pagefile_is_unknown() {
        assert_eq!(inventory_on("windows"), SwapInventory::Unavailable);
        assert_eq!(inventory_on("unknown-os"), SwapInventory::Unavailable);
    }

    /// A made-up /proc and /sys in a fresh temporary folder.
    struct FakeSystem(PathBuf);

    impl FakeSystem {
        fn new(swaps: &str) -> Self {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "mhfe-swap-test-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(root.join("proc")).unwrap();
            fs::create_dir_all(root.join("dev/mapper")).unwrap();
            fs::write(
                root.join("proc/swaps"),
                format!("Filename\tType\tSize\tUsed\tPriority\n{swaps}"),
            )
            .unwrap();
            Self(root)
        }

        /// A block device, with a dm UUID and the devices it is built on.
        fn device(&self, name: &str, uuid: Option<&str>, below: &[&str]) {
            let sysfs = self.0.join("sys/class/block").join(name);
            fs::create_dir_all(sysfs.join("slaves")).unwrap();
            if let Some(uuid) = uuid {
                fs::create_dir_all(sysfs.join("dm")).unwrap();
                fs::write(sysfs.join("dm/uuid"), uuid).unwrap();
            }
            for lower in below {
                fs::create_dir_all(sysfs.join("slaves").join(lower)).unwrap();
            }
            fs::write(self.0.join("dev").join(name), "").unwrap();
        }

        fn unprotected(&self) -> Vec<SwapArea> {
            let SwapInventory::Available(areas) = unprotected_swap_under(&self.0) else {
                panic!("the synthetic inventory could not be read");
            };
            areas
        }
    }

    impl Drop for FakeSystem {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_plain_partition_is_unprotected() {
        let system = FakeSystem::new("/dev/sda2 partition 1024 0 -2\n");
        system.device("sda2", None, &[]);
        assert_eq!(
            system.unprotected(),
            [SwapArea::new("/dev/sda2".into(), false,)]
        );
    }

    #[test]
    fn dm_crypt_and_zram_are_protected() {
        let system = FakeSystem::new(
            "/dev/dm-0 partition 1024 0 -2\n/dev/dm-2 partition 1024 0 -3\n/dev/zram0 partition 1024 0 100\n",
        );
        system.device("dm-0", Some("CRYPT-PLAIN-swap"), &["sda3"]);
        // LVM on LUKS: the logical volume is built on the encrypted device.
        system.device("dm-1", Some("CRYPT-LUKS2-abc-root"), &["nvme0n1p2"]);
        system.device("dm-2", Some("LVM-xyz"), &["dm-1"]);
        system.device("zram0", None, &[]);
        assert_eq!(system.unprotected(), []);
    }

    /// zram is in memory unless it writes back to a device: then that device decides, and one that
    /// cannot be resolved is unknown (AUD-023-SEC002).
    #[test]
    fn zram_is_protected_only_without_a_plaintext_writeback_device() {
        let zram = |backing: Option<&str>| {
            let system = FakeSystem::new("/dev/zram0 partition 1024 0 100\n");
            system.device("zram0", None, &[]);
            system.device("sdb2", None, &[]);
            system.device("dm-4", Some("CRYPT-LUKS2-abc-swap"), &["sdb3"]);
            if let Some(backing) = backing {
                fs::write(system.0.join("sys/class/block/zram0/backing_dev"), backing).unwrap();
            }
            system.unprotected()
        };
        let area = |unknown| vec![SwapArea::new("/dev/zram0".into(), unknown)];
        assert_eq!(zram(None), []);
        assert_eq!(zram(Some("none\n")), []);
        assert_eq!(zram(Some("/dev/sdb2\n")), area(false));
        assert_eq!(zram(Some("/dev/dm-4\n")), []);
        assert_eq!(zram(Some("/dev/missing\n")), area(true));
        // An attribute that is there but cannot be read leaves the device unknown.
        let system = FakeSystem::new("/dev/zram0 partition 1024 0 100\n");
        system.device("zram0", None, &[]);
        fs::create_dir(system.0.join("sys/class/block/zram0/backing_dev")).unwrap();
        assert_eq!(system.unprotected(), area(true));
    }

    /// A device seen in /dev whose entry in /sys cannot be seen, because /sys is not mounted or
    /// lacks the device, is unknown: nothing tells whether it writes back or is encrypted
    /// (AUD-024-SEC011).
    #[test]
    fn a_device_without_its_sysfs_entry_is_unknown() {
        for (name, other) in [("zram0", None), ("zram0", Some("sda1")), ("dm-0", None)] {
            let system = FakeSystem::new(&format!("/dev/{name} partition 1024 0 100\n"));
            fs::write(system.0.join("dev").join(name), "").unwrap();
            if let Some(other) = other {
                system.device(other, None, &[]);
            }
            assert_eq!(
                system.unprotected(),
                [SwapArea::new(format!("/dev/{name}"), true,)],
                "{name}, with another device: {other:?}"
            );
        }
    }

    #[test]
    fn lvm_without_encryption_is_unprotected() {
        let system = FakeSystem::new("/dev/dm-3 partition 1024 0 -2\n");
        system.device("dm-3", Some("LVM-xyz"), &["sdb1"]);
        system.device("sdb1", None, &[]);
        assert_eq!(system.unprotected().len(), 1);
    }

    #[test]
    fn a_file_whose_device_cannot_be_seen_is_unknown() {
        let system = FakeSystem::new("/swap\\040file file 1024 0 -2\n");
        assert_eq!(
            system.unprotected(),
            [SwapArea::new("/swap file".into(), true,)]
        );
    }

    #[test]
    fn no_swap_needs_no_warning() {
        assert_eq!(FakeSystem::new("").unprotected(), []);
    }

    #[test]
    fn a_missing_swap_inventory_is_not_confirmed_empty() {
        let empty = FakeSystem::new("");
        let missing = FakeSystem::new("");
        fs::remove_file(missing.0.join("proc/swaps")).unwrap();
        assert_ne!(
            unprotected_swap_under(&missing.0),
            unprotected_swap_under(&empty.0),
            "AUD-020-SEC001: unknown inventory must not suppress the warning"
        );
    }

    #[test]
    fn an_unreadable_swap_inventory_is_not_confirmed_empty() {
        let empty = FakeSystem::new("");
        let unreadable = FakeSystem::new("");
        let path = unreadable.0.join("proc/swaps");
        fs::remove_file(&path).unwrap();
        fs::create_dir(path).unwrap();
        assert_ne!(
            unprotected_swap_under(&unreadable.0),
            unprotected_swap_under(&empty.0),
            "AUD-020-SEC001: failed inventory read must remain unknown"
        );
    }

    #[test]
    fn a_denied_swap_inventory_remains_unavailable() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            swap_inventory(Err(denied), Path::new("/synthetic")),
            SwapInventory::Unavailable
        );
    }
}
