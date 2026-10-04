//! What the tool does to keep secrets inside its own memory: no core dumps, no reading of its
//! memory by other programs of the same user, and a warning when swap could write memory to a disk
//! without encryption. Argon2's work area is far too large to keep out of swap (src/memory.rs), and
//! from its blocks a password guess can be tested cheaply, so unencrypted swap matters.

// prctl and setrlimit are operating-system calls that Rust offers only through unsafe foreign
// functions.
#![allow(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

/// Forbids core dumps of this process and, on Linux, makes it non-dumpable, which also keeps
/// other processes of the same user from attaching to it (ptrace) or reading /proc/PID/mem. A
/// crash then writes nothing to disk, wherever systemd-coredump or apport would put it. Called
/// first in `main`; a refusal, which no usual system gives, changes nothing else.
pub fn harden_process() {
    #[cfg(unix)]
    {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads the struct, which lives for the call.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes an integer and touches no memory of this process.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    }
}

/// A swap area through which memory could reach a disk unencrypted.
#[derive(Debug, PartialEq, Eq)]
pub struct SwapArea {
    /// The device or file, as /proc/swaps names it.
    pub name: String,
    /// False when it is surely unencrypted, true when MHFE cannot tell, as for a swap file on a
    /// file system whose device it cannot see.
    pub unknown: bool,
}

/// The swap areas that are not encrypted by dm-crypt, or whose encryption cannot be told. An
/// area in memory (zram) is safe. Empty when there is no swap or this is not Linux.
pub fn unprotected_swap() -> Vec<SwapArea> {
    if cfg!(target_os = "linux") {
        unprotected_swap_under(Path::new("/"))
    } else {
        // macOS encrypts its swap; Windows keeps its page file without telling.
        Vec::new()
    }
}

/// [`unprotected_swap`] with /proc and /sys under `root`, so that a test can supply its own.
fn unprotected_swap_under(root: &Path) -> Vec<SwapArea> {
    let Ok(swaps) = fs::read_to_string(root.join("proc/swaps")) else {
        return Vec::new();
    };
    // "Filename Type Size Used Priority", one line per area after the heading; spaces in a name
    // are written as \040.
    swaps
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
            match device {
                Some(device) if encrypted(root, &device, 0) => None,
                Some(_) => Some(SwapArea {
                    name,
                    unknown: false,
                }),
                None => Some(SwapArea {
                    name,
                    unknown: true,
                }),
            }
        })
        .collect()
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

/// Whether a block device is encrypted with dm-crypt, directly or through the devices it is
/// built on (LVM on LUKS), or lies in memory (zram).
fn encrypted(root: &Path, device: &str, depth: usize) -> bool {
    if device.starts_with("zram") {
        return true;
    }
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
            unprotected_swap_under(&self.0)
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
            [SwapArea {
                name: "/dev/sda2".into(),
                unknown: false
            }]
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
            [SwapArea {
                name: "/swap file".into(),
                unknown: true
            }]
        );
    }

    #[test]
    fn no_swap_needs_no_warning() {
        assert_eq!(FakeSystem::new("").unprotected(), []);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_process_forbids_core_dumps() {
        harden_process();
        // SAFETY: PR_GET_DUMPABLE takes no pointer.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes the struct, which lives for the call.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
    }
}
