//! Memory that the process's control group may still take, on Linux.
//!
//! A container (Docker, Podman, Kubernetes) or a systemd unit can limit a group of processes to
//! less memory than the computer has free. /proc/meminfo describes the whole computer, so with it
//! alone MHFE would start Argon2 in a container limited to 1 GiB, and the kernel would end the
//! process for lack of memory in the middle of a round, instead of MHFE refusing at the start
//! with a clear message. This module reads the limit of the process's control group, and of every
//! group above it, from cgroup v2 or from the memory controller of cgroup v1.
//!
//! A group may still take its limit minus its usage. The usage includes the page cache, whose
//! inactive part (`inactive_file`) the kernel drops before it runs out of memory, so that part is
//! counted as available, as Kubernetes does for a container's working set. The figure is an
//! estimate like `MemAvailable`: other processes in the group can take memory meanwhile, so the
//! reservation of the work area may still fail, which MHFE reports as well.

use std::path::{Path, PathBuf};

/// In cgroup v1, a group without a limit reports a huge one (`PAGE_COUNTER_MAX` pages, about
/// 2^63 bytes); anything from 2^62 bytes up means "no limit".
const V1_NO_LIMIT_FROM: u64 = 1 << 62;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    V1,
    V2,
}

/// Memory that the control group of this process, and every group above it, may still take, or
/// `None` without a limit or where the figures cannot be read.
pub(super) fn available_bytes() -> Option<u64> {
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let read = |path: &Path| std::fs::read_to_string(path).ok();
    available_with(&membership, &mounts, read)
}

/// [`available_bytes`] for the given /proc files, reading the control files through `read`.
fn available_with(
    membership: &str,
    mounts: &str,
    read: impl Fn(&Path) -> Option<String>,
) -> Option<u64> {
    let (version, group_path) = memory_group(membership)?;
    let (mount_root, mount_point) = memory_mount(mounts, version)?;
    let directory = group_directory(&group_path, &mount_root, &mount_point)?;
    match version {
        Version::V2 => available_v2(&directory, &mount_point, read),
        Version::V1 => available_v1(&directory, read),
    }
}

/// The cgroup version that controls memory, and the process's group path in it, from
/// /proc/self/cgroup: lines "hierarchy:controllers:path". A cgroup v1 line that lists the memory
/// controller wins; on a system with both versions, v2 then does not control memory.
fn memory_group(membership: &str) -> Option<(Version, String)> {
    let mut unified = None;
    for line in membership.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if controllers.split(',').any(|name| name == "memory") {
            return Some((Version::V1, path.to_owned()));
        }
        if hierarchy == "0" && controllers.is_empty() {
            unified = Some((Version::V2, path.to_owned()));
        }
    }
    unified
}

/// The root and the mount point of the cgroup file system that holds the memory controller, from
/// /proc/self/mountinfo: "id parent device root mount-point options [optional fields] - type
/// source super-options".
fn memory_mount(mounts: &str, version: Version) -> Option<(String, PathBuf)> {
    mounts.lines().find_map(|line| {
        let (mount, file_system) = line.split_once(" - ")?;
        let mount: Vec<&str> = mount.split(' ').collect();
        let file_system: Vec<&str> = file_system.split(' ').collect();
        let (root, mount_point) = (mount.get(3)?, mount.get(4)?);
        let (kind, super_options) = (file_system.first()?, file_system.get(2).unwrap_or(&""));
        let wanted = match version {
            Version::V2 => *kind == "cgroup2",
            Version::V1 => *kind == "cgroup" && super_options.split(',').any(|o| o == "memory"),
        };
        wanted.then(|| (unescape(root), PathBuf::from(unescape(mount_point))))
    })
}

/// mountinfo writes a space, tab, line break and backslash in a path as \040, \011, \012 and \134.
fn unescape(field: &str) -> String {
    let mut text = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(index) = rest.find('\\') {
        text.push_str(&rest[..index]);
        let code = rest.get(index + 1..index + 4);
        match code.and_then(|digits| u8::from_str_radix(digits, 8).ok()) {
            Some(byte) => {
                text.push(char::from(byte));
                rest = &rest[index + 4..];
            }
            None => {
                text.push('\\');
                rest = &rest[index + 1..];
            }
        }
    }
    text.push_str(rest);
    text
}

/// The directory of the group: the mount shows the hierarchy from `mount_root` on, so the part of
/// the group path below it is appended to the mount point. A group outside the mounted part, as
/// can happen in a container without its own cgroup namespace, cannot be read.
fn group_directory(group_path: &str, mount_root: &str, mount_point: &Path) -> Option<PathBuf> {
    let below = Path::new(group_path).strip_prefix(mount_root).ok()?;
    Some(mount_point.join(below))
}

/// cgroup v2: the smallest room left in the group and in every group above it up to the mount
/// point. The root group has no memory.max, and "max" means no limit.
fn available_v2(
    directory: &Path,
    mount_point: &Path,
    read: impl Fn(&Path) -> Option<String>,
) -> Option<u64> {
    let mut smallest: Option<u64> = None;
    for group in directory
        .ancestors()
        .take_while(|group| group.starts_with(mount_point))
    {
        let Some(limit) = read(&group.join("memory.max")) else {
            continue;
        };
        let Ok(limit) = limit.trim().parse::<u64>() else {
            continue; // "max"
        };
        let usage = read_number(&read, &group.join("memory.current")).unwrap_or(limit);
        let stat = read(&group.join("memory.stat")).unwrap_or_default();
        let reclaimable = stat_value(&stat, "inactive_file").unwrap_or(0);
        let room = room_left(limit, usage, reclaimable);
        smallest = Some(smallest.map_or(room, |other| other.min(room)));
    }
    smallest
}

/// cgroup v1: memory.stat gives the limit that applies with every group above
/// (`hierarchical_memory_limit`) and the reclaimable cache of the group and its children.
fn available_v1(directory: &Path, read: impl Fn(&Path) -> Option<String>) -> Option<u64> {
    let stat = read(&directory.join("memory.stat"))?;
    let limit = stat_value(&stat, "hierarchical_memory_limit")?;
    if limit >= V1_NO_LIMIT_FROM {
        return None;
    }
    let usage = read_number(&read, &directory.join("memory.usage_in_bytes")).unwrap_or(limit);
    let reclaimable = stat_value(&stat, "total_inactive_file").unwrap_or(0);
    Some(room_left(limit, usage, reclaimable))
}

/// The limit minus the usage that the kernel cannot reclaim.
fn room_left(limit: u64, usage: u64, reclaimable: u64) -> u64 {
    limit.saturating_sub(usage.saturating_sub(reclaimable))
}

fn read_number(read: &impl Fn(&Path) -> Option<String>, path: &Path) -> Option<u64> {
    read(path)?.trim().parse().ok()
}

/// A value of memory.stat, whose lines are "name value".
fn stat_value(stat: &str, name: &str) -> Option<u64> {
    stat.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == name).then(|| value.trim().parse().ok()).flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const GIB: u64 = 1 << 30;

    /// A fake /sys/fs/cgroup: control files and their contents.
    fn files(entries: &[(&str, String)]) -> impl Fn(&Path) -> Option<String> {
        let map: HashMap<PathBuf, String> = entries
            .iter()
            .map(|(path, text)| (PathBuf::from(path), text.clone()))
            .collect();
        move |path: &Path| map.get(path).cloned()
    }

    const V2_MOUNTS: &str = "49 47 0:30 / /sys/fs/cgroup rw,nosuid shared:7 - cgroup2 cgroup2 rw";

    #[test]
    fn a_v2_container_limit_counts_its_inactive_cache_as_free() {
        // Docker with its own cgroup namespace: the group is the root of what is mounted.
        let read = files(&[
            ("/sys/fs/cgroup/memory.max", format!("{}\n", GIB)),
            ("/sys/fs/cgroup/memory.current", format!("{}\n", GIB / 2)),
            (
                "/sys/fs/cgroup/memory.stat",
                format!("anon 1\ninactive_file {}\n", GIB / 4),
            ),
        ]);
        assert_eq!(
            available_with("0::/\n", V2_MOUNTS, read),
            Some(GIB - GIB / 4)
        );
    }

    #[test]
    fn the_smallest_room_of_the_group_and_its_parents_counts() {
        let read = files(&[
            ("/sys/fs/cgroup/app/memory.max", "max\n".to_owned()),
            ("/sys/fs/cgroup/app/memory.current", "100\n".to_owned()),
            (
                "/sys/fs/cgroup/app/job/memory.max",
                format!("{}\n", 8 * GIB),
            ),
            (
                "/sys/fs/cgroup/app/job/memory.current",
                format!("{}\n", GIB),
            ),
            ("/sys/fs/cgroup/memory.max", format!("{}\n", 3 * GIB)),
            ("/sys/fs/cgroup/memory.current", format!("{}\n", 2 * GIB)),
        ]);
        assert_eq!(available_with("0::/app/job\n", V2_MOUNTS, read), Some(GIB));
    }

    #[test]
    fn no_limit_anywhere_gives_no_figure() {
        let read = files(&[("/sys/fs/cgroup/user.slice/memory.max", "max\n".to_owned())]);
        assert_eq!(available_with("0::/user.slice\n", V2_MOUNTS, read), None);
        assert_eq!(available_with("", V2_MOUNTS, files(&[])), None);
        assert_eq!(available_with("0::/\n", "", files(&[])), None);
    }

    #[test]
    fn a_v1_memory_controller_uses_the_hierarchical_limit() {
        let mounts = "30 25 0:27 / /sys/fs/cgroup/memory rw shared:12 - cgroup cgroup rw,memory\n\
                      31 25 0:28 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct";
        let membership = "5:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n0::/\n";
        let stat = format!(
            "cache 5\nhierarchical_memory_limit {}\ntotal_inactive_file {}\n",
            2 * GIB,
            GIB / 2
        );
        let read = files(&[
            ("/sys/fs/cgroup/memory/docker/abc/memory.stat", stat),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes",
                format!("{}\n", GIB),
            ),
        ]);
        assert_eq!(
            available_with(membership, mounts, read),
            Some(GIB + GIB / 2)
        );

        let unlimited = "hierarchical_memory_limit 9223372036854771712\n".to_owned();
        let read = files(&[("/sys/fs/cgroup/memory/docker/abc/memory.stat", unlimited)]);
        assert_eq!(available_with(membership, mounts, read), None);
    }

    #[test]
    fn a_mount_of_part_of_the_hierarchy_is_followed() {
        // cgroup v1 without a cgroup namespace: the container sees its own group mounted.
        let mounts = "30 25 0:27 /docker/abc /sys/fs/cgroup/memory ro - cgroup cgroup rw,memory";
        assert_eq!(
            group_directory(
                "/docker/abc",
                "/docker/abc",
                Path::new("/sys/fs/cgroup/memory")
            ),
            Some(PathBuf::from("/sys/fs/cgroup/memory"))
        );
        assert_eq!(
            memory_mount(mounts, Version::V1),
            Some((
                "/docker/abc".to_owned(),
                PathBuf::from("/sys/fs/cgroup/memory")
            ))
        );
        // A group outside the mounted part cannot be read.
        assert_eq!(
            group_directory("/other", "/docker/abc", Path::new("/sys/fs/cgroup/memory")),
            None
        );
    }

    #[test]
    fn escaped_mount_paths_are_decoded() {
        assert_eq!(unescape(r"/mnt/with\040space\134x"), r"/mnt/with space\x");
        assert_eq!(unescape(r"/plain"), "/plain");
        assert_eq!(unescape(r"/odd\9"), r"/odd\9");
    }

    #[test]
    fn usage_beyond_the_limit_leaves_no_room() {
        assert_eq!(room_left(GIB, 2 * GIB, 0), 0);
        assert_eq!(room_left(GIB, GIB / 2, GIB), GIB);
    }
}
