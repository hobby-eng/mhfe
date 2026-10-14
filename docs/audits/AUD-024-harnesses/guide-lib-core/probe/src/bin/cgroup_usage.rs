//! AUD-024 guide-lib-core: src/engine/cgroup.rs:28-29 documents `available_bytes` as giving `None`
//! "where the figures cannot be read". This calls the reviewed `available_with` (copied from the
//! file by build.rs) for a cgroup v2 group whose memory.max reads 8 GiB but whose memory.current
//! and memory.stat cannot be read, and for a cgroup v1 group whose memory.usage_in_bytes cannot be
//! read. Exits 1 when the code answers a figure (0 bytes) instead of `None`.
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/cgroup_copy.rs"));

use std::collections::HashMap;

/// A fake /sys/fs/cgroup, as the module's own tests make it: control files and their contents.
fn files(entries: &[(&str, String)]) -> impl Fn(&Path) -> Option<String> {
    let map: HashMap<PathBuf, String> = entries
        .iter()
        .map(|(path, text)| (PathBuf::from(path), text.clone()))
        .collect();
    move |path: &Path| map.get(path).cloned()
}

fn main() {
    const GIB: u64 = 1 << 30;
    let v2_mounts = "49 47 0:30 / /sys/fs/cgroup rw,nosuid shared:7 - cgroup2 cgroup2 rw";
    let v2 = available_with(
        "0::/app\n",
        v2_mounts,
        files(&[("/sys/fs/cgroup/app/memory.max", format!("{}\n", 8 * GIB))]),
    );
    println!("cgroup v2, memory.max 8 GiB, memory.current unreadable: {v2:?}");
    let v1_mounts = "30 25 0:27 / /sys/fs/cgroup/memory rw shared:12 - cgroup cgroup rw,memory";
    let v1 = available_with(
        "4:memory:/docker/abc\n",
        v1_mounts,
        files(&[(
            "/sys/fs/cgroup/memory/docker/abc/memory.stat",
            format!("hierarchical_memory_limit {}\n", 8 * GIB),
        )]),
    );
    println!("cgroup v1, limit 8 GiB, memory.usage_in_bytes unreadable: {v1:?}");
    if v2.is_some() || v1.is_some() {
        println!("FAIL: an unreadable usage is answered as a figure, not as None");
        std::process::exit(1);
    }
    println!("OK");
}
