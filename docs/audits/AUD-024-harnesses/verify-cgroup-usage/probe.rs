// AUD-024 verify-cgroup-usage probe (reviewed commit b6fca69). run.sh appends this module to a
// copy of the reviewed src/engine/cgroup.rs, so that it calls the module's own private functions
// (available_with) with the module's own fake-file technique, and builds it with `rustc --test`.
// The module's own tests run in the same binary.
#[cfg(test)]
mod aud024_probe {
    use super::*;
    use std::collections::HashMap;

    const GIB: u64 = 1 << 30;
    const V2_MOUNTS: &str = "49 47 0:30 / /sys/fs/cgroup rw,nosuid shared:7 - cgroup2 cgroup2 rw";
    const V1_MOUNTS: &str = "30 25 0:27 / /sys/fs/cgroup/memory rw shared:12 - cgroup cgroup rw,memory";

    fn files(entries: &[(&str, String)]) -> impl Fn(&Path) -> Option<String> {
        let map: HashMap<PathBuf, String> = entries
            .iter()
            .map(|(path, text)| (PathBuf::from(path), text.clone()))
            .collect();
        move |path: &Path| map.get(path).cloned()
    }

    /// Control: with every file readable the figure is the limit minus the usage.
    #[test]
    fn control_readable_usage_gives_limit_minus_usage() {
        let read = files(&[
            ("/sys/fs/cgroup/app/memory.max", format!("{}\n", 8 * GIB)),
            ("/sys/fs/cgroup/app/memory.current", format!("{}\n", GIB)),
            ("/sys/fs/cgroup/app/memory.stat", "inactive_file 0\n".to_owned()),
        ]);
        let got = available_with("0::/app\n", V2_MOUNTS, read);
        println!("v2 control, max 8 GiB, current 1 GiB: {got:?}");
        assert_eq!(got, Some(7 * GIB));
    }

    /// src/engine/cgroup.rs:28-29: `None` "where the figures cannot be read".
    #[test]
    fn v2_unreadable_memory_current_gives_no_figure() {
        let read = files(&[
            ("/sys/fs/cgroup/app/memory.max", format!("{}\n", 8 * GIB)),
            ("/sys/fs/cgroup/app/memory.stat", "inactive_file 0\n".to_owned()),
        ]);
        let got = available_with("0::/app\n", V2_MOUNTS, read);
        println!("v2, max 8 GiB, memory.current unreadable: {got:?}");
        assert_eq!(got, None, "an unreadable usage became a figure");
    }

    #[test]
    fn v1_unreadable_usage_in_bytes_gives_no_figure() {
        let stat = format!("hierarchical_memory_limit {}\ntotal_inactive_file 0\n", 8 * GIB);
        let read = files(&[("/sys/fs/cgroup/memory/docker/abc/memory.stat", stat)]);
        let got = available_with("4:memory:/docker/abc\n", V1_MOUNTS, read);
        println!("v1, limit 8 GiB, memory.usage_in_bytes unreadable: {got:?}");
        assert_eq!(got, None, "an unreadable usage became a figure");
    }
}
