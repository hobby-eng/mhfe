//! The only module with `unsafe` code: the operating-system queries for free memory, and the calls
//! that keep secrets out of swap. Every `unsafe` block states what it relies on.
#![allow(
    unsafe_code,
    reason = "the operating-system calls are unsafe foreign functions"
)]

/// The size of a memory page, a power of two, or `None` when the system does not say.
#[cfg(unix)]
pub(crate) fn page_size() -> Option<usize> {
    // SAFETY: sysconf only reads a system value.
    match usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) {
        Ok(page) if page.is_power_of_two() => Some(page),
        _ => None,
    }
}

/// Nothing is locked where there is no mlock, so no page size is needed.
#[cfg(not(unix))]
pub(crate) fn page_size() -> Option<usize> {
    None
}

/// Asks the operating system to keep the pages under `bytes` bytes at `start` in memory, never in
/// swap (mlock). Returns whether it agreed: a low RLIMIT_MEMLOCK, for example, refuses.
#[cfg(unix)]
pub(crate) fn lock_pages(start: *const u8, bytes: usize) -> bool {
    // SAFETY: mlock only changes how the kernel treats the pages of this process that contain
    // the range; it reads and writes no memory, and a range that is not mapped is refused.
    unsafe { libc::mlock(start.cast(), bytes) == 0 }
}

/// Undoes [`lock_pages`] for the same range.
#[cfg(unix)]
pub(crate) fn unlock_pages(start: *const u8, bytes: usize) {
    // SAFETY: as for mlock; munlock of pages that are no longer locked or mapped is refused
    // without effect.
    unsafe { libc::munlock(start.cast(), bytes) };
}

#[cfg(not(unix))]
pub(crate) fn lock_pages(_start: *const u8, _bytes: usize) -> bool {
    false
}

#[cfg(not(unix))]
pub(crate) fn unlock_pages(_start: *const u8, _bytes: usize) {}

/// Memory the operating system can give a new allocation without swapping, if it reports it:
/// the kernel's estimate for the whole computer, or less where the process's control group, such
/// as a container's, has less room left (see cgroup.rs).
#[cfg(target_os = "linux")]
pub(super) fn available_memory_bytes() -> Option<u64> {
    let computer = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| parse_mem_available(&meminfo));
    let group = super::cgroup::available_bytes();
    match (computer, group) {
        (Some(computer), Some(group)) => Some(computer.min(group)),
        (computer, group) => computer.or(group),
    }
}

/// `MemAvailable` in /proc/meminfo, the kernel's estimate of memory available for new
/// allocations without swapping, including caches it can drop.
#[cfg(any(target_os = "linux", test))]
fn parse_mem_available(meminfo: &str) -> Option<u64> {
    let line = meminfo
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Releases a send right; from <mach/mach_port.h> in the system library, which the libc
    /// crate does not declare.
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

/// Free and inactive pages of the Mach virtual-memory statistics: the pages the kernel can hand
/// to a new allocation without swapping. See [`mach_available_bytes`] for the counters left out.
#[cfg(target_os = "macos")]
pub(super) fn available_memory_bytes() -> Option<u64> {
    // SAFETY: vm_statistics64 holds only integers, for which all zero bytes are a valid value.
    let mut statistics: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    #[allow(
        deprecated,
        reason = "libc points the Mach calls to the mach2 crate; the Mach API itself is stable"
    )]
    // SAFETY: mach_host_self only returns a send right to the host port.
    let host = unsafe { libc::mach_host_self() };
    #[allow(
        deprecated,
        reason = "libc points the Mach calls to the mach2 crate; the Mach API itself is stable"
    )]
    // SAFETY: host_statistics64 writes at most `count` 32-bit words, and HOST_VM_INFO64_COUNT
    // is the size of `vm_statistics64`.
    let result = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            (&mut statistics as *mut libc::vm_statistics64).cast(),
            &mut count,
        )
    };
    // Each mach_host_self call adds a send right, which would otherwise pile up in a library
    // that checks the memory again and again. A failure to release it changes no result.
    #[allow(
        deprecated,
        reason = "libc points the Mach calls to the mach2 crate; the Mach API itself is stable"
    )]
    // SAFETY: releases the one right this call obtained above; `host` is not used afterwards.
    let _ = unsafe { mach_port_deallocate(libc::mach_task_self(), host) };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    // SAFETY: sysconf only reads a system constant.
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
    mach_available_bytes(statistics.free_count, statistics.inactive_count, page_size)
}

/// Bytes in the free and inactive pages of the Mach statistics.
///
/// Two counters are deliberately not added, because they overlap these two and adding them
/// would overstate the memory. Apple's `osfmk/mach/vm_statistics.h` states that speculative
/// pages "are already accounted for in free_count". Purgeable pages stay on the ordinary active
/// and inactive page queues, so `purgeable_count` may repeat inactive pages. A smaller estimate
/// only refuses earlier.
#[cfg(any(target_os = "macos", test))]
fn mach_available_bytes(free_count: u32, inactive_count: u32, page_size: u64) -> Option<u64> {
    let pages = u64::from(free_count) + u64::from(inactive_count);
    pages.checked_mul(page_size)
}

/// Available physical memory as Windows reports it, including the standby list.
#[cfg(windows)]
pub(super) fn available_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..MEMORYSTATUSEX::default()
    };
    // SAFETY: `status` is a writable MEMORYSTATUSEX whose dwLength is set, as the API requires.
    let succeeded = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    succeeded.then_some(status.ullAvailPhys)
}

/// Other systems give no figure; the operation then relies on the allocation itself.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(super) fn available_memory_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mem_available_from_proc_meminfo() {
        let meminfo = "MemTotal:       15448300 kB\nMemFree:  1 kB\nMemAvailable:    5242880 kB\n";
        assert_eq!(parse_mem_available(meminfo), Some(5_242_880 * 1024));
        assert_eq!(parse_mem_available("MemTotal: 1 kB\n"), None);
    }

    /// AUD-004-FUN001: 262144 free pages, of which 131072 are speculative, and 131072 inactive
    /// pages of 4096 bytes are 1.5 GiB. The old sum, which added the speculative pages again,
    /// reported 2 GiB and so admitted the default memory level.
    #[test]
    fn mach_estimate_does_not_count_speculative_pages_twice() {
        const PAGE_BYTES: u64 = 4096;
        let default_level = crate::memory_bytes(mhfe_core::WorkFactor::default());
        assert_eq!(default_level, 2 << 30);
        let available = mach_available_bytes(262_144, 131_072, PAGE_BYTES).unwrap();
        assert_eq!(available, 1_610_612_736);
        assert!(available < default_level);

        // Exactly the memory of a level, and one page fewer, at level 0 (2 GiB) and 1 (3 GiB).
        for level in [0, 1] {
            let needed = crate::memory_bytes(mhfe_core::WorkFactor::new(0, level).unwrap());
            let pages = u32::try_from(needed / PAGE_BYTES).unwrap();
            assert_eq!(mach_available_bytes(pages - 1, 1, PAGE_BYTES), Some(needed));
            assert_eq!(
                mach_available_bytes(pages - 1, 0, PAGE_BYTES),
                Some(needed - PAGE_BYTES)
            );
        }
        // 16 KiB pages, as on Apple silicon, and the largest counters do not overflow.
        assert_eq!(mach_available_bytes(1, 1, 16_384), Some(32_768));
        assert_eq!(
            mach_available_bytes(u32::MAX, u32::MAX, 16_384),
            Some(2 * u64::from(u32::MAX) * 16_384)
        );
    }
}
