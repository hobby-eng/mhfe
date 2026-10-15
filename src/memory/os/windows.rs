//! Windows page locking. The caller serializes calls and counts overlapping page holders, since
//! VirtualLock, like mlock, has no reference count.

use windows_sys::Win32::Foundation::{GetLastError, ERROR_WORKING_SET_QUOTA};
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
};

/// Grow only a small secret-buffer allowance; the gigabyte-sized Argon2 area is never locked.
const MAX_SECRET_WORKING_SET: usize = 64 * 1024 * 1024;

pub(crate) fn page_size() -> Option<usize> {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: GetSystemInfo fills the live, correctly sized system-information structure.
    unsafe { GetSystemInfo(&mut info) };
    let size = info.dwPageSize as usize;
    size.is_power_of_two().then_some(size)
}

pub(crate) fn lock_pages(start: *const u8, bytes: usize) -> bool {
    // SAFETY: VirtualLock only changes page policy for the supplied address range, whose
    // allocation the secret owner keeps alive. The OS refuses an uncommitted/unmapped range.
    if unsafe { VirtualLock(start.cast(), bytes) } != 0 {
        return true;
    }
    // SAFETY: GetLastError reads the current thread's last system error immediately after the
    // failed call, before another Windows call can replace it.
    if unsafe { GetLastError() } != ERROR_WORKING_SET_QUOTA || !grow_allowance(bytes) {
        return false;
    }
    // SAFETY: the same live allocation and range as the first attempt.
    unsafe { VirtualLock(start.cast(), bytes) != 0 }
}

fn grow_allowance(bytes: usize) -> bool {
    let Some(page) = page_size() else {
        return false;
    };
    let (mut minimum, mut maximum) = (0, 0);
    // SAFETY: the pseudo-handle belongs to this process and both outputs live for the call.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the borrowed process handle and the two live size outputs are valid.
    if unsafe { GetProcessWorkingSetSize(process, &mut minimum, &mut maximum) } == 0 {
        return false;
    }
    // VirtualLock's quota excludes a few overhead pages. Never lower an existing allowance or
    // reserve an unbounded working set after repeated failures.
    const OVERHEAD_PAGES: usize = 16;
    let Some(wanted) = minimum.checked_add(bytes.saturating_add(OVERHEAD_PAGES * page)) else {
        return false;
    };
    if wanted > MAX_SECRET_WORKING_SET {
        return false;
    }
    // SAFETY: adjusts only this process's allowance; a refusal is reported to the lock owner.
    unsafe { SetProcessWorkingSetSize(process, wanted, maximum.max(wanted)) != 0 }
}

pub(crate) fn unlock_pages(start: *const u8, bytes: usize) {
    // SAFETY: VirtualUnlock changes page policy without reading the range. The holder counts
    // ensure that no other live secret guard still owns any of the pages being released.
    unsafe { VirtualUnlock(start.cast(), bytes) };
}
