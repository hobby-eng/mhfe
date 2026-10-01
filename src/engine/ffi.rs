//! The only module with `unsafe` code: the calls into the vendored reference Argon2 C code and
//! the operating-system queries for free memory. Every `unsafe` block states what it relies on.
#![allow(unsafe_code)]

use std::alloc::{self, Layout};
use std::cell::Cell;
use std::ffi::{c_char, c_int, CStr};
use std::ptr::{self, NonNull};

use zeroize::Zeroize;

use crate::MhfeError;

// Values from vendor/phc-winner-argon2/include/argon2.h.
const ARGON2_OK: c_int = 0;
/// `Argon2_id` in `enum Argon2_type`.
const ARGON2_ID: c_int = 2;
pub(super) const ARGON2_VERSION_13: u32 = 0x13;
/// MHFE sets no flag: it wipes its own copies of the password.
const ARGON2_DEFAULT_FLAGS: u32 = 0;

/// Alignment of the work area; `malloc` in C guarantees the same on 64-bit systems.
const WORK_AREA_ALIGNMENT: usize = 16;

type AllocateCallback = unsafe extern "C" fn(memory: *mut *mut u8, bytes: usize) -> c_int;
type FreeCallback = unsafe extern "C" fn(memory: *mut u8, bytes: usize);

/// Field-for-field copy of `argon2_context` in include/argon2.h.
#[repr(C)]
struct Argon2Context {
    out: *mut u8,
    outlen: u32,
    pwd: *mut u8,
    pwdlen: u32,
    salt: *mut u8,
    saltlen: u32,
    secret: *mut u8,
    secretlen: u32,
    ad: *mut u8,
    adlen: u32,
    t_cost: u32,
    m_cost: u32,
    lanes: u32,
    threads: u32,
    version: u32,
    allocate_cbk: Option<AllocateCallback>,
    free_cbk: Option<FreeCallback>,
    flags: u32,
}

// The Rust copy must have exactly the C layout, or the C code would read the wrong fields.
// Each pointer takes the pointer size and alignment, each uint32_t four bytes, and a
// pointer that follows a uint32_t starts at the next pointer-aligned offset.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Argon2Context>() == 120);
    assert!(align_of::<Argon2Context>() == 8);
    assert!(offset_of!(Argon2Context, out) == 0);
    assert!(offset_of!(Argon2Context, outlen) == 8);
    assert!(offset_of!(Argon2Context, pwd) == 16);
    assert!(offset_of!(Argon2Context, pwdlen) == 24);
    assert!(offset_of!(Argon2Context, salt) == 32);
    assert!(offset_of!(Argon2Context, saltlen) == 40);
    assert!(offset_of!(Argon2Context, secret) == 48);
    assert!(offset_of!(Argon2Context, secretlen) == 56);
    assert!(offset_of!(Argon2Context, ad) == 64);
    assert!(offset_of!(Argon2Context, adlen) == 72);
    assert!(offset_of!(Argon2Context, t_cost) == 76);
    assert!(offset_of!(Argon2Context, m_cost) == 80);
    assert!(offset_of!(Argon2Context, lanes) == 84);
    assert!(offset_of!(Argon2Context, threads) == 88);
    assert!(offset_of!(Argon2Context, version) == 92);
    assert!(offset_of!(Argon2Context, allocate_cbk) == 96);
    assert!(offset_of!(Argon2Context, free_cbk) == 104);
    assert!(offset_of!(Argon2Context, flags) == 112);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Argon2Context>() == 72);
    assert!(align_of::<Argon2Context>() == 4);
    assert!(offset_of!(Argon2Context, out) == 0);
    assert!(offset_of!(Argon2Context, outlen) == 4);
    assert!(offset_of!(Argon2Context, pwd) == 8);
    assert!(offset_of!(Argon2Context, pwdlen) == 12);
    assert!(offset_of!(Argon2Context, salt) == 16);
    assert!(offset_of!(Argon2Context, saltlen) == 20);
    assert!(offset_of!(Argon2Context, secret) == 24);
    assert!(offset_of!(Argon2Context, secretlen) == 28);
    assert!(offset_of!(Argon2Context, ad) == 32);
    assert!(offset_of!(Argon2Context, adlen) == 36);
    assert!(offset_of!(Argon2Context, t_cost) == 40);
    assert!(offset_of!(Argon2Context, m_cost) == 44);
    assert!(offset_of!(Argon2Context, lanes) == 48);
    assert!(offset_of!(Argon2Context, threads) == 52);
    assert!(offset_of!(Argon2Context, version) == 56);
    assert!(offset_of!(Argon2Context, allocate_cbk) == 60);
    assert!(offset_of!(Argon2Context, free_cbk) == 64);
    assert!(offset_of!(Argon2Context, flags) == 68);
};

unsafe extern "C" {
    fn argon2_ctx(context: *mut Argon2Context, argon2_type: c_int) -> c_int;
    /// Returns a static, NUL-terminated message for every code (argon2.c), so any code is safe.
    safe fn argon2_error_message(error_code: c_int) -> *const c_char;
    /// The C code wipes its internal buffers only while this global is non-zero (core.c).
    #[cfg(test)]
    static FLAG_clear_internal_memory: c_int;
}

/// Inputs of one Argon2 call. MHFE leaves the secret and the associated data empty; the tests
/// fill them to check this binding against the RFC 9106 test vector.
pub(super) struct Argon2Inputs<'a> {
    pub password: &'a [u8],
    pub salt: &'a [u8],
    pub secret: &'a [u8],
    pub associated_data: &'a [u8],
    pub passes: u32,
    pub memory_kib: u32,
    pub lanes: u32,
    pub threads: u32,
    pub version: u32,
}

/// Runs Argon2id in `work_area` and writes the tag into `output`.
pub(super) fn argon2id(
    inputs: &Argon2Inputs<'_>,
    work_area: &mut WorkArea,
    output: &mut [u8],
) -> Result<(), MhfeError> {
    let mut context = Argon2Context {
        out: output.as_mut_ptr(),
        outlen: length_u32(output)?,
        // The C struct has non-const pointers, but the C code writes through `pwd` and
        // `secret` only when a CLEAR flag is set, and `flags` below never sets one.
        pwd: pointer_or_null(inputs.password),
        pwdlen: length_u32(inputs.password)?,
        salt: pointer_or_null(inputs.salt),
        saltlen: length_u32(inputs.salt)?,
        secret: pointer_or_null(inputs.secret),
        secretlen: length_u32(inputs.secret)?,
        ad: pointer_or_null(inputs.associated_data),
        adlen: length_u32(inputs.associated_data)?,
        t_cost: inputs.passes,
        m_cost: inputs.memory_kib,
        lanes: inputs.lanes,
        threads: inputs.threads,
        version: inputs.version,
        allocate_cbk: Some(hand_out_work_area),
        free_cbk: Some(keep_work_area),
        flags: ARGON2_DEFAULT_FLAGS,
    };
    run(&mut context, work_area)
}

fn run(context: &mut Argon2Context, work_area: &mut WorkArea) -> Result<(), MhfeError> {
    CURRENT_WORK_AREA.with(|slot| slot.set(Some((work_area.start, work_area.layout.size()))));
    // SAFETY: every pointer in `context` is either NULL with length 0 or points to a live
    // buffer of the stated length that outlives this call: the inputs are shared borrows the C
    // code only reads, `out` is an exclusive borrow, and the work area is exclusively borrowed
    // through `&mut WorkArea`, so nothing else touches it meanwhile. argon2_ctx joins all its
    // worker threads before it returns, also when creating one fails, so no thread keeps these
    // pointers afterwards; only a failing join could leave one running, and a join fails only
    // for a thread that is invalid or would deadlock, which the C code never passes. It keeps
    // no other global state, so calls on different threads do not interfere.
    let code = unsafe { argon2_ctx(context, ARGON2_ID) };
    CURRENT_WORK_AREA.with(|slot| slot.set(None));
    if code == ARGON2_OK {
        Ok(())
    } else {
        // After a failure in the filling step, for example a thread that could not be
        // created, argon2_ctx returns before finalize(), which is where the C code wipes the
        // work area. Blocks derived from the password may be left in it, so wipe it here.
        work_area.wipe();
        Err(MhfeError::Argon2(error_message(code)))
    }
}

fn error_message(code: c_int) -> String {
    let message = argon2_error_message(code);
    // SAFETY: argon2_error_message returns a pointer to a static NUL-terminated string
    // literal for every input, valid for the whole run of the program.
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

fn length_u32(buffer: &[u8]) -> Result<u32, MhfeError> {
    u32::try_from(buffer.len())
        .map_err(|_| MhfeError::Internal("an Argon2 input exceeds 4 GiB".to_owned()))
}

/// The C code expects NULL for an empty secret or associated data.
fn pointer_or_null(buffer: &[u8]) -> *mut u8 {
    if buffer.is_empty() {
        ptr::null_mut()
    } else {
        buffer.as_ptr().cast_mut()
    }
}

/// The Argon2 memory of one operation: allocated once, handed to the C code in every round and
/// released when the engine is dropped.
pub(super) struct WorkArea {
    start: NonNull<u8>,
    layout: Layout,
}

impl WorkArea {
    pub(super) fn allocate(bytes: u64) -> Result<Self, MhfeError> {
        let refused = MhfeError::MemoryAllocation { bytes };
        let size = usize::try_from(bytes).map_err(|_| refused.clone())?;
        let layout =
            Layout::from_size_align(size, WORK_AREA_ALIGNMENT).map_err(|_| refused.clone())?;
        if layout.size() == 0 {
            return Err(refused);
        }
        // SAFETY: the layout has a non-zero size. Zeroed memory comes from the operating
        // system lazily, so the pages are only committed when Argon2 writes them.
        let start = NonNull::new(unsafe { alloc::alloc_zeroed(layout) }).ok_or(refused)?;
        Ok(Self { start, layout })
    }

    /// Overwrites the whole area with zeros. The C code wipes it at the end of every successful
    /// call; this covers the calls that fail before that point (see `run`).
    fn wipe(&mut self) {
        // The area is a whole number of 1 KiB Argon2 blocks and 16-byte aligned, so it can be
        // wiped as 64-bit words, eight times fewer volatile writes than as bytes.
        let words = self.layout.size() / std::mem::size_of::<u64>();
        // SAFETY: `start` points to `layout.size()` bytes owned by `self` and aligned to
        // WORK_AREA_ALIGNMENT, which is a multiple of the alignment of u64, and the exclusive
        // borrow of `self` rules out any other access while the slice exists.
        let area =
            unsafe { std::slice::from_raw_parts_mut(self.start.as_ptr().cast::<u64>(), words) };
        // zeroize writes through volatile stores, which the compiler may not remove even
        // though the memory is not read again before it is freed.
        area.zeroize();
    }

    /// Reads the work area; the tests use it to confirm that the C code wiped it.
    #[cfg(test)]
    fn contents(&self) -> &[u8] {
        // SAFETY: the area is `layout.size()` initialized bytes (allocated zeroed and then only
        // written by the C code), and the shared borrow of `self` rules out a concurrent call.
        unsafe { std::slice::from_raw_parts(self.start.as_ptr(), self.layout.size()) }
    }
}

impl Drop for WorkArea {
    fn drop(&mut self) {
        // SAFETY: `start` came from `alloc_zeroed` with exactly this layout and is freed once.
        // The C code wiped the memory at the end of every successful call, before
        // `keep_work_area`, and `run` wiped it after a failed one.
        unsafe { alloc::dealloc(self.start.as_ptr(), self.layout) }
    }
}

// SAFETY: the work area is plain memory owned by one engine; moving it to another thread
// moves the only handle to it.
unsafe impl Send for WorkArea {}

thread_local! {
    /// The work area of the Argon2 call running on this thread. The C allocation callbacks
    /// receive no pointer of our own, so `run` places the area here for the length of one call.
    static CURRENT_WORK_AREA: Cell<Option<(NonNull<u8>, usize)>> = const { Cell::new(None) };
}

/// `allocate_cbk`: gives the C code the prepared work area instead of allocating new memory.
/// The C code calls it on the thread that called `argon2_ctx`, before any worker thread starts.
unsafe extern "C" fn hand_out_work_area(memory: *mut *mut u8, bytes: usize) -> c_int {
    let area = CURRENT_WORK_AREA.try_with(Cell::get).ok().flatten();
    let pointer = match area {
        Some((start, size)) if bytes <= size => start.as_ptr(),
        // The C code turns NULL into ARGON2_MEMORY_ALLOCATION_ERROR.
        _ => ptr::null_mut(),
    };
    // SAFETY: `memory` points to the `uint8_t *` variable of allocate_memory() in core.c.
    unsafe { *memory = pointer };
    // allocate_memory() ignores this value and checks the pointer instead.
    ARGON2_OK
}

/// `free_cbk`: keeps the work area for the next round. The C code has already wiped it:
/// free_memory() in core.c calls clear_internal_memory() before this callback.
unsafe extern "C" fn keep_work_area(_memory: *mut u8, _bytes: usize) {}

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
    // libc points Mach calls to the mach2 crate; the Mach API itself is stable.
    // SAFETY: mach_host_self only returns a send right to the host port.
    #[allow(deprecated)]
    let host = unsafe { libc::mach_host_self() };
    // SAFETY: host_statistics64 writes at most `count` 32-bit words, and HOST_VM_INFO64_COUNT
    // is the size of `vm_statistics64`.
    #[allow(deprecated)]
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
    // SAFETY: releases the one right this call obtained above; `host` is not used afterwards.
    #[allow(deprecated)]
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

    const RFC_TAG: &str = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
    /// Smallest Argon2 memory for `lanes` lanes: two blocks per slice and four slices per lane.
    fn minimum_memory_kib(lanes: u32) -> u32 {
        8 * lanes
    }

    fn inputs<'a>(password: &'a [u8], salt: &'a [u8]) -> Argon2Inputs<'a> {
        Argon2Inputs {
            password,
            salt,
            secret: &[],
            associated_data: &[],
            passes: 1,
            memory_kib: 64,
            lanes: 4,
            threads: 4,
            version: ARGON2_VERSION_13,
        }
    }

    /// Runs the C engine with a fresh work area big enough for `inputs`.
    fn c_tag(inputs: &Argon2Inputs<'_>, output_len: usize) -> Result<Vec<u8>, MhfeError> {
        let kib = inputs.memory_kib.max(minimum_memory_kib(inputs.lanes));
        let mut work_area = WorkArea::allocate(u64::from(kib) * 1024)?;
        let mut output = vec![0u8; output_len];
        argon2id(inputs, &mut work_area, &mut output)?;
        Ok(output)
    }

    /// The same computation with RustCrypto `argon2`, an independent implementation.
    fn rustcrypto_tag(inputs: &Argon2Inputs<'_>, output_len: usize) -> Vec<u8> {
        use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};

        let version = match inputs.version {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            other => panic!("unexpected version {other:#x}"),
        };
        let params = ParamsBuilder::new()
            .m_cost(inputs.memory_kib)
            .t_cost(inputs.passes)
            .p_cost(inputs.lanes)
            .output_len(output_len)
            .data(AssociatedData::new(inputs.associated_data).unwrap())
            .build()
            .unwrap();
        let mut blocks = vec![Block::default(); params.block_count()];
        let argon2 =
            Argon2::new_with_secret(inputs.secret, Algorithm::Argon2id, version, params).unwrap();
        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into_with_memory(inputs.password, inputs.salt, &mut output, &mut blocks)
            .unwrap();
        output
    }

    #[test]
    fn matches_the_rfc_9106_argon2id_test_vector() {
        // RFC 9106, section 5.3: every input differs, and the secret and associated data are
        // set, so every field of the context takes part.
        let password = [0x01; 32];
        let salt = [0x02; 16];
        let secret = [0x03; 8];
        let associated_data = [0x04; 12];
        let rfc = Argon2Inputs {
            password: &password,
            salt: &salt,
            secret: &secret,
            associated_data: &associated_data,
            passes: 3,
            memory_kib: 32,
            lanes: 4,
            threads: 4,
            version: ARGON2_VERSION_13,
        };
        assert_eq!(hex::encode(c_tag(&rfc, 32).unwrap()), RFC_TAG);
        assert_eq!(hex::encode(rustcrypto_tag(&rfc, 32)), RFC_TAG);
    }

    #[test]
    fn matches_rustcrypto_on_many_small_public_inputs() {
        // A deterministic spread of parameters: lengths, costs, lane and thread counts,
        // versions, secret and associated data. Inputs are counters, not secrets.
        let bytes = |length: usize, seed: u8| -> Vec<u8> {
            (0..length)
                .map(|index| seed.wrapping_add((index as u8).wrapping_mul(31)))
                .collect()
        };
        let mut checked = 0;
        for case in 0u32..160 {
            let lanes = [1, 2, 3, 4][case as usize % 4];
            let threads = if case % 3 == 0 { 1 } else { lanes };
            let password = bytes([0, 1, 20, 32, 100][case as usize % 5], case as u8);
            let salt = bytes([8, 16, 33][case as usize % 3], 7);
            let secret = if case % 7 == 0 {
                bytes(8, 3)
            } else {
                Vec::new()
            };
            let associated_data = if case % 5 == 0 {
                bytes(12, 4)
            } else {
                Vec::new()
            };
            let inputs = Argon2Inputs {
                password: &password,
                salt: &salt,
                secret: &secret,
                associated_data: &associated_data,
                passes: 1 + case % 3,
                memory_kib: minimum_memory_kib(lanes) + 8 * (case % 11),
                lanes,
                threads,
                version: if case % 4 == 1 {
                    0x10
                } else {
                    ARGON2_VERSION_13
                },
            };
            let output_len = [4, 16, 32, 64, 100][case as usize % 5];
            assert_eq!(
                c_tag(&inputs, output_len).unwrap(),
                rustcrypto_tag(&inputs, output_len),
                "case {case}"
            );
            checked += 1;
        }
        assert_eq!(checked, 160);
    }

    #[test]
    fn threads_do_not_change_the_result() {
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut single = inputs(password, salt);
        single.threads = 1;
        let parallel = inputs(password, salt);
        assert_eq!(c_tag(&single, 32).unwrap(), c_tag(&parallel, 32).unwrap());
    }

    #[test]
    fn every_context_field_reaches_the_c_code() {
        // Changing one input at a time must change the tag, so no field is silently ignored or
        // read from the wrong offset. `threads` is covered by the test above; the callbacks and
        // flags by the work-area tests below.
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let base = c_tag(&inputs(password, salt), 32).unwrap();
        type ChangeOneField = fn(&mut Argon2Inputs<'_>);
        let variants: [(&str, ChangeOneField); 8] = [
            ("pwd", |i| i.password = b"public test passworD"),
            ("salt", |i| i.salt = b"0123456789abcdeF"),
            ("secret", |i| i.secret = b"secret"),
            ("ad", |i| i.associated_data = b"data"),
            ("t_cost", |i| i.passes = 2),
            ("m_cost", |i| i.memory_kib = 128),
            ("lanes", |i| i.lanes = 2),
            ("version", |i| i.version = 0x10),
        ];
        for (field, change) in variants {
            let mut changed = inputs(password, salt);
            change(&mut changed);
            assert_ne!(c_tag(&changed, 32).unwrap(), base, "{field} is ignored");
            assert_eq!(
                c_tag(&changed, 32).unwrap(),
                rustcrypto_tag(&changed, 32),
                "{field} is read wrongly"
            );
        }
        let longer = c_tag(&inputs(password, salt), 64).unwrap();
        assert_ne!(longer[..32], base[..], "outlen is ignored");
    }

    #[test]
    fn reuses_one_work_area_and_leaves_it_wiped() {
        // SAFETY: the C code only reads this global, which is 1 unless someone changes it.
        assert_eq!(
            unsafe { FLAG_clear_internal_memory },
            1,
            "C code would not wipe"
        );
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut work_area = WorkArea::allocate(64 * 1024).unwrap();
        let start = work_area.start;
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        argon2id(&inputs(password, salt), &mut work_area, &mut first).unwrap();
        assert!(work_area.contents().iter().all(|&byte| byte == 0));
        argon2id(&inputs(password, salt), &mut work_area, &mut second).unwrap();
        assert!(work_area.contents().iter().all(|&byte| byte == 0));
        assert_eq!(work_area.start, start);
        assert_eq!(first, second);
    }

    #[test]
    fn a_work_area_too_small_is_refused_by_the_c_code() {
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut work_area = WorkArea::allocate(32 * 1024).unwrap();
        let mut output = [0u8; 32];
        let error = argon2id(&inputs(password, salt), &mut work_area, &mut output).unwrap_err();
        assert_eq!(
            error,
            MhfeError::Argon2("Memory allocation error".to_owned())
        );
    }

    /// Fills the area with non-zero bytes, as a round leaves it before the C code wipes it.
    fn fill_with_ones(work_area: &mut WorkArea) {
        // SAFETY: the area is `layout.size()` bytes owned by `work_area`, exclusively borrowed.
        unsafe { ptr::write_bytes(work_area.start.as_ptr(), 0xff, work_area.layout.size()) };
    }

    #[test]
    fn wipe_clears_every_byte() {
        let mut work_area = WorkArea::allocate(64 * 1024).unwrap();
        fill_with_ones(&mut work_area);
        work_area.wipe();
        assert!(work_area.contents().iter().all(|&byte| byte == 0));
    }

    #[test]
    fn a_failed_call_leaves_the_work_area_wiped() {
        // The C code refuses this area after it was handed out, so the call fails on its error
        // path, where the C code itself wipes nothing; `run` must wipe instead. A failing
        // thread, which the C code reaches after filling blocks, takes the same path.
        let mut work_area = WorkArea::allocate(32 * 1024).unwrap();
        fill_with_ones(&mut work_area);
        let mut output = [0u8; 32];
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        argon2id(&inputs(password, salt), &mut work_area, &mut output).unwrap_err();
        assert!(work_area.contents().iter().all(|&byte| byte == 0));
    }

    #[test]
    fn argon2_errors_carry_the_reference_message() {
        let mut short_salt = inputs(b"password", b"1234567");
        short_salt.salt = b"1234567";
        assert_eq!(
            c_tag(&short_salt, 32).unwrap_err(),
            MhfeError::Argon2("Salt is too short".to_owned())
        );
        assert_eq!(error_message(-22), "Memory allocation error");
        assert_eq!(error_message(-15), "Memory cost is too large");
    }

    #[test]
    fn the_clear_password_flag_is_read_from_its_offset() {
        // With ARGON2_FLAG_CLEAR_PASSWORD (bit 0) the C code wipes the password buffer; this
        // proves that `flags` sits where the C code reads it. MHFE itself never sets it.
        let mut password = *b"public test password";
        let salt = *b"0123456789abcdef";
        let mut output = [0u8; 32];
        let mut work_area = WorkArea::allocate(64 * 1024).unwrap();
        let mut context = Argon2Context {
            out: output.as_mut_ptr(),
            outlen: 32,
            pwd: password.as_mut_ptr(),
            pwdlen: password.len() as u32,
            salt: salt.as_ptr().cast_mut(),
            saltlen: salt.len() as u32,
            secret: ptr::null_mut(),
            secretlen: 0,
            ad: ptr::null_mut(),
            adlen: 0,
            t_cost: 1,
            m_cost: 64,
            lanes: 4,
            threads: 4,
            version: ARGON2_VERSION_13,
            allocate_cbk: Some(hand_out_work_area),
            free_cbk: Some(keep_work_area),
            flags: 1,
        };
        run(&mut context, &mut work_area).unwrap();
        assert_eq!(password, [0u8; 20]);
    }

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
        let default_level = crate::WorkFactor::default().memory_bytes();
        assert_eq!(default_level, 2 << 30);
        let available = mach_available_bytes(262_144, 131_072, PAGE_BYTES).unwrap();
        assert_eq!(available, 1_610_612_736);
        assert!(available < default_level);

        // Exactly the memory of a level, and one page fewer, at level 0 (2 GiB) and 1 (3 GiB).
        for level in [0, 1] {
            let needed = crate::WorkFactor::new(0, level).unwrap().memory_bytes();
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
