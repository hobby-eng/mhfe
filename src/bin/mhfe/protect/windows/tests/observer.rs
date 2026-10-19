//! Ordinary same-user observation, without the debugger privilege that bypasses a process DACL.

use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_NOT_ALL_ASSIGNED, ERROR_NO_TOKEN, ERROR_SUCCESS, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, CheckTokenMembership, CreateWellKnownSid, GetTokenInformation,
    LookupPrivilegeValueW, TokenPrivileges, WinLocalSystemSid, LUID_AND_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

// Bound the public test's variable-length token metadata independently of the host's contents.
const TOKEN_INFORMATION_BYTES: usize = 64 * 1024;

pub(super) fn require_ordinary_access() {
    no_thread_token();
    let system = is_system();
    assert!(
        !system,
        "UNAVAILABLE: SYSTEM is outside the ordinary-user DACL contract"
    );
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: this public observer opens only its own process token into a live output.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut raw,
            )
        },
        0
    );
    // SAFETY: OpenProcessToken succeeded; this is its sole owning handle, closed on all paths.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut debug = LUID::default();
    assert_ne!(
        // SAFETY: SE_DEBUG_NAME is static NUL-terminated text; debug is live writable storage.
        unsafe { LookupPrivilegeValueW(ptr::null(), SE_DEBUG_NAME, &mut debug) },
        0
    );
    let before = debug_enabled(&token, debug);
    let disabled = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: debug,
            Attributes: 0,
        }],
    };
    // SAFETY: modifies only this disposable observer's existing debugger privilege. No previous
    // state is requested; the live one-entry NewState matches its declared count.
    let changed = unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &disabled,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // SAFETY: capture this thread's error immediately after AdjustTokenPrivileges.
    let error = unsafe { GetLastError() };
    assert_ne!(
        changed, 0,
        "cannot disable public observer debug privilege: {error}"
    );
    assert!(
        matches!(error, ERROR_SUCCESS | ERROR_NOT_ALL_ASSIGNED),
        "{error}"
    );
    let after = debug_enabled(&token, debug);
    assert!(
        !after,
        "the public observer retains enabled SeDebugPrivilege"
    );
    no_thread_token();
    crate::style::out(format!(
        "MHFE_PUBLIC_OBSERVER system={system}, debug_before={before}, debug_after={after}"
    ))
    .unwrap();
}

fn no_thread_token() {
    let mut raw = ptr::null_mut();
    // SAFETY: queries only the calling test thread into a live output; OpenAsSelf is true.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    // SAFETY: preserve the query's immediate last-error value before closing any handle.
    let error = unsafe { GetLastError() };
    if opened != 0 {
        // SAFETY: a successful open returns one owned handle, released before the assertion.
        let _unexpected = unsafe { OwnedHandle::from_raw_handle(raw) };
    }
    assert_eq!(
        opened, 0,
        "UNAVAILABLE: an impersonation token changes the observer context"
    );
    assert_eq!(error, ERROR_NO_TOKEN);
}

fn is_system() -> bool {
    let mut sid = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<u32>())];
    let mut bytes = u32::try_from(size_of_val(&sid)).unwrap();
    assert_ne!(
        // SAFETY: aligned live storage has the documented maximum SID capacity; no domain SID.
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut bytes,
            )
        },
        0
    );
    let mut member = 0;
    assert_ne!(
        // SAFETY: the valid SID stays alive; null token deliberately queries the effective
        // context, rather than passing an unsupported primary token to CheckTokenMembership.
        unsafe { CheckTokenMembership(ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member) },
        0
    );
    member != 0
}

fn debug_enabled(token: &OwnedHandle, debug: LUID) -> bool {
    let mut words = [0usize; TOKEN_INFORMATION_BYTES.div_ceil(size_of::<usize>())];
    let mut bytes = 0;
    assert_ne!(
        // SAFETY: the owned token is open for QUERY; the aligned live buffer has this capacity.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenPrivileges,
                words.as_mut_ptr().cast(),
                u32::try_from(size_of_val(&words)).unwrap(),
                &mut bytes,
            )
        },
        0
    );
    let bytes = usize::try_from(bytes).unwrap();
    let start = offset_of!(TOKEN_PRIVILEGES, Privileges);
    assert!(bytes >= start && bytes <= size_of_val(&words));
    // SAFETY: returned bytes include the count, stored in aligned initialized word storage.
    let count = usize::try_from(unsafe { words.as_ptr().cast::<u32>().read() }).unwrap();
    let entries = count.checked_mul(size_of::<LUID_AND_ATTRIBUTES>()).unwrap();
    assert!(start.checked_add(entries).unwrap() <= bytes);
    let mut enabled = None;
    for index in 0..count {
        // SAFETY: the validated extent contains each complete entry. read_unaligned does not
        // assume array alignment beyond the byte offset; these types contain only integers.
        let entry = unsafe {
            words
                .as_ptr()
                .cast::<u8>()
                .add(start + index * size_of::<LUID_AND_ATTRIBUTES>())
                .cast::<LUID_AND_ATTRIBUTES>()
                .read_unaligned()
        };
        if entry.Luid.LowPart == debug.LowPart && entry.Luid.HighPart == debug.HighPart {
            assert!(enabled.is_none(), "duplicate debugger privilege entry");
            enabled = Some(entry.Attributes & SE_PRIVILEGE_ENABLED != 0);
        }
    }
    enabled.unwrap_or(false)
}
