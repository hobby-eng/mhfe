//! Process-local crash reporting and access control. This changes neither a global WER setting
//! nor the user's token. Administrator/debug privileges and handles opened before startup remain
//! outside this protection.

#![allow(
    unsafe_code,
    reason = "process security descriptors and error mode use Windows foreign functions"
)]

use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, IsValidAcl, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetErrorMode, SetErrorMode, SEM_NOGPFAULTERRORBOX,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::ReadBack;

/// OWNER RIGHTS suppresses the owner's implicit WRITE_DAC, preventing a same-user program from
/// granting itself VM_READ. The owner keeps synchronize, read-control, query and terminate rights
/// (0x00121401); SYSTEM keeps full access. No inherited ACE can grant extra rights.
const PROCESS_DACL: *const u16 = windows_sys::core::w!("D:P(A;;0x00121401;;;OW)(A;;GA;;;SY)");
const CANNOT_READ: ReadBack = ReadBack::Unknown("the process memory-access policy cannot be read");

pub(super) fn harden() {
    // SAFETY: changes only this process's policy, retaining flags inherited from its parent.
    // SEM_NOGPFAULTERRORBOX opts out of WER, rather than merely hiding its UI. CoreDumpCheck
    // reads the flag back before a secret is accepted.
    unsafe { SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX) };
    // A refusal is observed by memory_access(), whose failed read-back stops secret commands.
    let _ = restrict_memory_access();
}

pub(super) fn crash_reporting() -> ReadBack {
    // SAFETY: GetErrorMode returns the current process's mode and accesses no caller memory.
    if unsafe { GetErrorMode() } & SEM_NOGPFAULTERRORBOX != 0 {
        ReadBack::Set
    } else {
        ReadBack::Differs
    }
}

fn restrict_memory_access() -> Result<(), ReadBack> {
    let wanted = Descriptor::wanted()?;
    let dacl = wanted.dacl()?;
    // SAFETY: the pseudo-handle names this process; the valid ACL lives inside `wanted` until
    // SetSecurityInfo copies it. Owner, group and SACL are left unchanged.
    let result = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl.as_ptr().cast::<ACL>(),
            ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ReadBack::Differs)
    }
}

pub(super) fn memory_access() -> ReadBack {
    let compare = || {
        let wanted = Descriptor::wanted()?;
        let actual = Descriptor::current()?;
        Ok::<_, ReadBack>(if wanted.dacl()? == actual.dacl()? {
            ReadBack::Set
        } else {
            ReadBack::Differs
        })
    };
    compare().unwrap_or_else(|reading| reading)
}

/// An OS-allocated descriptor: returned pointers into it cannot outlive the owner.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn wanted() -> Result<Self, ReadBack> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: the string is a static, NUL-terminated UTF-16 SDDL descriptor; the system
        // allocates the output, released exactly once by Descriptor::drop.
        let read = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PROCESS_DACL,
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if read == 0 {
            Err(CANNOT_READ)
        } else {
            Ok(Self(descriptor))
        }
    }

    fn current() -> Result<Self, ReadBack> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: the OS allocates a descriptor for this process; unused component outputs are
        // null. The owner releases the result with LocalFree after all borrowed ACL bytes.
        let read = unsafe {
            GetSecurityInfo(
                GetCurrentProcess(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if read != 0 {
            Err(CANNOT_READ)
        } else {
            Ok(Self(descriptor))
        }
    }

    fn dacl(&self) -> Result<&[u8], ReadBack> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl = ptr::null_mut();
        // SAFETY: self owns a valid descriptor returned by Windows; all output pointers live
        // for the call. A successful, present, non-null ACL remains valid while self lives.
        let read =
            unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err(CANNOT_READ);
        }
        // SAFETY: dacl points inside the live OS descriptor. IsValidAcl checks its extent
        // before AclSize is used, and the borrowed slice cannot outlive the descriptor.
        unsafe {
            if IsValidAcl(dacl) == 0 {
                return Err(CANNOT_READ);
            }
            Ok(std::slice::from_raw_parts(
                dacl.cast(),
                usize::from((*dacl).AclSize),
            ))
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: this allocation came from Windows' security APIs and has one owner.
        unsafe { LocalFree(self.0) };
    }
}

#[cfg(test)]
mod tests;
