//! Test-only OS snapshots of live storage, including padding Rust must not load as `u8`.

use zeroize::Zeroizing;

/// A stack-sized snapshot; overlapping chunks also find a word across their boundary.
const CHUNK_BYTES: usize = 4096;

pub(super) struct MemoryReader {
    #[cfg(target_os = "linux")]
    memory: std::fs::File,
}

impl MemoryReader {
    pub(super) fn open() -> Result<Self, ()> {
        #[cfg(target_os = "linux")]
        return std::fs::File::open("/proc/self/mem")
            .map(|memory| Self { memory })
            .map_err(|_| ());
        #[cfg(any(target_os = "macos", windows))]
        return Ok(Self {});
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        Err(())
    }

    /// No allocation, formatting or borrowed Rust view of the inspected storage.
    pub(super) fn contains(&self, address: usize, size: usize, word: &[u8]) -> Result<bool, ()> {
        if word.is_empty() || word.len() > CHUNK_BYTES {
            return Err(());
        }
        let mut bytes = Zeroizing::new([0u8; CHUNK_BYTES]);
        let overlap = word.len() - 1;
        let mut offset = 0;
        while offset < size {
            let length = (size - offset).min(CHUNK_BYTES);
            self.read(address.checked_add(offset).ok_or(())?, &mut bytes[..length])?;
            if bytes[..length].windows(word.len()).any(|part| part == word) {
                return Ok(true);
            }
            if length == size - offset {
                break;
            }
            offset += length - overlap;
        }
        Ok(false)
    }

    #[cfg(target_os = "linux")]
    fn read(&self, address: usize, into: &mut [u8]) -> Result<(), ()> {
        use std::os::unix::fs::FileExt;
        match self.memory.read_at(into, address as u64) {
            Ok(length) if length == into.len() => Ok(()),
            _ => Err(()),
        }
    }

    #[cfg(windows)]
    fn read(&self, address: usize, into: &mut [u8]) -> Result<(), ()> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut copied = 0;
        // SAFETY: the pseudo-handle is this process; the OS validates the source address and
        // writes at most into.len() bytes to initialized, exclusively borrowed destination bytes.
        let result = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const _,
                into.as_mut_ptr().cast(),
                into.len(),
                &mut copied,
            )
        };
        if result != 0 && copied == into.len() {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(target_os = "macos")]
    fn read(&self, address: usize, into: &mut [u8]) -> Result<(), ()> {
        extern "C" {
            fn mach_vm_read_overwrite(
                target_task: libc::mach_port_t,
                address: u64,
                size: u64,
                data: u64,
                outsize: *mut u64,
            ) -> libc::kern_return_t;
        }
        let mut copied = 0;
        #[allow(
            deprecated,
            reason = "the stable Mach task API supplies this process's task port"
        )]
        // SAFETY: mach_task_self reads this process's task port without touching caller storage.
        let task = unsafe { libc::mach_task_self() };
        // SAFETY: the task is this process; Mach validates source storage and copies into the
        // initialized, exclusively borrowed output range. No Rust reference covers source bytes.
        let result = unsafe {
            mach_vm_read_overwrite(
                task,
                address as u64,
                into.len() as u64,
                into.as_mut_ptr() as u64,
                &mut copied,
            )
        };
        if result == libc::KERN_SUCCESS && copied == into.len() as u64 {
            Ok(())
        } else {
            Err(())
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    fn read(&self, _: usize, _: &mut [u8]) -> Result<(), ()> {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_across_snapshot_chunks_is_found() {
        let reader = MemoryReader::open().unwrap();
        let mut bytes = [0u8; CHUNK_BYTES * 2];
        let start = CHUNK_BYTES - 3;
        bytes[start..start + 9].copy_from_slice(b"zookeeper");
        assert_eq!(
            reader.contains(bytes.as_ptr() as usize, bytes.len(), b"zookeeper"),
            Ok(true)
        );
        assert_eq!(
            reader.contains(bytes.as_ptr() as usize, bytes.len(), b"absent"),
            Ok(false)
        );
    }

    #[test]
    fn an_unreadable_address_is_refused() {
        let reader = MemoryReader::open().unwrap();
        assert_eq!(reader.contains(0, 1, b"x"), Err(()));
    }
}
