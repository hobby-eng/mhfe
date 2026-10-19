//! Linux work-area page policy, confirmed from bounded kernel metadata before any use.
#![allow(
    unsafe_code,
    reason = "madvise is an operating-system foreign function"
)]

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::ptr::NonNull;

use super::EngineError;

const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 8 * 1024;

/// A complete allocation's page range; it borrows an address without accessing its contents.
pub(super) struct DumpRange {
    start: NonNull<u8>,
    bytes: usize,
    end: usize,
}

impl DumpRange {
    pub(super) fn read(start: NonNull<u8>, bytes: usize) -> Result<Self, EngineError> {
        let page = crate::memory::os::page_size().ok_or(EngineError::MemoryProtection)?;
        let address = start.as_ptr() as usize;
        if bytes == 0 || !address.is_multiple_of(page) || !bytes.is_multiple_of(page) {
            return Err(EngineError::MemoryProtection);
        }
        let end = address
            .checked_add(bytes)
            .ok_or(EngineError::MemoryProtection)?;
        Ok(Self { start, bytes, end })
    }

    /// A refused request, unavailable readback or missing page flag all fail closed.
    pub(super) fn require(&self) -> Result<(), EngineError> {
        // SAFETY: madvise only changes page policy and does not access contents. The caller owns
        // the entire aligned allocation until this call and its readback have completed.
        let applied =
            unsafe { libc::madvise(self.start.as_ptr().cast(), self.bytes, libc::MADV_DONTDUMP) };
        if applied != 0 {
            return Err(EngineError::MemoryProtection);
        }
        if !self
            .confirmed()
            .map_err(|_| EngineError::MemoryProtection)?
        {
            return Err(EngineError::MemoryProtection);
        }
        Ok(())
    }

    /// Current kernel metadata, distinct from whether the preceding request returned success.
    pub(super) fn confirmed(&self) -> io::Result<bool> {
        // Bound the underlying read too, before BufReader can prefetch beyond parser consumption.
        let file = File::open("/proc/self/smaps")?.take(MAX_SCAN_BYTES as u64);
        self.confirms(BufReader::new(file))
    }

    /// Confirm continuous coverage, permitting adjacent VMAs but no gap or missing exact dd flag.
    fn confirms(&self, mut reader: impl BufRead) -> io::Result<bool> {
        let mut remaining = MAX_SCAN_BYTES;
        let mut cursor = self.start.as_ptr() as usize;
        let mut current: Option<(usize, usize)> = None;
        let mut previous_end = 0;
        let mut line = Vec::with_capacity(256);
        while remaining > 0 {
            line.clear();
            let taken = reader
                .by_ref()
                .take(remaining.min(MAX_LINE_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if taken == 0 || taken > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
                return Ok(false);
            }
            remaining -= taken;
            if let Some(flags) = line.strip_prefix(b"VmFlags:") {
                let Some((first, last)) = current.take() else {
                    return Ok(false);
                };
                if last <= cursor {
                    continue;
                }
                if first > cursor
                    || !flags
                        .split(u8::is_ascii_whitespace)
                        .any(|flag| flag == b"dd")
                {
                    return Ok(false);
                }
                cursor = last.min(self.end);
                if cursor == self.end {
                    return Ok(true);
                }
            } else {
                match Self::header(&line) {
                    Ok(Some((first, last))) => {
                        if first < previous_end
                            || current.is_some_and(|(begin, end)| begin <= cursor && end > cursor)
                        {
                            return Ok(false);
                        }
                        previous_end = last;
                        current = Some((first, last));
                    }
                    Ok(None) => {}
                    Err(()) => return Ok(false),
                }
            }
        }
        Ok(false)
    }

    fn header(line: &[u8]) -> Result<Option<(usize, usize)>, ()> {
        let token = line
            .split(u8::is_ascii_whitespace)
            .next()
            .unwrap_or_default();
        if !token.contains(&b'-') {
            return Ok(None);
        }
        let token = std::str::from_utf8(token).map_err(|_| ())?;
        let (first, last) = token.split_once('-').ok_or(())?;
        let first = usize::from_str_radix(first, 16).map_err(|_| ())?;
        let last = usize::from_str_radix(last, 16).map_err(|_| ())?;
        if first >= last {
            return Err(());
        }
        Ok(Some((first, last)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range() -> DumpRange {
        // These addresses are compared with fixture metadata only, never dereferenced/advised.
        DumpRange {
            start: NonNull::new(0x1000 as *mut u8).unwrap(),
            bytes: 0x2000,
            end: 0x3000,
        }
    }

    #[test]
    fn continuous_whole_range_requires_each_exact_dump_flag() {
        for text in [
            "1000-3000 rw-p 0 00:00 0\nVmFlags: rd wr dd\n",
            "0000-1000 r--p 0 00:00 0\nVmFlags: rd\n1000-2000 rw-p 0 00:00 0\nVmFlags: dd\n2000-3000 rw-p 0 00:00 0\nVmFlags: wr dd\n",
        ] {
            assert!(range().confirms(io::Cursor::new(text)).unwrap());
        }
        for text in [
            "",
            "1000-3000 rw-p\n",
            "1000-3000 rw-p\nVmFlags: ddd\n",
            "1000-3000 rw-p\nVmFlags: rd wr\n",
            "1000-2000 rw-p\nVmFlags: dd\n2000-3000 rw-p\nVmFlags: wr\n",
            "1000-2000 rw-p\nVmFlags: dd\n2100-3000 rw-p\nVmFlags: dd\n",
            "1000-2000 rw-p\n2000-3000 rw-p\nVmFlags: dd\n",
            "1000-2000 rw-p\nVmFlags: dd\n1f00-3000 rw-p\nVmFlags: dd\n",
            "3000-1000 rw-p\nVmFlags: dd\n",
            "xyz-3000 rw-p\nVmFlags: dd\n",
            "1000-3000 rw-p\nVmFlags: dd",
        ] {
            assert!(!range().confirms(io::Cursor::new(text)).unwrap(), "{text}");
        }
    }

    #[test]
    fn metadata_reading_is_bounded_and_io_failures_remain_unknown() {
        // Removing either budget would admit the otherwise valid protected range in its tail.
        let long_line = format!(
            "1000-3000 rw-p {}\nVmFlags: dd\n",
            "x".repeat(MAX_LINE_BYTES)
        );
        let mut reader = io::Cursor::new(long_line);
        assert!(!range().confirms(&mut reader).unwrap());
        assert!(reader.position() <= (MAX_LINE_BYTES + 1) as u64);
        let many_lines =
            "Size: 0 kB\n".repeat(MAX_SCAN_BYTES / 11 + 1) + "1000-3000 rw-p\nVmFlags: dd\n";
        let mut reader = io::Cursor::new(many_lines);
        assert!(!range().confirms(&mut reader).unwrap());
        assert!(reader.position() <= MAX_SCAN_BYTES as u64);
        struct Refused;
        impl Read for Refused {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(
            range()
                .confirms(BufReader::new(Refused))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
