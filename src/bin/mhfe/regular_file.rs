//! Bounded reads of local public files. Final symlinks, devices, FIFOs and directories are refused.
//! Ancestor directories must be trusted; this is not a sandbox against their replacement.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

/// One validated open handle; a path replacement cannot change what its reads inspect.
pub(crate) struct RegularFile(File);

impl RegularFile {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Self::with_access(path, false)
    }

    /// Opens or creates the regular checksum list without truncation, before taking its lock.
    pub(crate) fn for_update(path: &Path) -> io::Result<Self> {
        Self::with_access(path, true)
    }

    fn with_access(path: &Path, update: bool) -> io::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => require_regular(&metadata)?,
            Err(error) if update && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(update)
            .create(update)
            .truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(
            &mut options,
            libc::O_NONBLOCK | libc::O_NOFOLLOW,
        );
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::custom_flags(
            &mut options,
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        );
        let file = options.open(path)?;
        // Refuse replacement by a nonregular object between metadata and open, too.
        require_regular(&file.metadata()?)?;
        Ok(Self(file))
    }

    /// `None` means oversize, including a file that grew after open. Reads at most limit + 1.
    pub(crate) fn bytes(self, limit: u64) -> io::Result<Option<Vec<u8>>> {
        let mut bytes = Vec::new();
        self.limited(limit)?.read_to_end(&mut bytes)?;
        Ok((bytes.len() as u64 <= limit).then_some(bytes))
    }

    /// Hashes incrementally with fixed scratch space, under the same byte bound as reads.
    pub(crate) fn sha256(self, limit: u64) -> io::Result<Option<[u8; 32]>> {
        const HASH_CHUNK_BYTES: usize = 16 * 1024;
        let mut file = self.limited(limit)?;
        let mut bytes = [0u8; HASH_CHUNK_BYTES];
        let mut count = 0;
        let mut hash = Sha256::new();
        loop {
            let length = file.read(&mut bytes)?;
            if length == 0 {
                return Ok((count <= limit).then(|| hash.finalize().into()));
            }
            count += length as u64;
            hash.update(&bytes[..length]);
        }
    }

    fn limited(self, limit: u64) -> io::Result<io::Take<File>> {
        let bound = limit.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "the file limit is too large")
        })?;
        Ok(self.0.take(bound))
    }

    pub(crate) fn lock(&self) -> io::Result<()> {
        self.0.lock()
    }

    /// Rewrites the locked checksum handle in place, preserving the identity of its lock.
    pub(crate) fn rewrite(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(0))?;
        self.0.set_len(0)?;
        self.0.write_all(bytes)?;
        self.0.sync_all()
    }
}

fn require_regular(metadata: &Metadata) -> io::Result<()> {
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    };
    #[cfg(not(windows))]
    let reparse = metadata.file_type().is_symlink();
    if !metadata.is_file() || reparse {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "it is not a regular file",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_streamed_hashes_have_the_same_exact_bound() {
        let path = std::env::temp_dir().join(format!("mhfe-file-bound-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            RegularFile::open(&path).unwrap().bytes(3).unwrap(),
            Some(b"abc".to_vec())
        );
        assert_eq!(RegularFile::open(&path).unwrap().bytes(2).unwrap(), None);
        assert_eq!(RegularFile::open(&path).unwrap().sha256(2).unwrap(), None);
        let digest = RegularFile::open(&path)
            .unwrap()
            .sha256(3)
            .unwrap()
            .unwrap();
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::write(&path, []).unwrap();
        assert_eq!(
            RegularFile::open(&path).unwrap().bytes(0).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            hex::encode(
                RegularFile::open(&path)
                    .unwrap()
                    .sha256(0)
                    .unwrap()
                    .unwrap()
            ),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(RegularFile::open(&path).unwrap().bytes(u64::MAX).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_rewrite_starts_at_the_beginning_and_keeps_the_lock() {
        let path = std::env::temp_dir().join(format!("mhfe-file-update-{}", std::process::id()));
        let mut file = RegularFile::for_update(&path).unwrap();
        file.lock().unwrap();
        file.rewrite(b"longer").unwrap();
        file.rewrite(b"short").unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
        std::fs::remove_file(path).unwrap();
    }
}
