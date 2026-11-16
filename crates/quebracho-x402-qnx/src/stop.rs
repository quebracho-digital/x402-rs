//! The stop switch (port of `Stop.php`): payments stop while a file exists.
//!
//! Fails toward "stopped": anything at the path (a file, a link, a directory) counts as engaged, and so
//! does a path this process cannot look at (a directory it cannot search). Not ported: PHP's check that
//! the flag directory is owned by the process's user (it needs `getuid`, i.e. `libc`).

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use quebracho_x402::ports::Pause;

pub struct StopFile {
    file: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StopError {
    /// A relative path is not the same place in every process.
    NotAbsolute,
    /// The path is a link, or its directory can be written by others.
    Unsafe,
    Io,
}

impl StopFile {
    pub fn new(file: impl Into<PathBuf>) -> Result<Self, StopError> {
        let file = file.into();
        if !file.is_absolute() {
            return Err(StopError::NotAbsolute);
        }
        Ok(Self { file })
    }

    /// Stops payments. `why` is for whoever reads the file; buyers never see it.
    pub fn engage(&self, why: &str) -> Result<(), StopError> {
        let dir = self.file.parent().unwrap_or(Path::new("/"));
        if !dir.is_dir() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| StopError::Io)?;
        }
        if fs::symlink_metadata(&self.file).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(StopError::Unsafe);
        }
        let mode = fs::metadata(dir)
            .map_err(|_| StopError::Io)?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(StopError::Unsafe);
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.file)
            .map_err(|_| StopError::Io)?;
        f.write_all(why.as_bytes()).map_err(|_| StopError::Io)
    }

    /// Lets payments run again.
    pub fn release(&self) -> Result<(), StopError> {
        match fs::remove_file(&self.file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StopError::Io),
        }
    }

    /// Why it was engaged, if it is and says.
    pub fn note(&self) -> Option<String> {
        fs::read_to_string(&self.file)
            .ok()
            .filter(|s| !s.is_empty())
    }
}

impl Pause for StopFile {
    fn engaged(&self) -> bool {
        match fs::symlink_metadata(&self.file) {
            Ok(_) => true,
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            // Cannot look (permission denied, I/O): it must not look like "off".
            Err(_) => true,
        }
    }
}
