use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Write bytes to `path` through a sibling temporary file and atomic rename.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fs::create_dir_all(parent)?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".stacker-write-")
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;

    let (_, tmp_path) = tmp.keep()?;
    fs::rename(&tmp_path, path)?;
    sync_parent_dir(parent)
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_atomic_writes_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.env");

        write_atomic(&path, b"KEY=value\n", 0o600).unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "KEY=value\n");
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.env");

        write_atomic(&path, b"OLD=value\n", 0o600).unwrap();
        write_atomic(&path, b"NEW=value\n", 0o600).unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "NEW=value\n");
    }

    #[test]
    fn write_atomic_creates_parent_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested").join("config.env");

        write_atomic(&path, b"KEY=value\n", 0o600).unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "KEY=value\n");
    }

    #[test]
    #[cfg(unix)]
    fn write_atomic_sets_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.env");

        write_atomic(&path, b"KEY=value\n", 0o600).unwrap();

        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
