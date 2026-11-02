//! Connecting folders to spaces, and finding plaintext secrets to bring in.

use std::fs;
use std::path::{Path, PathBuf};

use crate::env_file::parse as parse_env_file;
use crate::{Error, Result};

const LINK_FILE: &str = ".lv";
const SKIPPED: &[&str] = &["node_modules", "target", ".git", "dist", "build", ".next", "vendor"];

/// Writes `.lv` into `dir`. It holds only the space's name, so it is safe to commit.
pub fn link_folder(dir: &Path, space: &str) -> Result<()> {
    fs::write(dir.join(LINK_FILE), format!("space = {space}\n"))?;
    Ok(())
}

/// A folder's link to a space, and the file that makes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    pub space: String,
    pub file: PathBuf,
}

/// The space linked to `dir` or its nearest linked parent. A link file that names no space is an
/// error rather than no link, or its folder's secrets would quietly go to another space.
pub fn linked_space(dir: &Path) -> Result<Option<Linked>> {
    let Some(file) = dir.ancestors().map(|dir| dir.join(LINK_FILE)).find(|file| file.is_file()) else { return Ok(None) };
    let text = fs::read_to_string(&file)
        .map_err(|error| Error::Unreadable(format!("{} could not be read: {}", file.display(), crate::error::reason(&error))))?;
    let space = text.lines().find_map(|line| Some(line.trim().strip_prefix("space")?.trim_start().strip_prefix('=')?.trim().to_owned()));
    match space {
        Some(space) if !space.is_empty() => Ok(Some(Linked { space, file })),
        _ => Err(Error::Unreadable(format!("{} names no space. It holds one line, like: space = Work", file.display()))),
    }
}

/// A `.env` file on disk. Holds a count, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileInfo {
    pub path: PathBuf,
    pub variables: usize,
}

/// Finds `.env` files below `dir`, skipping dependencies and build output.
pub fn find_env_files(dir: &Path) -> Vec<EnvFileInfo> {
    let mut found = Vec::new();
    walk(dir, &mut found);
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

fn walk(dir: &Path, found: &mut Vec<EnvFileInfo>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // A link is not followed: two pointing at each other would never end.
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() {
            if !SKIPPED.contains(&name.as_ref()) {
                walk(&path, found);
            }
        } else if name == ".env" || (name.starts_with(".env.") && !name.ends_with(".example") && !name.ends_with(".sample")) {
            let variables = fs::read_to_string(&path).map_or(0, |text| parse_env_file(&text).vars.len());
            found.push(EnvFileInfo { path, variables });
        }
    }
}

/// A name for this device, used until the person renames it.
pub fn device_name() -> String {
    crate::sys::host_name().unwrap_or_else(|| "This device".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_that_link_to_each_other_do_not_hang_a_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("b"), dir.path().join("a")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("a"), dir.path().join("b")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("self")).unwrap();
        let root = dir.path().to_path_buf();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(find_env_files(&root).len()));
        assert_eq!(finished.recv_timeout(std::time::Duration::from_secs(5)), Ok(0));
    }

    #[test]
    fn a_link_is_found_from_nested_folders() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        fs::create_dir_all(&nested).unwrap();
        link_folder(dir.path(), "project-a").unwrap();
        assert_eq!(linked_space(&nested).unwrap().map(|linked| linked.space).as_deref(), Some("project-a"));
    }

    #[test]
    fn a_link_file_that_names_no_space_is_an_error_not_no_link() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(LINK_FILE), "spaces: Work\n").unwrap();
        assert!(linked_space(dir.path()).unwrap_err().to_string().contains("names no space"));
    }

    #[test]
    fn scanning_counts_variables_and_skips_examples_and_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "A=1\nB=2\n").unwrap();
        fs::write(dir.path().join(".env.local"), "C=3\n").unwrap();
        fs::write(dir.path().join(".env.example"), "D=\n").unwrap();
        fs::create_dir(dir.path().join("node_modules")).unwrap();
        fs::write(dir.path().join("node_modules/.env"), "E=5\n").unwrap();
        let found = find_env_files(dir.path());
        assert_eq!(found.iter().map(|file| file.variables).collect::<Vec<_>>(), [2, 1]);
    }
}
