//! Bounded file transfer after the executor has proven process containment.
//! This is not isolation from a hostile process sharing the agent's OS identity.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use mcloving_domain::workspace::{
    MAX_WORKSPACE_BYTES, MAX_WORKSPACE_DEPTH, MAX_WORKSPACE_ENTRIES, WorkspaceEntry,
    WorkspaceSnapshot, validate_path,
};

fn fail(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(super) fn seed(root: &Path, snapshot: &WorkspaceSnapshot) -> Result<(), String> {
    snapshot.validate().map_err(fail)?;
    // Domain validation requires explicit parent directories and canonical order.
    for entry in &snapshot.entries {
        match entry {
            WorkspaceEntry::Directory { path } => fs::create_dir(root.join(path)).map_err(fail)?,
            WorkspaceEntry::File {
                path,
                executable,
                contents,
            } => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if *executable { 0o700 } else { 0o600 })
                    .open(root.join(path))
                    .map_err(fail)?;
                file.write_all(contents).map_err(fail)?;
                file.sync_all().map_err(fail)?;
            }
        }
    }
    let control = File::open(root).map_err(fail)?;
    let actual = capture(root, &control)?;
    if actual.digest().map_err(fail)? != snapshot.digest().map_err(fail)? {
        return Err("seed_readback_mismatch".to_owned());
    }
    Ok(())
}

pub(super) fn capture(root: &Path, control: &File) -> Result<WorkspaceSnapshot, String> {
    let original = control.metadata().map_err(fail)?;
    let current = fs::symlink_metadata(root).map_err(fail)?;
    if !current.is_dir() || original.dev() != current.dev() || original.ino() != current.ino() {
        return Err("workspace_leaf_replaced".to_owned());
    }
    let mut entries = Vec::new();
    let mut bytes = 0;
    visit(root, root, 0, &mut entries, &mut bytes)?;
    entries.sort_by(|a, b| entry_path(a).cmp(entry_path(b)));
    let snapshot = WorkspaceSnapshot {
        version: 1,
        entries,
    };
    snapshot.validate().map_err(fail)?;
    let current = fs::symlink_metadata(root).map_err(fail)?;
    if original.dev() != current.dev() || original.ino() != current.ino() || !current.is_dir() {
        return Err("workspace_leaf_replaced".to_owned());
    }
    Ok(snapshot)
}

fn entry_path(entry: &WorkspaceEntry) -> &str {
    match entry {
        WorkspaceEntry::Directory { path } | WorkspaceEntry::File { path, .. } => path,
    }
}

fn visit(
    root: &Path,
    directory: &Path,
    depth: usize,
    entries: &mut Vec<WorkspaceEntry>,
    bytes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_WORKSPACE_DEPTH {
        return Err("workspace_depth_limit".to_owned());
    }
    for item in fs::read_dir(directory).map_err(fail)? {
        let item = item.map_err(fail)?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .map_err(fail)?
            .to_str()
            .ok_or_else(|| "workspace_non_utf8_path".to_owned())?
            .to_owned();
        if relative == "spool" {
            continue;
        }
        validate_path(&relative).map_err(fail)?;
        if entries.len() >= MAX_WORKSPACE_ENTRIES {
            return Err("workspace_entry_limit".to_owned());
        }
        let metadata = fs::symlink_metadata(&path).map_err(fail)?;
        if metadata.is_dir() {
            entries.push(WorkspaceEntry::Directory { path: relative });
            visit(root, &path, depth + 1, entries, bytes)?;
        } else if metadata.is_file() && metadata.nlink() == 1 {
            if metadata.len() > (MAX_WORKSPACE_BYTES - *bytes) as u64 {
                return Err("workspace_content_limit".to_owned());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)
                .map_err(fail)?;
            let opened = file.metadata().map_err(fail)?;
            if !opened.is_file()
                || opened.nlink() != 1
                || opened.dev() != metadata.dev()
                || opened.ino() != metadata.ino()
            {
                return Err("workspace_file_replaced".to_owned());
            }
            let mut contents = Vec::new();
            file.take((MAX_WORKSPACE_BYTES + 1 - *bytes) as u64)
                .read_to_end(&mut contents)
                .map_err(fail)?;
            *bytes += contents.len();
            if *bytes > MAX_WORKSPACE_BYTES {
                return Err("workspace_content_limit".to_owned());
            }
            entries.push(WorkspaceEntry::File {
                path: relative,
                executable: metadata.permissions().mode() & 0o111 != 0,
                contents,
            });
        } else {
            return Err("workspace_unsupported_entry".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_transfer_preserves_contents_directories_and_executable_bit() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("a")).unwrap();
        fs::create_dir(source.path().join("empty")).unwrap();
        fs::create_dir(source.path().join("spool")).unwrap();
        fs::write(source.path().join("spool/log"), b"excluded").unwrap();
        fs::write(source.path().join("a/tool"), b"hello\0world").unwrap();
        fs::set_permissions(
            source.path().join("a/tool"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let snapshot = capture(source.path(), &File::open(source.path()).unwrap()).unwrap();
        assert_eq!(snapshot.entries.len(), 3);
        let target = tempfile::tempdir().unwrap();
        seed(target.path(), &snapshot).unwrap();
        assert_eq!(
            fs::read(target.path().join("a/tool")).unwrap(),
            b"hello\0world"
        );
        assert!(target.path().join("empty").is_dir());
        assert_eq!(
            fs::metadata(target.path().join("a/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o100,
            0o100
        );
    }
    #[test]
    fn capture_enforces_entry_depth_and_total_content_bounds() {
        for kind in 0..3 {
            let source = tempfile::tempdir().unwrap();
            match kind {
                0 => {
                    for n in 0..33 {
                        fs::create_dir(source.path().join(format!("d{n}"))).unwrap();
                    }
                }
                1 => {
                    let mut path = source.path().to_owned();
                    for _ in 0..9 {
                        path.push("d");
                        fs::create_dir(&path).unwrap();
                    }
                }
                _ => {
                    fs::write(source.path().join("a"), vec![1; 4096]).unwrap();
                    fs::write(source.path().join("b"), vec![2; 4097]).unwrap();
                }
            }
            assert!(
                capture(source.path(), &File::open(source.path()).unwrap()).is_err(),
                "kind {kind}"
            );
        }
    }

    #[test]
    fn capture_refuses_links_oversize_and_replaced_workspace() {
        for kind in 0..4 {
            let source = tempfile::tempdir().unwrap();
            let root = source.path().join("workspace");
            fs::create_dir(&root).unwrap();
            let control = File::open(&root).unwrap();
            match kind {
                0 => std::os::unix::fs::symlink("missing", root.join("link")).unwrap(),
                1 => {
                    fs::write(root.join("file"), b"x").unwrap();
                    fs::hard_link(root.join("file"), root.join("link")).unwrap();
                }
                2 => fs::write(root.join("large"), vec![1; 8193]).unwrap(),
                _ => {
                    fs::rename(&root, source.path().join("old")).unwrap();
                    fs::create_dir(&root).unwrap();
                }
            }
            assert!(capture(&root, &control).is_err(), "kind {kind}");
        }
    }
}
