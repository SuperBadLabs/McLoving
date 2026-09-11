//! Declared artifact collection (PAR-014): after a stage's steps, the regular
//! files under the attempt workspace that match its declarations are found
//! by a descriptor-relative walk that never follows a link, opened without
//! following a link and re-identified after the open, and counted against
//! bounds before the first byte leaves the agent. A link that a declaration
//! would collect or descend into refuses the whole set by name: a step that
//! plants a link to a host file gets a named refusal, not an upload.

use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use mcloving_domain::artifacts::{
    ArtifactSpec, MAX_ARTIFACT_FILES_PER_ATTEMPT, MAX_ARTIFACT_OBJECT_NAME_BYTES,
    MAX_ARTIFACT_WALK_DEPTH, MAX_ARTIFACT_WALK_ENTRIES, MAX_ATTEMPT_ARTIFACT_BYTES,
    pattern_may_descend,
};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, fstat, fstatat};

/// The agent-owned directory at the workspace root that holds the executor's
/// spools; never an artifact, whatever a pattern says.
const AGENT_SPOOL_DIRECTORY: &str = "spool";

/// One regular file to upload: the object name it registers under, its
/// length as identified at open, and the opened descriptor.
#[derive(Debug)]
pub struct CollectedFile {
    pub name: String,
    pub relative_path: String,
    pub bytes: u64,
    pub file: File,
}

/// Why a declared set is not collected. Every variant names its offender,
/// so the attempt's failure reason says which path or bound refused it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionRefusal {
    /// A link the declarations would collect or descend into.
    Link(String),
    /// A matching entry that is neither a regular file nor a directory.
    NotRegular(String),
    /// A matching file whose identity changed between the walk and the open.
    IdentityChanged(String),
    /// A matching file whose object name would exceed the store's bound.
    NameTooLong(String),
    /// A matching entry whose name is not UTF-8 and so cannot be named.
    UnnameableEntry(String),
    /// More matching files than one attempt may upload.
    TooManyFiles(usize),
    /// More matching bytes than one attempt may upload.
    TooManyBytes(u64),
    /// A directory the declarations descend into below the depth bound.
    TooDeep(String),
    /// More directory entries than the walk visits.
    TooManyEntries(usize),
}

impl fmt::Display for CollectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Link(path) => write!(f, "artifact_refused:link:{path}"),
            Self::NotRegular(path) => write!(f, "artifact_refused:not_regular:{path}"),
            Self::IdentityChanged(path) => {
                write!(f, "artifact_refused:identity_changed:{path}")
            }
            Self::NameTooLong(path) => write!(f, "artifact_refused:name_too_long:{path}"),
            Self::UnnameableEntry(path) => write!(f, "artifact_refused:unnameable:{path}"),
            Self::TooManyFiles(count) => write!(f, "artifact_refused:too_many_files:{count}"),
            Self::TooManyBytes(bytes) => write!(f, "artifact_refused:too_many_bytes:{bytes}"),
            Self::TooDeep(path) => write!(f, "artifact_refused:too_deep:{path}"),
            Self::TooManyEntries(count) => {
                write!(f, "artifact_refused:too_many_entries:{count}")
            }
        }
    }
}

#[derive(Debug)]
pub enum CollectionError {
    Refused(CollectionRefusal),
    Io(std::io::Error),
}

impl From<std::io::Error> for CollectionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<nix::Error> for CollectionError {
    fn from(error: nix::Error) -> Self {
        Self::Io(std::io::Error::from(error))
    }
}

impl From<CollectionRefusal> for CollectionError {
    fn from(refusal: CollectionRefusal) -> Self {
        Self::Refused(refusal)
    }
}

struct Walk<'a> {
    specs: &'a [ArtifactSpec],
    files: Vec<CollectedFile>,
    bytes: u64,
    entries: usize,
}

/// Collects every regular file under `workspace` that a declaration matches.
/// The workspace itself is opened by path once; everything below is reached
/// descriptor-relative with `O_NOFOLLOW`.
pub fn collect(
    workspace: &Path,
    specs: &[ArtifactSpec],
) -> Result<Vec<CollectedFile>, CollectionError> {
    let root = File::open(workspace)?;
    let root_stat = fstat(&root)?;
    if !is_directory(&root_stat) {
        return Err(std::io::Error::other("workspace root is not a directory").into());
    }
    let root: OwnedFd = root.into();
    let mut walk = Walk {
        specs,
        files: Vec::new(),
        bytes: 0,
        entries: 0,
    };
    walk_directory(&mut walk, &root, "", 0)?;
    // Deterministic upload order, and a stable name for the first refusal
    // a reviewer sees in the attempt's reason.
    walk.files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(walk.files)
}

fn walk_directory(
    walk: &mut Walk<'_>,
    directory: &OwnedFd,
    prefix: &str,
    depth: usize,
) -> Result<(), CollectionError> {
    let mut reader = Dir::from_fd(directory.try_clone()?)?;
    for entry in reader.iter() {
        let entry = entry?;
        let raw_name = entry.file_name();
        if raw_name.to_bytes() == b"." || raw_name.to_bytes() == b".." {
            continue;
        }
        walk.entries += 1;
        if walk.entries > MAX_ARTIFACT_WALK_ENTRIES {
            return Err(CollectionRefusal::TooManyEntries(walk.entries).into());
        }
        let display_name = String::from_utf8_lossy(raw_name.to_bytes()).into_owned();
        let path = if prefix.is_empty() {
            display_name.clone()
        } else {
            format!("{prefix}/{display_name}")
        };
        if depth == 0 && display_name == AGENT_SPOOL_DIRECTORY {
            continue;
        }
        let stat = fstatat(directory, raw_name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        let collects = walk.specs.iter().any(|spec| spec.matches(&path));
        let descends = walk.specs.iter().any(|spec| {
            spec.paths
                .iter()
                .any(|pattern| pattern_may_descend(pattern, &path))
        });
        if is_link(&stat) {
            if collects || descends {
                return Err(CollectionRefusal::Link(path).into());
            }
            continue;
        }
        if is_directory(&stat) {
            if !descends {
                continue;
            }
            if depth + 1 > MAX_ARTIFACT_WALK_DEPTH {
                return Err(CollectionRefusal::TooDeep(path).into());
            }
            let child = openat(
                directory,
                raw_name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )?;
            let child_stat = fstat(&child)?;
            if !same_identity(&stat, &child_stat) {
                return Err(CollectionRefusal::IdentityChanged(path).into());
            }
            walk_directory(walk, &child, &path, depth + 1)?;
            continue;
        }
        if !collects {
            continue;
        }
        if !is_regular(&stat) {
            return Err(CollectionRefusal::NotRegular(path).into());
        }
        if std::str::from_utf8(raw_name.to_bytes()).is_err() {
            return Err(CollectionRefusal::UnnameableEntry(path).into());
        }
        let spec = walk
            .specs
            .iter()
            .find(|spec| spec.matches(&path))
            .expect("a collected path matches a declaration");
        let name = format!("{}/{path}", spec.name);
        if name.len() > MAX_ARTIFACT_OBJECT_NAME_BYTES {
            return Err(CollectionRefusal::NameTooLong(path).into());
        }
        let opened = open_regular(directory, raw_name)?;
        let opened_stat = fstat(&opened)?;
        if !same_identity(&stat, &opened_stat) || !is_regular(&opened_stat) {
            return Err(CollectionRefusal::IdentityChanged(path).into());
        }
        let bytes = u64::try_from(opened_stat.st_size).unwrap_or(u64::MAX);
        if walk.files.len() + 1 > MAX_ARTIFACT_FILES_PER_ATTEMPT {
            return Err(CollectionRefusal::TooManyFiles(walk.files.len() + 1).into());
        }
        walk.bytes = walk.bytes.saturating_add(bytes);
        if walk.bytes > MAX_ATTEMPT_ARTIFACT_BYTES {
            return Err(CollectionRefusal::TooManyBytes(walk.bytes).into());
        }
        walk.files.push(CollectedFile {
            name,
            relative_path: path,
            bytes,
            file: File::from(opened),
        });
    }
    Ok(())
}

fn open_regular(directory: &OwnedFd, name: &CStr) -> Result<OwnedFd, CollectionError> {
    Ok(openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        nix::sys::stat::Mode::empty(),
    )?)
}

fn file_type(stat: &FileStat) -> nix::libc::mode_t {
    stat.st_mode & nix::libc::S_IFMT
}

fn is_directory(stat: &FileStat) -> bool {
    file_type(stat) == nix::libc::S_IFDIR
}

fn is_link(stat: &FileStat) -> bool {
    file_type(stat) == nix::libc::S_IFLNK
}

fn is_regular(stat: &FileStat) -> bool {
    file_type(stat) == nix::libc::S_IFREG
}

fn same_identity(a: &FileStat, b: &FileStat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn spec(name: &str, paths: &[&str]) -> ArtifactSpec {
        ArtifactSpec {
            name: name.to_owned(),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    fn workspace() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join("target/debug/deep")).unwrap();
        std::fs::create_dir_all(root.join("spool/step-0")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("target/build.log"), b"top").unwrap();
        std::fs::write(root.join("target/debug/deep/x.log"), b"deep").unwrap();
        std::fs::write(root.join("target/debug/x.txt"), b"not a log").unwrap();
        std::fs::write(root.join("spool/step-0/stdout.log"), b"agent-owned").unwrap();
        std::fs::write(root.join("other/report-1.xml"), b"<r/>").unwrap();
        directory
    }

    #[test]
    fn matching_regular_files_are_collected_by_object_name_in_order() {
        let directory = workspace();
        let files = collect(
            directory.path(),
            &[
                spec("logs", &["**/*.log"]),
                spec("reports", &["other/report-?.xml"]),
            ],
        )
        .unwrap();
        let names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();
        // The agent's spool is never an artifact, however wide the pattern.
        assert_eq!(
            names,
            [
                "logs/target/build.log",
                "logs/target/debug/deep/x.log",
                "reports/other/report-1.xml",
            ]
        );
        let mut content = String::new();
        let mut first = files.into_iter().next().unwrap();
        first.file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "top");
        assert_eq!(first.bytes, 3);
        assert_eq!(first.relative_path, "target/build.log");
    }

    #[test]
    fn a_link_the_declarations_would_collect_or_enter_refuses_the_set_by_name() {
        let directory = workspace();
        std::os::unix::fs::symlink("/etc/hostname", directory.path().join("target/planted.log"))
            .unwrap();
        let error = collect(directory.path(), &[spec("logs", &["target/*.log"])]).unwrap_err();
        let CollectionError::Refused(refusal) = error else {
            panic!("a link is a refusal, not an I/O error");
        };
        assert_eq!(
            refusal,
            CollectionRefusal::Link("target/planted.log".to_owned())
        );
        assert_eq!(
            refusal.to_string(),
            "artifact_refused:link:target/planted.log"
        );
        // A link the declarations would descend into is refused too, before
        // anything below it is looked at.
        std::fs::remove_file(directory.path().join("target/planted.log")).unwrap();
        std::os::unix::fs::symlink("/etc", directory.path().join("outward")).unwrap();
        let error = collect(directory.path(), &[spec("cfg", &["outward/*"])]).unwrap_err();
        assert!(matches!(
            error,
            CollectionError::Refused(CollectionRefusal::Link(path)) if path == "outward"
        ));
        // A link nothing declares is simply not an artifact.
        let files = collect(directory.path(), &[spec("logs", &["target/*.log"])]).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn non_regular_matches_and_bounds_refuse_by_name() {
        let directory = workspace();
        nix::unistd::mkfifo(
            &directory.path().join("target/pipe.log"),
            nix::sys::stat::Mode::S_IRWXU,
        )
        .unwrap();
        let error = collect(directory.path(), &[spec("logs", &["target/*.log"])]).unwrap_err();
        assert!(matches!(
            error,
            CollectionError::Refused(CollectionRefusal::NotRegular(path)) if path == "target/pipe.log"
        ));
        std::fs::remove_file(directory.path().join("target/pipe.log")).unwrap();
        // A path whose object name would pass the store's 512-byte bound:
        // three nested 200-byte components under the walk.
        let component = "n".repeat(200);
        let deep = directory
            .path()
            .join("target")
            .join(&component)
            .join(&component)
            .join(&component);
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("x.log"), b"x").unwrap();
        let error = collect(directory.path(), &[spec("logs", &["target/**/*.log"])]).unwrap_err();
        assert!(matches!(
            error,
            CollectionError::Refused(CollectionRefusal::NameTooLong(_))
        ));
    }
}
