use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use mcloving_migration_package::{MAX_PACKAGE_BYTES, generate, verify};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.as_slice() {
        [_, command, repository] if command == "generate" => {
            io::stdout()
                .lock()
                .write_all(&generate(Path::new(repository))?)?;
        }
        [_, command, repository, output] if command == "generate" => {
            let bytes = generate(Path::new(repository))?;
            publish_new_file(Path::new(output), &bytes)?;
        }
        [_, command, package, repository] if command == "verify" => {
            let bytes = read_regular_bounded(Path::new(package))?;
            let receipt = verify(&bytes, Path::new(repository))?;
            println!("schema={}", receipt.schema);
            println!("package_sha256={}", receipt.package_sha256);
            println!("packaged_cases={}", receipt.packaged_cases);
            println!("rejected_cases={}", receipt.rejected_cases);
            println!(
                "admitted_state_dependencies={}",
                receipt.admitted_state_dependencies
            );
            println!("production_authority={}", receipt.production_authority);
        }
        _ => {
            return Err(
                "usage: mcloving-migration-package generate REPOSITORY_ROOT [OUTPUT]\n       mcloving-migration-package verify PACKAGE REPOSITORY_ROOT"
                    .into(),
            );
        }
    }
    Ok(())
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn publish_new_file(output: &Path, bytes: &[u8]) -> io::Result<()> {
    let file_name = output.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "package output must name a file",
        )
    })?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (temporary, mut file) = create_temporary_sibling(parent, file_name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::hard_link(&temporary.path, output)?;
    if let Err(error) = sync_directory(parent) {
        let _ = fs::remove_file(output);
        let _ = sync_directory(parent);
        return Err(error);
    }

    // Publication is complete and durable. A failed best-effort cleanup must
    // not report generation as failed and make a retry collide with the
    // already-published, complete destination.
    if fs::remove_file(&temporary.path).is_ok() {
        let _ = sync_directory(parent);
    }
    Ok(())
}

fn create_temporary_sibling(parent: &Path, file_name: &OsStr) -> io::Result<(TemporaryPath, File)> {
    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let path = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((TemporaryPath { path }, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a temporary package path",
    ))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    let directory = File::open(path)?;
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
    };
    directory.sync_all()
}

struct TemporaryPath {
    path: std::path::PathBuf,
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn read_regular_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_PACKAGE_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package exceeds byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_is_atomic_and_leaves_no_staging_name() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");

        publish_new_file(&output, b"complete package").unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"complete package");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn publication_never_replaces_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");
        fs::write(&output, b"existing package").unwrap();

        let error = publish_new_file(&output, b"replacement package").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&output).unwrap(), b"existing package");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
