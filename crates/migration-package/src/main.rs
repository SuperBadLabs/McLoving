use std::env;
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(all(test, unix))]
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Read as _, Write as _};
#[cfg(unix)]
use std::path::Component;
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use mcloving_migration_package::{
    MAX_PACKAGE_BYTES, MAX_PRIVATE_PACKAGE_BYTES, PrivateGenerationInputs,
    PrivateVerificationInputs, generate, generate_private, verify, verify_private,
};

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
            let repository = Path::new(repository);
            let bytes = generate(repository)?;
            verify(&bytes, repository)?;
            io::stdout().lock().write_all(&bytes)?;
        }
        [_, command, repository, output] if command == "generate" => {
            let repository = Path::new(repository);
            let bytes = generate(repository)?;
            verify(&bytes, repository)?;
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
            println!("package_complete={}", receipt.package_complete);
            println!("production_authority={}", receipt.production_authority);
        }
        [
            _,
            command,
            repository,
            sealed_history,
            forward_evidence,
            forward_pin,
            forward_implementation_pin,
            reverse_evidence,
            reverse_pin,
            reverse_implementation_pin,
            output,
        ] if command == "generate-private" => {
            let forward_pin = read_owner_pin(Path::new(forward_pin))?;
            let reverse_pin = read_owner_pin(Path::new(reverse_pin))?;
            let forward_implementation_pin = read_owner_pin(Path::new(forward_implementation_pin))?;
            let reverse_implementation_pin = read_owner_pin(Path::new(reverse_implementation_pin))?;
            let verification = PrivateVerificationInputs {
                sealed_history_root: Path::new(sealed_history),
                expected_forward_manifest_sha256: &forward_pin,
                expected_reverse_manifest_sha256: &reverse_pin,
                expected_forward_implementation_sha256: &forward_implementation_pin,
                expected_reverse_implementation_sha256: &reverse_implementation_pin,
                expected_package_sha256: None,
            };
            let inputs = PrivateGenerationInputs {
                forward_evidence_root: Path::new(forward_evidence),
                reverse_evidence_root: Path::new(reverse_evidence),
                verification,
            };
            let bytes = generate_private(Path::new(repository), &inputs)?;
            publish_new_private_file(Path::new(output), &bytes)?;
        }
        [
            _,
            command,
            package,
            package_pin,
            repository,
            sealed_history,
            forward_pin,
            forward_implementation_pin,
            reverse_pin,
            reverse_implementation_pin,
        ] if command == "verify-private" => {
            let bytes =
                read_private_regular_bounded(Path::new(package), MAX_PRIVATE_PACKAGE_BYTES)?;
            let package_pin = read_owner_pin(Path::new(package_pin))?;
            let forward_pin = read_owner_pin(Path::new(forward_pin))?;
            let reverse_pin = read_owner_pin(Path::new(reverse_pin))?;
            let forward_implementation_pin = read_owner_pin(Path::new(forward_implementation_pin))?;
            let reverse_implementation_pin = read_owner_pin(Path::new(reverse_implementation_pin))?;
            let inputs = PrivateVerificationInputs {
                sealed_history_root: Path::new(sealed_history),
                expected_forward_manifest_sha256: &forward_pin,
                expected_reverse_manifest_sha256: &reverse_pin,
                expected_forward_implementation_sha256: &forward_implementation_pin,
                expected_reverse_implementation_sha256: &reverse_implementation_pin,
                expected_package_sha256: Some(&package_pin),
            };
            let receipt = verify_private(&bytes, Path::new(repository), &inputs)?;
            println!("schema={}", receipt.schema);
            println!("packaged_cases={}", receipt.packaged_cases);
            println!("rejected_cases={}", receipt.rejected_cases);
            println!(
                "admitted_state_dependencies={}",
                receipt.admitted_state_dependencies
            );
            println!("package_complete={}", receipt.package_complete);
            println!("shadow_eligible={}", receipt.shadow_eligible);
            println!("production_authority={}", receipt.production_authority);
        }
        _ => {
            return Err(
                "usage: mcloving-migration-package generate REPOSITORY_ROOT [OUTPUT]\n       mcloving-migration-package verify PACKAGE REPOSITORY_ROOT\n       mcloving-migration-package generate-private REPOSITORY_ROOT SEALED_HISTORY FORWARD_EVIDENCE FORWARD_MANIFEST_PIN_FILE FORWARD_IMPLEMENTATION_PIN_FILE REVERSE_EVIDENCE REVERSE_MANIFEST_PIN_FILE REVERSE_IMPLEMENTATION_PIN_FILE OUTPUT\n       mcloving-migration-package verify-private PACKAGE PACKAGE_PIN_FILE REPOSITORY_ROOT SEALED_HISTORY FORWARD_MANIFEST_PIN_FILE FORWARD_IMPLEMENTATION_PIN_FILE REVERSE_MANIFEST_PIN_FILE REVERSE_IMPLEMENTATION_PIN_FILE"
                    .into(),
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
fn publish_new_file(output: &Path, bytes: &[u8]) -> io::Result<()> {
    publish_new_file_with_policy(
        output,
        bytes,
        false,
        sync_open_directory,
        remove_relative_file,
    )
}

#[cfg(unix)]
fn publish_new_private_file(output: &Path, bytes: &[u8]) -> io::Result<()> {
    publish_new_file_with_policy(
        output,
        bytes,
        true,
        sync_open_directory,
        remove_relative_file,
    )
}

#[cfg(not(unix))]
fn publish_new_private_file(_output: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-private package publication is unsupported on this platform",
    ))
}

#[cfg(not(unix))]
fn publish_new_file(_output: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe descriptor-relative package publication is unsupported on this platform; use stdout and an external atomic publisher",
    ))
}

#[cfg(all(test, unix))]
fn publish_new_file_with<SyncDirectory, RemovePublished>(
    output: &Path,
    bytes: &[u8],
    sync_directory: SyncDirectory,
    remove_published: RemovePublished,
) -> io::Result<()>
where
    SyncDirectory: FnMut(&rustix::fd::OwnedFd) -> io::Result<()>,
    RemovePublished: FnMut(&rustix::fd::OwnedFd, &OsStr) -> io::Result<()>,
{
    publish_new_file_with_policy(output, bytes, false, sync_directory, remove_published)
}

#[cfg(all(test, unix))]
fn publish_new_private_file_with<SyncDirectory, RemovePublished>(
    output: &Path,
    bytes: &[u8],
    sync_directory: SyncDirectory,
    remove_published: RemovePublished,
) -> io::Result<()>
where
    SyncDirectory: FnMut(&rustix::fd::OwnedFd) -> io::Result<()>,
    RemovePublished: FnMut(&rustix::fd::OwnedFd, &OsStr) -> io::Result<()>,
{
    publish_new_file_with_policy(output, bytes, true, sync_directory, remove_published)
}

#[cfg(unix)]
fn publish_new_file_with_policy<SyncDirectory, RemovePublished>(
    output: &Path,
    bytes: &[u8],
    require_owner_only_parent: bool,
    mut sync_directory: SyncDirectory,
    mut remove_published: RemovePublished,
) -> io::Result<()>
where
    SyncDirectory: FnMut(&rustix::fd::OwnedFd) -> io::Result<()>,
    RemovePublished: FnMut(&rustix::fd::OwnedFd, &OsStr) -> io::Result<()>,
{
    if require_owner_only_parent {
        require_private_parent_custody(output)?;
    }
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
    let parent_directory = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(os_error)?;
    if require_owner_only_parent {
        let metadata = rustix::fs::fstat(&parent_directory).map_err(os_error)?;
        if metadata.st_uid != nix::unistd::geteuid().as_raw() || metadata.st_mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private package parent must belong to the invoking owner and deny group/other access",
            ));
        }
    }
    let (mut temporary, mut file) = create_temporary_sibling(&parent_directory, file_name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    if let Err(error) = rustix::fs::linkat(
        &parent_directory,
        temporary.name.as_os_str(),
        &parent_directory,
        file_name,
        rustix::fs::AtFlags::empty(),
    ) {
        if error == rustix::io::Errno::EXIST {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "package destination already exists; verify and reconcile it before retrying",
            ));
        }
        return Err(os_error(error));
    }
    if let Err(publication_error) = sync_directory(&parent_directory) {
        match remove_published(&parent_directory, file_name) {
            Ok(()) => match sync_directory(&parent_directory) {
                Ok(()) => return Err(publication_error),
                Err(rollback_sync_error) => {
                    return Err(ambiguous_publication_error(
                        &publication_error,
                        "destination removal could not be made durable",
                        &rollback_sync_error,
                    ));
                }
            },
            Err(rollback_remove_error) => {
                return Err(ambiguous_publication_error(
                    &publication_error,
                    "destination removal failed",
                    &rollback_remove_error,
                ));
            }
        }
    }

    if require_owner_only_parent {
        remove_published(&parent_directory, temporary.name.as_os_str()).map_err(|error| {
            io::Error::other(format!(
                "E_PRIVATE_PUBLICATION_CLEANUP: staging-link removal failed after durable publication ({error}); destination requires explicit verification and reconciliation"
            ))
        })?;
        temporary.active = false;
        sync_directory(&parent_directory).map_err(|error| {
            io::Error::other(format!(
                "E_PRIVATE_PUBLICATION_CLEANUP: staging-link removal could not be made durable ({error}); destination requires explicit verification and reconciliation"
            ))
        })?;
        return Ok(());
    }

    // Public package publication is complete and durable. Its staging-name
    // cleanup remains best effort because an extra public link does not make
    // the public verifier reject an otherwise complete destination.
    if temporary.remove().is_ok() {
        let _ = sync_directory(&parent_directory);
    }
    Ok(())
}

#[cfg(unix)]
fn ambiguous_publication_error(
    publication_error: &io::Error,
    rollback_stage: &str,
    rollback_error: &io::Error,
) -> io::Error {
    io::Error::other(format!(
        "E_PUBLICATION_ROLLBACK_AMBIGUOUS: parent-directory sync failed ({publication_error}); {rollback_stage} ({rollback_error}); destination state is poisoned and requires explicit verification and reconciliation"
    ))
}

#[cfg(unix)]
fn create_temporary_sibling<'a>(
    parent: &'a rustix::fd::OwnedFd,
    file_name: &OsStr,
) -> io::Result<(TemporaryPath<'a>, File)> {
    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        match rustix::fs::openat(
            parent,
            temporary_name.as_os_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_bits_truncate(0o600),
        ) {
            Ok(file) => {
                return Ok((
                    TemporaryPath {
                        parent,
                        name: temporary_name,
                        active: true,
                    },
                    File::from(file),
                ));
            }
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(os_error(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a temporary package path",
    ))
}

#[cfg(unix)]
fn sync_open_directory(parent: &rustix::fd::OwnedFd) -> io::Result<()> {
    rustix::fs::fsync(parent).map_err(os_error)
}

#[cfg(unix)]
fn remove_relative_file(parent: &rustix::fd::OwnedFd, name: &OsStr) -> io::Result<()> {
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()).map_err(os_error)
}

#[cfg(unix)]
fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(unix)]
struct TemporaryPath<'a> {
    parent: &'a rustix::fd::OwnedFd,
    name: OsString,
    active: bool,
}

#[cfg(unix)]
impl TemporaryPath<'_> {
    fn remove(&mut self) -> io::Result<()> {
        remove_relative_file(self.parent, &self.name)?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TemporaryPath<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = remove_relative_file(self.parent, &self.name);
        }
    }
}

fn read_regular_bounded(path: &Path) -> io::Result<Vec<u8>> {
    read_regular_bounded_with_limit(path, MAX_PACKAGE_BYTES)
}

fn read_regular_bounded_with_limit(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    read_regular_bounded_with_policy(path, limit, false)
}

fn read_regular_bounded_with_policy(
    path: &Path,
    limit: usize,
    require_owner_only: bool,
) -> io::Result<Vec<u8>> {
    #[cfg(not(unix))]
    let _ = require_owner_only;
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
    #[cfg(unix)]
    let mut file = if require_owner_only {
        open_private_regular_descriptor(path)?
    } else {
        options.open(path)?
    };
    #[cfg(not(unix))]
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if require_owner_only
            && (metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner-private input has the wrong owner, is linked, or grants group/other access",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package exceeds byte limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_private_regular_descriptor(path: &Path) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let components = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name)),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "owner-private path contains an unsafe component",
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let (leaf, parents) = components.split_last().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner-private path has no file name",
        )
    })?;
    let directory_flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let mut directory =
        rustix::fs::open(Path::new("/"), directory_flags, rustix::fs::Mode::empty())
            .map_err(os_error)?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    for component in parents {
        directory = rustix::fs::openat(
            &directory,
            *component,
            directory_flags,
            rustix::fs::Mode::empty(),
        )
        .map_err(os_error)?;
        let metadata = rustix::fs::fstat(&directory).map_err(os_error)?;
        let trusted_sticky_root = metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
        if metadata.st_mode & 0o022 != 0 && metadata.st_uid != effective_uid && !trusted_sticky_root
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner-private path traverses a redirectable foreign directory",
            ));
        }
    }
    let parent_metadata = rustix::fs::fstat(&directory).map_err(os_error)?;
    if parent_metadata.st_uid != effective_uid || parent_metadata.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owner-private input parent has the wrong owner or broad permissions",
        ));
    }
    let file = rustix::fs::openat(
        &directory,
        *leaf,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(os_error)?;
    Ok(File::from(file))
}

#[cfg(unix)]
fn require_private_parent_custody(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut current = absolute.parent();
    let mut immediate = true;
    while let Some(directory) = current {
        let metadata = std::fs::symlink_metadata(directory)?;
        let trusted_sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.mode() & 0o022 != 0
                && metadata.uid() != nix::unistd::geteuid().as_raw()
                && !trusted_sticky_root)
            || (immediate
                && (metadata.uid() != nix::unistd::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner-private input/output has a symlinked, writable, or non-owner parent",
            ));
        }
        immediate = false;
        current = directory.parent();
    }
    Ok(())
}

fn read_owner_pin(path: &Path) -> io::Result<String> {
    let bytes = read_private_regular_bounded(path, 128)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "owner pin is not UTF-8"))?;
    let pin = value.strip_suffix('\n').unwrap_or(value);
    if pin.len() != 64
        || pin.contains('\n')
        || !pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner pin is not canonical lowercase SHA-256",
        ));
    }
    Ok(pin.to_owned())
}

fn read_private_regular_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owner-private package inputs require Unix mode and link validation",
        ));
    }
    #[cfg(unix)]
    {
        read_regular_bounded_with_policy(path, limit, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn publication_is_atomic_and_leaves_no_staging_name() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");

        publish_new_file(&output, b"complete package").unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"complete package");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn publication_never_replaces_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");
        fs::write(&output, b"existing package").unwrap();

        let error = publish_new_file(&output, b"replacement package").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("verify and reconcile"));
        assert_eq!(fs::read(&output).unwrap(), b"existing package");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn failed_publication_rollback_is_reported_as_poisoned() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");

        let error = publish_new_file_with(
            &output,
            b"complete package",
            |_| Err(io::Error::other("injected directory sync failure")),
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected rollback failure",
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error
                .to_string()
                .contains("E_PUBLICATION_ROLLBACK_AMBIGUOUS")
        );
        assert!(
            error
                .to_string()
                .contains("requires explicit verification and reconciliation")
        );
        assert_eq!(fs::read(&output).unwrap(), b"complete package");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn publication_survives_parent_path_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        let moved_parent = root.path().join("moved-parent");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("migration-package.json");
        let original_parent = parent.clone();
        let moved_parent_for_sync = moved_parent.clone();
        let mut replaced = false;

        publish_new_file_with(
            &output,
            b"complete package",
            |directory| {
                if !replaced {
                    fs::rename(&original_parent, &moved_parent_for_sync)?;
                    fs::create_dir(&original_parent)?;
                    replaced = true;
                }
                sync_open_directory(directory)
            },
            remove_relative_file,
        )
        .unwrap();

        assert!(!output.exists());
        assert_eq!(
            fs::read(moved_parent.join("migration-package.json")).unwrap(),
            b"complete package"
        );
        assert_eq!(fs::read_dir(&moved_parent).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn private_inputs_reject_broad_modes_and_multiple_links() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input = directory.path().join("private-package.json");
        fs::write(&input, b"private").unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private_regular_bounded(&input, 128).is_err());

        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        let second_link = directory.path().join("second-link.json");
        fs::hard_link(&input, second_link).unwrap();
        assert!(read_private_regular_bounded(&input, 128).is_err());

        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let real_input = real_parent.join("pin");
        fs::write(&real_input, b"private").unwrap();
        fs::set_permissions(&real_input, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.path().join("parent-alias");
        std::os::unix::fs::symlink(&real_parent, &alias).unwrap();
        assert!(read_private_regular_bounded(&alias.join("pin"), 128).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_publication_rejects_a_broad_parent_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let output = directory.path().join("private-package.json");

        assert!(publish_new_private_file(&output, b"private").is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_publication_reports_staging_cleanup_failure() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("private-package.json");

        let error =
            publish_new_private_file_with(&output, b"private", sync_open_directory, |_, _| {
                Err(io::Error::other("injected staging cleanup failure"))
            })
            .unwrap_err();

        assert!(error.to_string().contains("E_PRIVATE_PUBLICATION_CLEANUP"));
        assert_eq!(fs::read(&output).unwrap(), b"private");
    }

    #[cfg(unix)]
    #[test]
    fn private_publication_reports_nondurable_cleanup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("private-package.json");
        let mut syncs = 0;

        let error = publish_new_private_file_with(
            &output,
            b"private",
            |_| {
                syncs += 1;
                if syncs == 1 {
                    Ok(())
                } else {
                    Err(io::Error::other("injected cleanup sync failure"))
                }
            },
            remove_relative_file,
        )
        .unwrap_err();

        assert!(error.to_string().contains("E_PRIVATE_PUBLICATION_CLEANUP"));
        assert_eq!(fs::read(&output).unwrap(), b"private");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(not(unix))]
    #[test]
    fn file_publication_is_explicitly_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("migration-package.json");

        let error = publish_new_file(&output, b"complete package").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!output.exists());
    }
}
