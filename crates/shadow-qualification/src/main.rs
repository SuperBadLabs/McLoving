use std::env;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

use mcloving_migration_package::{MAX_PRIVATE_PACKAGE_BYTES, PrivateVerificationInputs};
use mcloving_shadow_qualification::{
    VerificationReceipt, seal_private_session, verify_private_session,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use sha2::{Digest as _, Sha256};

const MAX_SESSION_BYTES: usize = 262_144;
const MAX_PIN_BYTES: usize = 65;

fn main() {
    if let Err(error) = run() {
        eprintln!("shadow qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.as_slice() {
        [_, command, source_key, shadow_key] if command == "generate-keys" => {
            let random = SystemRandom::new();
            let source = Ed25519KeyPair::generate_pkcs8(&random)
                .map_err(|_| "could not generate source-capture Ed25519 key")?;
            let shadow = Ed25519KeyPair::generate_pkcs8(&random)
                .map_err(|_| "could not generate shadow-replay Ed25519 key")?;
            publish_owner_private(Path::new(source_key), source.as_ref())?;
            if let Err(error) = publish_owner_private(Path::new(shadow_key), shadow.as_ref()) {
                rollback_new_private(Path::new(source_key)).map_err(|rollback| {
                    io::Error::other(format!(
                        "shadow key publication failed ({error}); source-key rollback failed ({rollback}); reconcile both paths"
                    ))
                })?;
                return Err(error.into());
            }
            println!("source_capture_key_created=true");
            println!("shadow_replay_key_created=true");
        }
        [
            _,
            command,
            template,
            source_key,
            shadow_key,
            session,
            session_pin,
            package,
            package_pin,
            repository,
            sealed_history,
            forward_manifest_pin,
            forward_implementation_pin,
            reverse_manifest_pin,
            reverse_implementation_pin,
            expected_head,
        ] if command == "seal" => {
            let template_bytes = read_owner_private(Path::new(template), MAX_SESSION_BYTES)?;
            let source_key = read_owner_private(Path::new(source_key), 1_024)?;
            let shadow_key = read_owner_private(Path::new(shadow_key), 1_024)?;
            let session_bytes = seal_private_session(&template_bytes, &source_key, &shadow_key)?;
            let computed_session_pin = digest_hex(&session_bytes);
            let (package_bytes, pins) = read_package_inputs(
                package,
                package_pin,
                forward_manifest_pin,
                forward_implementation_pin,
                reverse_manifest_pin,
                reverse_implementation_pin,
            )?;
            let package_inputs = private_inputs(sealed_history, &pins);
            let receipt = verify_private_session(
                &session_bytes,
                &computed_session_pin,
                &package_bytes,
                Path::new(repository),
                &package_inputs,
                expected_head,
            )?;
            publish_owner_private(Path::new(session), &session_bytes)?;
            let pin_bytes = format!("{computed_session_pin}\n");
            if let Err(error) = publish_owner_private(Path::new(session_pin), pin_bytes.as_bytes()) {
                rollback_new_private(Path::new(session)).map_err(|rollback| {
                    io::Error::other(format!(
                        "session-pin publication failed ({error}); session rollback failed ({rollback}); reconcile both paths"
                    ))
                })?;
                return Err(error.into());
            }
            print_receipt(&receipt);
        }
        [
            _,
            command,
            session,
            session_pin,
            package,
            package_pin,
            repository,
            sealed_history,
            forward_manifest_pin,
            forward_implementation_pin,
            reverse_manifest_pin,
            reverse_implementation_pin,
            expected_head,
        ] if command == "verify" => {
            let session_bytes = read_owner_private(Path::new(session), MAX_SESSION_BYTES)?;
            let session_pin = read_owner_pin(Path::new(session_pin))?;
            let (package_bytes, pins) = read_package_inputs(
                package,
                package_pin,
                forward_manifest_pin,
                forward_implementation_pin,
                reverse_manifest_pin,
                reverse_implementation_pin,
            )?;
            let package_inputs = private_inputs(sealed_history, &pins);
            let receipt = verify_private_session(
                &session_bytes,
                &session_pin,
                &package_bytes,
                Path::new(repository),
                &package_inputs,
                expected_head,
            )?;
            print_receipt(&receipt);
        }
        _ => return Err("usage:\n  mcloving-shadow-qualification generate-keys SOURCE_CAPTURE_KEY SHADOW_REPLAY_KEY\n  mcloving-shadow-qualification seal TEMPLATE SOURCE_CAPTURE_KEY SHADOW_REPLAY_KEY SESSION SESSION_PIN PACKAGE PACKAGE_PIN REPOSITORY_ROOT SEALED_HISTORY FORWARD_MANIFEST_PIN FORWARD_IMPLEMENTATION_PIN REVERSE_MANIFEST_PIN REVERSE_IMPLEMENTATION_PIN EXPECTED_IMPLEMENTATION_HEAD\n  mcloving-shadow-qualification verify SESSION SESSION_PIN PACKAGE PACKAGE_PIN REPOSITORY_ROOT SEALED_HISTORY FORWARD_MANIFEST_PIN FORWARD_IMPLEMENTATION_PIN REVERSE_MANIFEST_PIN REVERSE_IMPLEMENTATION_PIN EXPECTED_IMPLEMENTATION_HEAD".into()),
    }
    Ok(())
}

struct OwnerPins {
    package: String,
    forward_manifest: String,
    forward_implementation: String,
    reverse_manifest: String,
    reverse_implementation: String,
}

fn read_package_inputs(
    package: &str,
    package_pin: &str,
    forward_manifest_pin: &str,
    forward_implementation_pin: &str,
    reverse_manifest_pin: &str,
    reverse_implementation_pin: &str,
) -> io::Result<(Vec<u8>, OwnerPins)> {
    Ok((
        read_owner_private(Path::new(package), MAX_PRIVATE_PACKAGE_BYTES)?,
        OwnerPins {
            package: read_owner_pin(Path::new(package_pin))?,
            forward_manifest: read_owner_pin(Path::new(forward_manifest_pin))?,
            forward_implementation: read_owner_pin(Path::new(forward_implementation_pin))?,
            reverse_manifest: read_owner_pin(Path::new(reverse_manifest_pin))?,
            reverse_implementation: read_owner_pin(Path::new(reverse_implementation_pin))?,
        },
    ))
}

fn private_inputs<'a>(
    sealed_history: &'a str,
    pins: &'a OwnerPins,
) -> PrivateVerificationInputs<'a> {
    PrivateVerificationInputs {
        sealed_history_root: Path::new(sealed_history),
        expected_forward_manifest_sha256: &pins.forward_manifest,
        expected_reverse_manifest_sha256: &pins.reverse_manifest,
        expected_forward_implementation_sha256: &pins.forward_implementation,
        expected_reverse_implementation_sha256: &pins.reverse_implementation,
        expected_package_sha256: Some(&pins.package),
    }
}

fn print_receipt(receipt: &VerificationReceipt) {
    println!("schema={}", receipt.schema);
    println!("captured_events={}", receipt.captured_events);
    println!("replayed_events={}", receipt.replayed_events);
    println!("compared_traces={}", receipt.compared_traces);
    println!("mismatches={}", receipt.mismatches);
    println!("packaged_cases={}", receipt.packaged_cases);
    println!("rejected_cases={}", receipt.rejected_cases);
    println!("shadow_qualified={}", receipt.shadow_qualified);
    println!("production_authority={}", receipt.production_authority);
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_owner_pin(path: &Path) -> io::Result<String> {
    let bytes = read_owner_private(path, MAX_PIN_BYTES)?;
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

fn read_owner_private(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owner-private shadow inputs require Unix custody validation",
        ))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let mut file = open_owner_private(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owner-private input is not a bounded, owner-only, singly linked regular file",
            ));
        }
        if metadata.len() > limit as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner-private input exceeds its byte ceiling",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "owner-private input exceeds its byte ceiling",
            ));
        }
        Ok(bytes)
    }
}

#[cfg(unix)]
fn open_owner_private(path: &Path) -> io::Result<File> {
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
        require_safe_ancestor(&directory, effective_uid)?;
    }
    let parent = rustix::fs::fstat(&directory).map_err(os_error)?;
    if parent.st_uid != effective_uid || parent.st_mode & 0o077 != 0 {
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
fn require_safe_ancestor(directory: &rustix::fd::OwnedFd, effective_uid: u32) -> io::Result<()> {
    let metadata = rustix::fs::fstat(directory).map_err(os_error)?;
    let trusted_sticky_root = metadata.st_uid == 0 && metadata.st_mode & 0o1000 != 0;
    if metadata.st_mode & 0o022 != 0 && metadata.st_uid != effective_uid && !trusted_sticky_root {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owner-private path traverses a redirectable foreign directory",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn os_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(unix)]
fn publish_owner_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (parent, leaf) = open_owner_parent(path)?;
    let descriptor = rustix::fs::openat(
        &parent,
        leaf.as_os_str(),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(os_error)?;
    let mut file = File::from(descriptor);
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        rollback_at(&parent, leaf.as_os_str())?;
        return Err(error);
    }
    drop(file);
    if let Err(error) = rustix::fs::fsync(&parent).map_err(os_error) {
        rollback_at(&parent, leaf.as_os_str())?;
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_owner_private(_path: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-private shadow publication requires Unix",
    ))
}

#[cfg(unix)]
fn rollback_new_private(path: &Path) -> io::Result<()> {
    let (parent, leaf) = open_owner_parent(path)?;
    rollback_at(&parent, leaf.as_os_str())
}

#[cfg(not(unix))]
fn rollback_new_private(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-private shadow rollback requires Unix",
    ))
}

#[cfg(unix)]
fn rollback_at(parent: &rustix::fd::OwnedFd, leaf: &std::ffi::OsStr) -> io::Result<()> {
    rustix::fs::unlinkat(parent, leaf, rustix::fs::AtFlags::empty()).map_err(os_error)?;
    rustix::fs::fsync(parent).map_err(os_error)
}

#[cfg(unix)]
fn open_owner_parent(path: &Path) -> io::Result<(rustix::fd::OwnedFd, OsString)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let components = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name.to_owned())),
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
            component.as_os_str(),
            directory_flags,
            rustix::fs::Mode::empty(),
        )
        .map_err(os_error)?;
        require_safe_ancestor(&directory, effective_uid)?;
    }
    let parent = rustix::fs::fstat(&directory).map_err(os_error)?;
    if parent.st_uid != effective_uid || parent.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owner-private input/output parent has the wrong owner or broad permissions",
        ));
    }
    Ok((directory, leaf.clone()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    fn private_directory() -> tempfile::TempDir {
        let temporary_root = if Path::new("/private/tmp").is_dir() {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        let directory = tempfile::tempdir_in(temporary_root).expect("private root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private mode");
        directory
    }

    #[test]
    fn owner_private_reader_rejects_modes_links_aliases_and_oversize() {
        let directory = private_directory();
        let file = directory.path().join("input");
        fs::write(&file, b"private").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(read_owner_private(&file, 7).expect("read"), b"private");
        assert_eq!(
            read_owner_private(&file, 6).expect_err("oversize").kind(),
            io::ErrorKind::InvalidData
        );

        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("broad mode");
        assert_eq!(
            read_owner_private(&file, 7).expect_err("broad mode").kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("restore mode");

        let link = directory.path().join("link");
        fs::hard_link(&file, &link).expect("hard link");
        assert_eq!(
            read_owner_private(&file, 7)
                .expect_err("multiple links")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(&link).expect("remove hard link");
        let alias = directory.path().join("alias");
        symlink(&file, &alias).expect("symlink");
        assert!(read_owner_private(&alias, 7).is_err());
    }

    #[test]
    fn owner_pin_is_canonical() {
        let directory = private_directory();
        let pin = directory.path().join("pin");
        fs::write(&pin, format!("{}\n", "a".repeat(64))).expect("pin");
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(read_owner_pin(&pin).expect("canonical"), "a".repeat(64));
        fs::write(&pin, format!("{}\n", "A".repeat(64))).expect("bad pin");
        assert!(read_owner_pin(&pin).is_err());
    }

    #[test]
    fn private_publication_is_create_new_durable_and_owner_only() {
        let directory = private_directory();
        let output = directory.path().join("session");
        publish_owner_private(&output, b"complete").expect("publish");
        assert_eq!(read_owner_private(&output, 8).expect("read"), b"complete");
        let metadata = fs::metadata(&output).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            publish_owner_private(&output, b"replacement")
                .expect_err("create new")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&output).expect("unchanged"), b"complete");
        rollback_new_private(&output).expect("rollback");
        assert!(!output.exists());
    }
}
