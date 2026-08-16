use std::env;
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_migration_package::{MAX_PRIVATE_PACKAGE_BYTES, PrivateVerificationInputs};
use mcloving_shadow_qualification::{
    IndependentPins, SourceTemplateInputs, VerificationReceipt,
    prepare_source_authenticated_template, seal_private_session, verify_private_session,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};

const MAX_SESSION_BYTES: usize = 262_144;
const MAX_PIN_BYTES: usize = 65;
const MAX_RUNTIME_OBSERVATION_BYTES: usize = 65_536;

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "shadow qualification failed: {}",
            public_error_code(&*error)
        );
        std::process::exit(1);
    }
}

fn public_error_code(_error: &(dyn std::error::Error + 'static)) -> &'static str {
    // Owner-private inputs can appear inside parser and I/O error strings. Keep the
    // process boundary deliberately non-reflective; detailed diagnosis belongs in
    // the owner-private evidence package, never captured stderr.
    "SHADOW_QUALIFICATION_FAILED"
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().collect::<Vec<_>>();
    run_with_arguments(&arguments)
}

fn run_with_arguments(arguments: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    let command = arguments.get(1).and_then(|value| value.to_str());
    match (command, arguments) {
        (
            Some("generate-keys"),
            [
                _,
                _,
                source_key,
                source_key_pin,
                shadow_key,
                shadow_public_key,
            ],
        ) => {
            let random = SystemRandom::new();
            let source = Ed25519KeyPair::generate_pkcs8(&random)
                .map_err(|_| "could not generate source-capture Ed25519 key")?;
            let shadow = Ed25519KeyPair::generate_pkcs8(&random)
                .map_err(|_| "could not generate shadow-replay Ed25519 key")?;
            let source_pair = Ed25519KeyPair::from_pkcs8(source.as_ref())
                .map_err(|_| "could not load generated source-capture key")?;
            let shadow_pair = Ed25519KeyPair::from_pkcs8(shadow.as_ref())
                .map_err(|_| "could not load generated shadow-replay key")?;
            let source_pin_bytes = format!("{}\n", digest_hex(source_pair.public_key().as_ref()));
            let shadow_public_key_bytes =
                format!("{}\n", BASE64.encode(shadow_pair.public_key().as_ref()));
            publish_owner_private_bundle(&[
                (Path::new(source_key), source.as_ref()),
                (Path::new(source_key_pin), source_pin_bytes.as_bytes()),
                (Path::new(shadow_key), shadow.as_ref()),
                (
                    Path::new(shadow_public_key),
                    shadow_public_key_bytes.as_bytes(),
                ),
            ])?;
            println!("source_capture_key_created=true");
            println!("source_capture_key_pin_created=true");
            println!("shadow_replay_key_created=true");
            println!("shadow_replay_public_identity_created=true");
        }
        (
            Some("prepare"),
            [
                _,
                _,
                source_probe,
                target_replay,
                trace_observation,
                isolation_observation,
                source_key,
                source_key_pin,
                shadow_public_identity,
                package,
                package_pin,
                authz_generation_pin,
                verifier_binary_pin,
                expected_head,
                template,
            ],
        ) => {
            let expected_head = expected_head
                .to_str()
                .ok_or("expected implementation head is not UTF-8")?;
            let source_probe =
                read_owner_private(Path::new(source_probe), MAX_RUNTIME_OBSERVATION_BYTES)?;
            let target_replay =
                read_owner_private(Path::new(target_replay), MAX_RUNTIME_OBSERVATION_BYTES)?;
            let trace_observation =
                read_owner_private(Path::new(trace_observation), MAX_RUNTIME_OBSERVATION_BYTES)?;
            let isolation_observation = read_owner_private(
                Path::new(isolation_observation),
                MAX_RUNTIME_OBSERVATION_BYTES,
            )?;
            let source_key = read_owner_private(Path::new(source_key), 1_024)?;
            let source_key_pin = read_owner_pin(Path::new(source_key_pin))?;
            let shadow_public_identity =
                read_owner_private(Path::new(shadow_public_identity), 128)?;
            let shadow_public_identity = std::str::from_utf8(&shadow_public_identity)
                .map_err(|_| "shadow public identity is not UTF-8")?
                .trim();
            let package = read_owner_private(Path::new(package), MAX_PRIVATE_PACKAGE_BYTES)?;
            let package_pin = read_owner_pin(Path::new(package_pin))?;
            let authz_generation = read_owner_pin(Path::new(authz_generation_pin))?;
            let verifier_binary = read_owner_pin(Path::new(verifier_binary_pin))?;
            let bytes = prepare_source_authenticated_template(&SourceTemplateInputs {
                source_probe_bytes: &source_probe,
                target_replay_bytes: &target_replay,
                trace_observation_bytes: &trace_observation,
                isolation_observation_bytes: &isolation_observation,
                private_package_bytes: &package,
                expected_private_package_sha256: &package_pin,
                source_capture_pkcs8: &source_key,
                expected_source_capture_public_key_sha256: &source_key_pin,
                shadow_replay_public_key_base64: shadow_public_identity,
                authz_generation_sha256: &authz_generation,
                verifier_binary_sha256: &verifier_binary,
                shadow_implementation_head: expected_head,
            })?;
            publish_owner_private(Path::new(template), &bytes)?;
            println!("source_capture_authenticated=true");
            println!("target_replay_observed=true");
            println!("shadow_replay_signed=false");
            println!("production_authority=false");
        }
        (
            Some("seal"),
            [
                _,
                _,
                template,
                source_capture_key_pin,
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
                authz_generation_pin,
                verifier_binary_pin,
                expected_head,
            ],
        ) => {
            let expected_head = expected_head
                .to_str()
                .ok_or("expected implementation head is not UTF-8")?;
            let template_bytes = read_owner_private(Path::new(template), MAX_SESSION_BYTES)?;
            let shadow_key = read_owner_private(Path::new(shadow_key), 1_024)?;
            let paths = PackageInputPaths {
                package,
                package_pin,
                source_capture_key_pin,
                forward_manifest_pin,
                forward_implementation_pin,
                reverse_manifest_pin,
                reverse_implementation_pin,
                authz_generation_pin,
                verifier_binary_pin,
            };
            let (package_bytes, pins) = read_package_inputs(&paths)?;
            let session_bytes =
                seal_private_session(&template_bytes, &pins.source_capture_key, &shadow_key)?;
            let computed_session_pin = digest_hex(&session_bytes);
            let package_inputs = private_inputs(sealed_history, &pins);
            let independent_pins = IndependentPins {
                session_sha256: &computed_session_pin,
                source_capture_public_key_sha256: &pins.source_capture_key,
                authz_generation_sha256: &pins.authz_generation,
                verifier_binary_sha256: &pins.verifier_binary,
                shadow_implementation_head: expected_head,
            };
            let receipt = verify_private_session(
                &session_bytes,
                &independent_pins,
                &package_bytes,
                Path::new(repository),
                &package_inputs,
            )?;
            publish_owner_private(Path::new(session), &session_bytes)?;
            let pin_bytes = format!("{computed_session_pin}\n");
            if let Err(error) = publish_owner_private(Path::new(session_pin), pin_bytes.as_bytes())
            {
                rollback_new_private(Path::new(session)).map_err(|rollback| {
                    io::Error::other(format!(
                        "session-pin publication failed ({error}); session rollback failed ({rollback}); reconcile both paths"
                    ))
                })?;
                return Err(error.into());
            }
            print_receipt(&receipt);
        }
        (
            Some("verify"),
            [
                _,
                _,
                session,
                session_pin,
                package,
                package_pin,
                source_capture_key_pin,
                repository,
                sealed_history,
                forward_manifest_pin,
                forward_implementation_pin,
                reverse_manifest_pin,
                reverse_implementation_pin,
                authz_generation_pin,
                verifier_binary_pin,
                expected_head,
            ],
        ) => {
            let expected_head = expected_head
                .to_str()
                .ok_or("expected implementation head is not UTF-8")?;
            let session_bytes = read_owner_private(Path::new(session), MAX_SESSION_BYTES)?;
            let session_pin = read_owner_pin(Path::new(session_pin))?;
            let paths = PackageInputPaths {
                package,
                package_pin,
                source_capture_key_pin,
                forward_manifest_pin,
                forward_implementation_pin,
                reverse_manifest_pin,
                reverse_implementation_pin,
                authz_generation_pin,
                verifier_binary_pin,
            };
            let (package_bytes, pins) = read_package_inputs(&paths)?;
            let package_inputs = private_inputs(sealed_history, &pins);
            let independent_pins = IndependentPins {
                session_sha256: &session_pin,
                source_capture_public_key_sha256: &pins.source_capture_key,
                authz_generation_sha256: &pins.authz_generation,
                verifier_binary_sha256: &pins.verifier_binary,
                shadow_implementation_head: expected_head,
            };
            let receipt = verify_private_session(
                &session_bytes,
                &independent_pins,
                &package_bytes,
                Path::new(repository),
                &package_inputs,
            )?;
            print_receipt(&receipt);
        }
        _ => return Err("usage error".into()),
    }
    Ok(())
}

struct OwnerPins {
    package: String,
    source_capture_key: String,
    forward_manifest: String,
    forward_implementation: String,
    reverse_manifest: String,
    reverse_implementation: String,
    authz_generation: String,
    verifier_binary: String,
}

struct PackageInputPaths<'a> {
    package: &'a OsStr,
    package_pin: &'a OsStr,
    source_capture_key_pin: &'a OsStr,
    forward_manifest_pin: &'a OsStr,
    forward_implementation_pin: &'a OsStr,
    reverse_manifest_pin: &'a OsStr,
    reverse_implementation_pin: &'a OsStr,
    authz_generation_pin: &'a OsStr,
    verifier_binary_pin: &'a OsStr,
}

fn read_package_inputs(paths: &PackageInputPaths<'_>) -> io::Result<(Vec<u8>, OwnerPins)> {
    Ok((
        read_owner_private(Path::new(paths.package), MAX_PRIVATE_PACKAGE_BYTES)?,
        OwnerPins {
            package: read_owner_pin(Path::new(paths.package_pin))?,
            source_capture_key: read_owner_pin(Path::new(paths.source_capture_key_pin))?,
            forward_manifest: read_owner_pin(Path::new(paths.forward_manifest_pin))?,
            forward_implementation: read_owner_pin(Path::new(paths.forward_implementation_pin))?,
            reverse_manifest: read_owner_pin(Path::new(paths.reverse_manifest_pin))?,
            reverse_implementation: read_owner_pin(Path::new(paths.reverse_implementation_pin))?,
            authz_generation: read_owner_pin(Path::new(paths.authz_generation_pin))?,
            verifier_binary: read_owner_pin(Path::new(paths.verifier_binary_pin))?,
        },
    ))
}

fn private_inputs<'a>(
    sealed_history: &'a OsStr,
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

fn publish_owner_private_bundle(outputs: &[(&Path, &[u8])]) -> io::Result<()> {
    let mut published: Vec<&Path> = Vec::with_capacity(outputs.len());
    for (path, bytes) in outputs {
        if let Err(publication_error) = publish_owner_private(path, bytes) {
            let mut rollback_failed = false;
            for published_path in published.iter().rev() {
                rollback_failed |= rollback_new_private(published_path).is_err();
            }
            if rollback_failed {
                return Err(io::Error::other(
                    "key-bundle publication and rollback failed; reconcile all output paths",
                ));
            }
            return Err(publication_error);
        }
        published.push(*path);
    }
    Ok(())
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
    use std::os::unix::ffi::OsStringExt as _;
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

    #[test]
    fn key_generation_publishes_precommitted_source_and_shadow_identities() {
        let directory = private_directory();
        let source = directory.path().join("source.pkcs8");
        let source_pin = directory.path().join("source-public.sha256");
        let shadow = directory.path().join("shadow.pkcs8");
        let shadow_public = directory.path().join("shadow-public.base64");
        let arguments = vec![
            OsString::from("mcloving-shadow-qualification"),
            OsString::from("generate-keys"),
            source.as_os_str().to_owned(),
            source_pin.as_os_str().to_owned(),
            shadow.as_os_str().to_owned(),
            shadow_public.as_os_str().to_owned(),
        ];

        run_with_arguments(&arguments).expect("generate keys and pin");
        let source_bytes = read_owner_private(&source, 1_024).expect("source key");
        let source_pair = Ed25519KeyPair::from_pkcs8(&source_bytes).expect("source pair");
        assert_eq!(
            read_owner_pin(&source_pin).expect("source pin"),
            digest_hex(source_pair.public_key().as_ref())
        );
        let shadow_bytes = read_owner_private(&shadow, 1_024).expect("shadow key");
        let shadow_pair = Ed25519KeyPair::from_pkcs8(&shadow_bytes).expect("shadow pair");
        let shadow_public_bytes =
            read_owner_private(&shadow_public, 128).expect("shadow public identity");
        assert_eq!(
            shadow_public_bytes,
            format!("{}\n", BASE64.encode(shadow_pair.public_key().as_ref())).as_bytes()
        );
        assert_ne!(
            source_pair.public_key().as_ref(),
            shadow_pair.public_key().as_ref()
        );
    }

    #[test]
    fn key_generation_rolls_back_source_outputs_when_shadow_is_preexisting() {
        let directory = private_directory();
        let source = directory.path().join("source.pkcs8");
        let source_pin = directory.path().join("source-public.sha256");
        let shadow = directory.path().join("shadow.pkcs8");
        let shadow_public = directory.path().join("shadow-public.base64");
        fs::write(&shadow, b"preexisting").expect("preexisting shadow");
        fs::set_permissions(&shadow, fs::Permissions::from_mode(0o600)).expect("shadow mode");
        let arguments = vec![
            OsString::from("mcloving-shadow-qualification"),
            OsString::from("generate-keys"),
            source.as_os_str().to_owned(),
            source_pin.as_os_str().to_owned(),
            shadow.as_os_str().to_owned(),
            shadow_public.as_os_str().to_owned(),
        ];

        assert!(run_with_arguments(&arguments).is_err());
        assert!(!source.exists());
        assert!(!source_pin.exists());
        assert!(!shadow_public.exists());
        assert_eq!(fs::read(&shadow).expect("unchanged shadow"), b"preexisting");
    }

    #[test]
    fn key_generation_rolls_back_all_keys_when_shadow_identity_is_preexisting() {
        let directory = private_directory();
        let source = directory.path().join("source.pkcs8");
        let source_pin = directory.path().join("source-public.sha256");
        let shadow = directory.path().join("shadow.pkcs8");
        let shadow_public = directory.path().join("shadow-public.base64");
        fs::write(&shadow_public, b"preexisting").expect("preexisting identity");
        fs::set_permissions(&shadow_public, fs::Permissions::from_mode(0o600))
            .expect("identity mode");
        let arguments = vec![
            OsString::from("mcloving-shadow-qualification"),
            OsString::from("generate-keys"),
            source.as_os_str().to_owned(),
            source_pin.as_os_str().to_owned(),
            shadow.as_os_str().to_owned(),
            shadow_public.as_os_str().to_owned(),
        ];

        assert!(run_with_arguments(&arguments).is_err());
        assert!(!source.exists());
        assert!(!source_pin.exists());
        assert!(!shadow.exists());
        assert_eq!(
            fs::read(&shadow_public).expect("unchanged identity"),
            b"preexisting"
        );
    }

    #[test]
    fn prepare_command_publishes_only_a_source_authenticated_template() {
        let directory = private_directory();
        let write_private = |name: &str, bytes: &[u8]| {
            let path = directory.path().join(name);
            fs::write(&path, bytes).expect("write private input");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("private input mode");
            path
        };
        let random = SystemRandom::new();
        let source_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("source key");
        let source_pair = Ed25519KeyPair::from_pkcs8(source_pkcs8.as_ref()).expect("source pair");
        let shadow_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("shadow key");
        let shadow_pair = Ed25519KeyPair::from_pkcs8(shadow_pkcs8.as_ref()).expect("shadow pair");
        let source_observations = [
            (
                "api",
                "WorkflowJob.doBuild(StaplerRequest2,StaplerResponse2,TimeDuration)",
                serde_json::json!({"rejection": "org.kohsuke.stapler.HttpResponses$3"}),
            ),
            (
                "manual",
                "WorkflowJob.scheduleBuild2(UserIdCause)",
                serde_json::json!({"returned_future": false}),
            ),
            ("schedule", "TimerTrigger.run()", serde_json::json!({})),
            (
                "upstream",
                "ReverseBuildTrigger.RunListenerImpl.onCompleted",
                serde_json::json!({"upstream_result": "ABORTED"}),
            ),
            ("webhook", "SCMTrigger.run(Action[])", serde_json::json!({})),
        ]
        .iter()
        .map(|(kind, path, detail)| {
            serde_json::json!({
                "kind": kind,
                "path": path,
                "outcome": "disabled_pre_queue",
                "queued_builds": 0,
                "scheduled_attempts": 0,
                "credential_grants": 0,
                "connector_requests": 0,
                "production_effects": 0,
                "detail": detail,
            })
        })
        .collect::<Vec<_>>();
        let target_observations = [
            ("api", "Store.accept_trigger_delivery(remote_api)"),
            ("manual", "Store.admit_dag"),
            ("schedule", "Store.accept_trigger_delivery(schedule)"),
            ("upstream", "Store.accept_trigger_delivery(upstream)"),
            ("webhook", "Store.accept_trigger_delivery(scm_webhook)"),
        ]
        .iter()
        .map(|(kind, path)| {
            serde_json::json!({
                "kind": kind,
                "path": path,
                "outcome": "disabled_pre_queue",
                "queued_builds": 0,
                "scheduled_attempts": 0,
                "credential_grants": 0,
                "connector_requests": 0,
                "production_effects": 0,
            })
        })
        .collect::<Vec<_>>();
        let activity = serde_json::json!({
            "builds": 1,
            "queued": 0,
            "next_build_number": 2,
            "credential_lookups": 0,
        });
        let source = serde_json::to_vec(&serde_json::json!({
            "schema": "mcloving.shadow001.jenkins-source-probe/v1",
            "job_id": "corpus-052-cinqict_jenkinsdev",
            "source_state": "disabled",
            "definition_kind": "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition",
            "source_sha256": "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100",
            "source_config_sha256": "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97",
            "captured_wall_clock_unix_ms": 1_786_904_213_797_i64,
            "original_activity": activity,
            "terminal_activity": activity,
            "observations": source_observations,
        }))
        .expect("source observation");
        let target = serde_json::to_vec(&serde_json::json!({
            "schema": "mcloving.shadow001.target-replay/v1",
            "job_id": "corpus-052-cinqict_jenkinsdev",
            "target_state": "disabled",
            "target_generation": "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97",
            "observations": target_observations,
            "terminal_queued_builds": 0,
        }))
        .expect("target observation");
        let log = serde_json::json!([
            {
                "sequence": 1,
                "stream": "stderr",
                "content_sha256": "dd0b88f8948e42d79e88c9fee0a6825c96a07800d0d6cff497d60bf092d4609c",
                "bytes": 19,
            },
            {
                "sequence": 2,
                "stream": "stdout",
                "content_sha256": "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26",
                "bytes": 12,
            },
        ]);
        let trace = serde_json::to_vec(&serde_json::json!({
            "schema": "mcloving.shadow001.trace-observation/v1",
            "certified_trace_sha256": "e1465ed5261dc046222045657c2f0e1ab774f63bd50d70f5e263bc7a6e94c4f6",
            "source_trace_sha256": "e1465ed5261dc046222045657c2f0e1ab774f63bd50d70f5e263bc7a6e94c4f6",
            "target_trace_sha256": "e1465ed5261dc046222045657c2f0e1ab774f63bd50d70f5e263bc7a6e94c4f6",
            "source_log": log,
            "target_log": log,
            "source_result": "SUCCESS",
            "target_result": "SUCCESS",
            "artifacts": 0,
            "external_effect_intents": 0,
            "isolated_replay_executed": true,
            "compared_traces": 1,
            "mismatches": 0,
        }))
        .expect("trace observation");
        let isolation = serde_json::to_vec(&serde_json::json!({
            "schema": "mcloving.shadow001.isolation-observation/v1",
            "source_fixture_identity": "source-fixture",
            "target_fixture_identity": "target-fixture",
            "source_network_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "target_network_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "reachability_receipt_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "source_and_target_networks_disjoint": true,
            "production_network_requests": 0,
            "production_endpoint_mappings": 0,
            "production_credentials": 0,
            "host_mounts": 0,
            "cross_fixture_mounts": 0,
            "teardown_complete": true,
        }))
        .expect("isolation observation");
        let package = b"private-package";
        let source_path = write_private("source.json", &source);
        let target_path = write_private("target.json", &target);
        let trace_path = write_private("trace.json", &trace);
        let isolation_path = write_private("isolation.json", &isolation);
        let source_key_path = write_private("source.pkcs8", source_pkcs8.as_ref());
        let source_pin_path = write_private(
            "source.sha256",
            format!("{}\n", digest_hex(source_pair.public_key().as_ref())).as_bytes(),
        );
        let shadow_public_path = write_private(
            "shadow.base64",
            format!("{}\n", BASE64.encode(shadow_pair.public_key().as_ref())).as_bytes(),
        );
        let package_path = write_private("package.json", package);
        let package_pin_path = write_private(
            "package.sha256",
            format!("{}\n", digest_hex(package)).as_bytes(),
        );
        let authz_path = write_private("authz.sha256", format!("{}\n", "d".repeat(64)).as_bytes());
        let verifier_path = write_private(
            "verifier.sha256",
            format!("{}\n", "e".repeat(64)).as_bytes(),
        );
        let template_path = directory.path().join("template.json");
        let arguments = vec![
            OsString::from("mcloving-shadow-qualification"),
            OsString::from("prepare"),
            source_path.into_os_string(),
            target_path.into_os_string(),
            trace_path.into_os_string(),
            isolation_path.into_os_string(),
            source_key_path.into_os_string(),
            source_pin_path.into_os_string(),
            shadow_public_path.into_os_string(),
            package_path.into_os_string(),
            package_pin_path.into_os_string(),
            authz_path.into_os_string(),
            verifier_path.into_os_string(),
            OsString::from("f".repeat(40)),
            template_path.as_os_str().to_owned(),
        ];

        run_with_arguments(&arguments).expect("prepare template");
        let bytes = read_owner_private(&template_path, MAX_SESSION_BYTES).expect("template");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("template JSON");
        let events = value["events"].as_array().expect("events");
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|event| {
            !event["source"]["signature_base64"]
                .as_str()
                .expect("source signature")
                .is_empty()
                && event["shadow"]["signature_base64"] == ""
                && event["shadow"]["signing_public_key_sha256"] == ""
        }));
    }

    #[test]
    fn public_failure_output_never_reflects_private_parser_values() {
        let sentinel = "DO-NOT-DISCLOSE-PRIVATE-SENTINEL";
        let malformed = format!(r#""{sentinel}""#);
        let error = serde_json::from_str::<u64>(&malformed).expect_err("malformed");
        assert!(error.to_string().contains(sentinel));

        let output = format!("shadow qualification failed: {}", public_error_code(&error));
        assert_eq!(
            output,
            "shadow qualification failed: SHADOW_QUALIFICATION_FAILED"
        );
        assert!(!output.contains(sentinel));
    }

    #[test]
    fn non_utf8_private_path_reaches_the_redacted_error_boundary_without_panicking() {
        let mut arguments = vec![
            OsString::from("mcloving-shadow-qualification"),
            OsString::from("verify"),
        ];
        arguments.extend((0..14).map(|index| OsString::from(format!("argument-{index}"))));
        arguments[2] = OsString::from_vec(b"/tmp/private-\xff-path".to_vec());
        arguments[15] = OsString::from("a".repeat(40));

        let result = std::panic::catch_unwind(|| run_with_arguments(&arguments));
        let error = result
            .expect("non-UTF-8 path must not panic")
            .expect_err("missing private input must fail");
        assert_ne!(error.to_string(), "usage error");
        assert_eq!(public_error_code(&*error), "SHADOW_QUALIFICATION_FAILED");
    }
}
