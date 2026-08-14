use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use mcloving_release_provenance::{
    ComponentArtifact, ReleaseBuildReceipt, ReleaseError, ReleaseRequest, SignedReleaseEnvelope,
    VerificationPolicy, build_bundle, sbom_from_cargo_lock, sign_build_outputs, verify_release,
};
use zeroize::Zeroize as _;

const MAX_PUBLIC_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 16 * 1024;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("release_provenance_denied: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<(), CliError> {
    match arguments.as_slice() {
        [command, lock, generator, output] if command == "sbom" => {
            let lock_bytes = read_public(Path::new(lock))?;
            let lock_text = std::str::from_utf8(&lock_bytes).map_err(|_| CliError::InvalidInput)?;
            let sbom = sbom_from_cargo_lock(lock_text, generator)?;
            write_new_private(Path::new(output), &sbom.canonical_bytes()?)
        }
        [command, root, components, output] if command == "bundle" => {
            let components: Vec<ComponentArtifact> =
                serde_json::from_slice(&read_public(Path::new(components))?)?;
            let bundle = build_bundle(Path::new(root), &components)?;
            write_new_private(Path::new(output), &bundle)
        }
        [
            command,
            build_receipt,
            release_request,
            components,
            sbom,
            bundle,
            source_archive,
            cargo_lock,
            toolchain,
            signing_key,
            output,
        ] if command == "sign-build" => {
            let build_receipt: ReleaseBuildReceipt =
                serde_json::from_slice(&read_public(Path::new(build_receipt))?)?;
            let release_request: ReleaseRequest =
                serde_json::from_slice(&read_public(Path::new(release_request))?)?;
            let components = read_public(Path::new(components))?;
            let sbom = read_public(Path::new(sbom))?;
            let bundle = read_bundle(Path::new(bundle))?;
            let source_archive = read_bundle(Path::new(source_archive))?;
            let cargo_lock = read_public(Path::new(cargo_lock))?;
            let toolchain = read_public(Path::new(toolchain))?;
            let mut signing_key = read_signing_key(Path::new(signing_key))?;
            let result = sign_build_outputs(
                build_receipt,
                release_request,
                &components,
                &sbom,
                &bundle,
                &source_archive,
                &cargo_lock,
                &toolchain,
                &signing_key,
            );
            signing_key.zeroize();
            let envelope = result?;
            write_new_private(Path::new(output), &serde_json::to_vec(&envelope)?)
        }
        [
            command,
            environment,
            configuration_sha256,
            deployed_at,
            output,
            chain @ ..,
        ] if command == "verify-chain" => {
            if chain.is_empty() || chain.len() % 5 != 0 {
                return Err(CliError::Usage);
            }
            let deployed_at = deployed_at
                .parse::<i64>()
                .map_err(|_| CliError::InvalidInput)?;
            let mut verified = None;
            for group in chain.chunks_exact(5) {
                let envelope: SignedReleaseEnvelope =
                    serde_json::from_slice(&read_public(Path::new(&group[0]))?)?;
                let policy: VerificationPolicy =
                    serde_json::from_slice(&read_public(Path::new(&group[1]))?)?;
                let sbom = read_public(Path::new(&group[2]))?;
                let bundle = read_bundle(Path::new(&group[3]))?;
                let cargo_lock = read_public(Path::new(&group[4]))?;
                verified = Some(verify_release(
                    &envelope,
                    &policy,
                    &sbom,
                    &bundle,
                    &cargo_lock,
                    verified.as_ref(),
                )?);
            }
            let receipt = verified.ok_or(CliError::InvalidInput)?.deployment_receipt(
                environment,
                configuration_sha256,
                deployed_at,
            )?;
            write_new_private(Path::new(output), &serde_json::to_vec(&receipt)?)
        }
        _ => Err(CliError::Usage),
    }
}

fn read_public(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded_regular(path, MAX_PUBLIC_INPUT_BYTES, false)
}

fn read_bundle(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded_regular(path, MAX_BUNDLE_INPUT_BYTES, false)
}

fn read_signing_key(path: &Path) -> Result<Vec<u8>, CliError> {
    read_bounded_regular(path, MAX_SIGNING_KEY_BYTES, true)
}

fn read_bounded_regular(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>, CliError> {
    if !path.is_absolute() {
        return Err(CliError::InvalidInput);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let input = options.open(path)?;
    let metadata = input.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(CliError::InvalidInput);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1
            || (private
                && (metadata.uid() != nix::unistd::Uid::effective().as_raw()
                    || metadata.mode() & 0o077 != 0))
        {
            return Err(CliError::InvalidInput);
        }
    }
    let expected_length = usize::try_from(metadata.len()).map_err(|_| CliError::InvalidInput)?;
    let mut bytes = Vec::with_capacity(expected_length);
    input
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected_length {
        return Err(CliError::InvalidInput);
    }
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(CliError::InvalidInput);
    }
    let parent = path.parent().ok_or(CliError::InvalidInput)?;
    let canonical_parent = parent.canonicalize()?;
    if !canonical_parent.is_dir()
        || canonical_parent.join(path.file_name().ok_or(CliError::InvalidInput)?) != path
    {
        return Err(CliError::InvalidInput);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = canonical_parent.metadata()?;
        if metadata.uid() != nix::unistd::Uid::effective().as_raw() || metadata.mode() & 0o077 != 0
        {
            return Err(CliError::InvalidInput);
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(
        "usage: mcloving-release-provenance sbom LOCK GENERATOR_SHA256 OUTPUT | bundle ROOT COMPONENTS_JSON OUTPUT | sign-build BUILD_RECEIPT RELEASE_REQUEST COMPONENTS SBOM BUNDLE SOURCE_ARCHIVE CARGO_LOCK TOOLCHAIN PRIVATE_PKCS8 OUTPUT | verify-chain ENV CONFIG_SHA256 DEPLOYED_AT_MS OUTPUT ENVELOPE POLICY SBOM BUNDLE CARGO_LOCK [ENVELOPE POLICY SBOM BUNDLE CARGO_LOCK ...]"
    )]
    Usage,
    #[error("release input is invalid")]
    InvalidInput,
    #[error("release file operation failed")]
    Io(#[from] std::io::Error),
    #[error("release JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("release verification failed")]
    Release(#[from] ReleaseError),
}
