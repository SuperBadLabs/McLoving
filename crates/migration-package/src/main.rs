use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

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
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
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
