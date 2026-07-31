use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;

use mcloving_jenkins_compiler_admission::{
    ExpectedAdmission, ValidatedResponse, validate_response,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 6 {
        return Err(
            "usage: mcloving-jenkins-compiler-admission RESPONSE SOURCE REQUEST_ID JOB_ID JOB_GENERATION"
                .into(),
        );
    }
    let response = read_regular_bounded(&arguments[1], 65_536)?;
    let source = read_regular_bounded(&arguments[2], 262_144)?;
    let validated = validate_response(
        &response,
        ExpectedAdmission {
            request_id: &arguments[3],
            job_id: &arguments[4],
            job_generation: &arguments[5],
            source: &source,
        },
    )?;
    match validated {
        ValidatedResponse::Admitted(receipt) => {
            println!("status=admitted");
            println!("request_id={}", receipt.request_id);
            println!("job_id={}", receipt.job_id);
            println!("state={}", receipt.state);
            println!("source_sha256={}", receipt.source_sha256);
            println!("pipeline_yaml_sha256={}", receipt.pipeline_yaml_sha256);
            println!("jobstate_yaml_sha256={}", receipt.jobstate_yaml_sha256);
            println!("semantic_ir_sha256={}", receipt.semantic_ir_sha256);
            println!("canonical_ir_sha256={}", receipt.canonical_ir_sha256);
            println!("stages={}", receipt.stages);
            println!("steps={}", receipt.steps);
        }
        ValidatedResponse::Unsupported { code } => {
            println!("status=unsupported");
            println!("code={code}");
        }
        ValidatedResponse::Rejected { code } => {
            println!("status=rejected");
            println!("code={code}");
        }
    }
    Ok(())
}

fn read_regular_bounded(path: impl AsRef<Path>, limit: usize) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds its byte limit", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} grew beyond its byte limit", path.display()),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::read_regular_bounded;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn test_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "mcloving-admission-input-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create test root");
        root
    }

    #[test]
    fn admission_inputs_are_regular_and_bounded() {
        let root = test_root();
        let regular = root.join("regular");
        fs::write(&regular, b"bounded").expect("write regular file");
        assert_eq!(read_regular_bounded(&regular, 7).unwrap(), b"bounded");

        let oversized = root.join("oversized");
        fs::write(&oversized, vec![0_u8; 9]).expect("write oversized file");
        assert!(read_regular_bounded(&oversized, 8).is_err());
        assert!(read_regular_bounded(&root, 8).is_err());

        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn admission_inputs_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let root = test_root();
        let regular = root.join("regular");
        fs::write(&regular, b"bounded").expect("write regular file");
        let link = root.join("link");
        symlink(&regular, &link).expect("create symlink");
        assert!(read_regular_bounded(&link, 8).is_err());

        fs::remove_dir_all(root).expect("remove test root");
    }
}
