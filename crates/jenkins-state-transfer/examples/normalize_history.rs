use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Result as IoResult, Write as _};
use std::path::Path;

use mcloving_jenkins_state_transfer::{
    ImportBinding, SealedHistory, admitted_destination_identity, admitted_source_identity,
    digest_tree, normalize_single_aborted_workflow,
};
use mcloving_state_transfer::{BuildResult, Digest, sha256, transform};

const PATHS: [&str; 5] = [
    "1/build.xml",
    "1/log",
    "1/log-index",
    "1/workflow-completed/flowNodeStore.xml",
    "permalinks",
];
const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(unix) {
        return Err(
            "exact Jenkins history normalization requires Unix no-follow file access".into(),
        );
    }
    let arguments = env::args().collect::<Vec<_>>();
    if !matches!(arguments.len(), 4 | 5) {
        return Err(
            "usage: normalize_history SEALED_BUILDS EXPECTED_TREE_SHA256 OPAQUE_EVIDENCE_ID [OUTPUT_BUNDLE]"
                .into(),
        );
    }
    let root = Path::new(&arguments[1]);
    let expected_tree_digest = parse_digest(&arguments[2])?;
    let files = load_exact_files(root)?;
    if digest_tree(&files)? != expected_tree_digest {
        return Err("sealed source digest mismatch".into());
    }
    let executable = fs::read(env::current_exe()?)?;
    let parsed = normalize_single_aborted_workflow(
        &SealedHistory {
            files,
            expected_tree_digest,
            opaque_evidence_id: arguments[3].clone(),
        },
        &ImportBinding {
            source: admitted_source_identity(),
            destination: admitted_destination_identity(),
            transform_implementation_digest: sha256(&executable),
            transform_configuration_digest: sha256(b"corpus052-single-aborted-workflow-v1"),
            provenance: "MIG-005A owner-held exact admitted-case source".to_owned(),
            source_job_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
            target_pipeline_id: "corpus-052-cinqict_jenkinsdev".to_owned(),
        },
    )?;
    let plan = transform(&parsed.bundle, &parsed.expected, &BTreeMap::new())?;
    let job = &plan.bundle.jobs[0];
    if job.previous_result != Some(BuildResult::Aborted) {
        return Err("normalized previous result is divergent".into());
    }
    println!("schema={}", plan.bundle.binding.schema);
    println!("source_tree_sha256={}", encode_digest(expected_tree_digest));
    println!("bundle_sha256={}", encode_digest(plan.bundle_digest));
    println!("record_count={}", plan.bundle.expected_record_ids.len());
    println!("build_count={}", job.builds.len());
    println!("next_build_number={}", job.next_build_number);
    println!("previous_result=aborted");
    println!("persistent_dependency=build-history");
    println!("production_authority=false");
    if let Some(output) = arguments.get(4) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        file.write_all(&plan.canonical_bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

fn load_exact_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    require_plain_directory(root)?;
    require_plain_directory(&root.join("1"))?;
    require_plain_directory(&root.join("1/workflow-completed"))?;
    let actual = regular_files(root)?;
    let expected = PATHS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("sealed source file denominator is divergent".into());
    }
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for relative in PATHS {
        let path = root.join(relative);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(format!("sealed source entry {relative} is not regular").into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(format!("sealed source entry {relative} is hard-linked").into());
            }
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("sealed source byte count overflow")?;
        if total > MAX_SOURCE_BYTES {
            return Err("sealed source exceeds byte limit".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(metadata.len() + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(format!("sealed source entry {relative} changed while reading").into());
        }
        files.insert(relative.to_owned(), bytes);
    }
    Ok(files)
}

fn regular_files(root: &Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err("sealed source contains a symbolic link".into());
            }
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or("sealed source path is not UTF-8")?
                    .replace('\\', "/");
                files.insert(relative);
            } else {
                return Err("sealed source contains an unsupported file type".into());
            }
        }
    }
    Ok(files)
}

fn require_plain_directory(path: &Path) -> IoResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sealed source parent is not a plain directory",
        ))
    }
}

fn parse_digest(value: &str) -> Result<Digest, Box<dyn std::error::Error>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("expected digest is not canonical lowercase SHA-256".into());
    }
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn encode_digest(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
