use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use mcloving_jenkins_compiler_admission::{ADMITTED_JOB_GENERATION, ADMITTED_JOB_ID};
use sha2::{Digest, Sha256};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
struct Inputs(PathBuf);
impl Inputs {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sequential-cli-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }
}
impl Drop for Inputs {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcloving-jenkins-compiler-admission"))
        .args(args)
        .output()
        .unwrap()
}
fn context(source: &[u8]) -> Vec<u8> {
    format!("{{:document-id \"cli-source\", :origin \"project-authored:cli-test\", :origin-kind :authored-document, :schema \"mcloving.jenkins.source-document/1\", :source-sha256 \"{:x}\"}}\n", Sha256::digest(source)).into_bytes()
}

#[test]
fn legacy_snapshot_and_golden_admission_cli_remain_unchanged() {
    let files = Inputs::new();
    let source = include_bytes!(
        "../../../migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile"
    );
    let source_path = files.write("source", source);
    let response_path = files.write("response", include_bytes!("fixtures/mig003-golden.edn"));
    let snapshot = cli(&["snapshot", &source_path]);
    assert!(snapshot.status.success());
    assert_eq!(snapshot.stdout, source);
    let result = cli(&[
        &response_path,
        &source_path,
        "mig003-golden",
        ADMITTED_JOB_ID,
        ADMITTED_JOB_GENERATION,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("status=admitted\nrequest_id=mig003-golden\n")
    );
}

#[test]
fn sequential_request_cli_emits_canonical_versioned_bytes() {
    let files = Inputs::new();
    let source =
        b"pipeline { agent any; stages { stage('Compile') { steps { sh 'printf ok' } } } }\n";
    let source_path = files.write("source", source);
    let context_path = files.write("context", &context(source));
    let result = cli(&[
        "request-sequential",
        &source_path,
        &context_path,
        "cli-request",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let request = String::from_utf8(result.stdout).unwrap();
    assert_eq!(request.lines().count(), 1);
    assert!(request.ends_with("}\n"));
    assert!(
        request
            .contains(":operation :compile-sequential, :protocol \"mcloving.jenkins.compiler/2\"")
    );
    assert!(request.contains(":source-path \"/input/Jenkinsfile\""));
}

#[test]
fn sequential_cli_rejects_bad_context_without_response_or_receipt() {
    let files = Inputs::new();
    let source_path = files.write("source", b"source must not leak");
    let context_path = files.write("context", b"{}");
    let response_path = files.write("response", b"{}\n");
    for arguments in [
        vec![
            "request-sequential",
            &source_path,
            &context_path,
            "cli-request",
        ],
        vec![
            "validate-sequential",
            &response_path,
            &source_path,
            &context_path,
            "cli-request",
        ],
    ] {
        let result = cli(&arguments);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("source must not leak"));
    }
}

#[test]
fn sequential_snapshot_cli_is_bounded_and_wrong_arity_never_uses_legacy_dispatch() {
    let files = Inputs::new();
    let oversized = files.write("oversized", &vec![b'x'; 262_145]);
    let result = cli(&["snapshot-sequential-source", &oversized]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"E_SOURCE_TOO_LARGE\n");
    for operation in [
        "snapshot-sequential-source",
        "snapshot-sequential-context",
        "request-sequential",
        "validate-sequential",
    ] {
        let result = cli(&[operation]);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"E_SEQUENTIAL_ARGUMENTS\n");
    }
    for operation in ["snapshot-sequential-source", "snapshot-sequential-context"] {
        let result = cli(&[operation, "a", "b", "c", "d"]);
        assert_eq!(result.stderr, b"E_SEQUENTIAL_ARGUMENTS\n");
    }
}
