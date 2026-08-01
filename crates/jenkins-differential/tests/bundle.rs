use std::fs;
use std::path::{Path, PathBuf};

use mcloving_jenkins_differential::{CASE, SCHEMA, verify_bundle};
use sha2::{Digest, Sha256};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../migration/mario-jenkins-oracle-228/corpus-v1/differential-v1")
}

#[test]
fn exact_two_sided_receipt_is_certified() {
    let receipt = verify_bundle(&fixture()).expect("verify exact differential bundle");
    assert_eq!(receipt.schema, SCHEMA);
    assert_eq!(receipt.case, CASE);
    assert_eq!(receipt.files, 30);
    assert_eq!(receipt.admitted_cases, 1);
    assert_eq!(receipt.certified_cases, 1);
    assert_eq!(receipt.non_admitted_cases, 227);
}

#[test]
fn self_consistent_semantic_and_containment_mutations_fail_closed() {
    for (path, from, to, code) in [
        (
            "jenkins/build.json",
            "\"result\":\"SUCCESS\"",
            "\"result\":\"FAILURE\"",
            "E_JENKINS_BUILD",
        ),
        (
            "jenkins/container-inspect.json",
            "\"NetworkMode\": \"none\"",
            "\"NetworkMode\": \"bridge\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"MemorySwap\": 4294967296",
            "\"MemorySwap\": 0",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Soft\": 1024",
            "\"Soft\": 2048",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"/tmp\": \"rw,noexec,nosuid,nodev,size=2g,rprivate,tmpcopyup\"",
            "\"/tmp\": \"rw,noexec,nosuid,nodev,size=1g,rprivate,tmpcopyup\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"CAP_SYS_CHROOT\"",
            "\"CAP_SYS_ADMIN\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Source\": \"/home/srikanth/jenkins-oracle-228/plugins\"",
            "\"Source\": \"/tmp/unsealed-plugins\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/console.txt",
            "Hello World\n[Pipeline] }",
            "Hello World\nunexpected output\n[Pipeline] }",
            "E_JENKINS_LOG",
        ),
        (
            "jenkins/PLUGIN_SHA256SUMS",
            "695c029c078e91dd423a4f0b98bd4e24a60469826088e7855ad022fc1a134e92",
            "795c029c078e91dd423a4f0b98bd4e24a60469826088e7855ad022fc1a134e92",
            "E_JENKINS_PLUGINS",
        ),
        (
            "mcloving/mcloving-raw.json",
            "48656c6c6f20576f726c640a",
            "476f6f6462796520576f726c640a",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "2a9b8b7bcd076950c67de874bd1e2b693af511ad55a7de3495d5c0b4210349d3",
            "3a9b8b7bcd076950c67de874bd1e2b693af511ad55a7de3495d5c0b4210349d3",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"sequence\": 0",
            "\"sequence\": 9",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "76b55bd3-7040-40b9-8dcf-243b2b5f6f45",
            "86b55bd3-7040-40b9-8dcf-243b2b5f6f45",
            "E_MCLOVING",
        ),
        (
            "mcloving/runner-inspect-post.json",
            "\"ReadonlyRootfs\": true",
            "\"ReadonlyRootfs\": false",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "coverage.yaml",
            "admitted_cases: 1",
            "admitted_cases: 2",
            "E_COVERAGE",
        ),
    ] {
        let temporary = tempfile::tempdir().expect("create mutation root");
        copy_tree(&fixture(), temporary.path());
        let target = temporary.path().join(path);
        let original = fs::read_to_string(&target).expect("read mutation target");
        let mutation = original.replace(from, to);
        assert_ne!(original, mutation, "mutation must change {path}");
        fs::write(&target, mutation).expect("write mutation");
        reseal(temporary.path());
        let error = verify_bundle(temporary.path()).expect_err("mutation must fail closed");
        assert_eq!(error.code, code, "unexpected error for {path}: {error}");
    }
}

#[test]
fn manifest_path_and_file_set_are_exact() {
    let temporary = tempfile::tempdir().expect("create mutation root");
    copy_tree(&fixture(), temporary.path());
    fs::OpenOptions::new()
        .append(true)
        .open(temporary.path().join("SHA256SUMS"))
        .expect("open manifest")
        .write_all(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ../escape\n")
        .expect("append unsafe path");
    assert_eq!(verify_bundle(temporary.path()).unwrap_err().code, "E_PATH");
}

#[test]
fn unmanifested_files_fail_closed() {
    let temporary = tempfile::tempdir().expect("create mutation root");
    copy_tree(&fixture(), temporary.path());
    fs::write(
        temporary.path().join("unmanifested.txt"),
        b"hidden evidence",
    )
    .expect("write extra file");
    assert_eq!(verify_bundle(temporary.path()).unwrap_err().code, "E_TREE");
}

#[cfg(unix)]
#[test]
fn symlinked_evidence_parent_fails_closed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("create mutation root");
    let external = tempfile::tempdir().expect("create external target");
    copy_tree(&fixture(), temporary.path());
    fs::create_dir(external.path().join("jenkins")).expect("create external directory");
    copy_tree(
        &temporary.path().join("jenkins"),
        &external.path().join("jenkins"),
    );
    fs::remove_dir_all(temporary.path().join("jenkins")).expect("remove evidence directory");
    symlink(
        external.path().join("jenkins"),
        temporary.path().join("jenkins"),
    )
    .expect("create evidence symlink");
    assert_eq!(verify_bundle(temporary.path()).unwrap_err().code, "E_TREE");
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("read source bundle") {
        let entry = entry.expect("read source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("read source type").is_dir() {
            fs::create_dir(&target).expect("create copied directory");
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy evidence file");
        }
    }
}

fn reseal(root: &Path) {
    let manifest = fs::read_to_string(root.join("SHA256SUMS")).expect("read manifest");
    let mut lines = Vec::new();
    for line in manifest.lines() {
        let (_, name) = line.split_once("  ").expect("parse manifest line");
        let bytes = fs::read(root.join(name)).expect("read manifested file");
        lines.push(format!("{}  {name}", hex(&Sha256::digest(bytes))));
    }
    fs::write(root.join("SHA256SUMS"), format!("{}\n", lines.join("\n"))).expect("reseal manifest");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

use std::io::Write;
