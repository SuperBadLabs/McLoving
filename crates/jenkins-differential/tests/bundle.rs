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
            "jenkins/build.json",
            "\"building\":false",
            "\"building\":true",
            "E_JENKINS_BUILD",
        ),
        (
            "jenkins/build.json",
            "\"inProgress\":false",
            "\"inProgress\":true",
            "E_JENKINS_BUILD",
        ),
        (
            "jenkins/build.json",
            "\"executorUtilization\":0.24",
            "\"executorUtilization\":0.99",
            "E_JENKINS_CAPTURE_IDENTITY",
        ),
        (
            "jenkins/wfapi.json",
            "\"id\":\"1\"",
            "\"id\":\"2\"",
            "E_JENKINS_WORKFLOW",
        ),
        (
            "jenkins/wfapi.json",
            "/job/diff-001-admitted/1/wfapi/describe",
            "/job/diff-001-admitted/2/wfapi/describe",
            "E_JENKINS_WORKFLOW",
        ),
        (
            "jenkins/wfapi.json",
            "\"endTimeMillis\":1785605100272",
            "\"endTimeMillis\":1785605098000",
            "E_JENKINS_WORKFLOW",
        ),
        (
            "jenkins/stage-build.json",
            "\"id\":\"6\"",
            "\"id\":\"9\"",
            "E_JENKINS_STAGE",
        ),
        (
            "jenkins/stage-build.json",
            "\"startTimeMillis\":1785605099899",
            "\"startTimeMillis\":1785605102000",
            "E_JENKINS_STAGE",
        ),
        (
            "jenkins/container-inspect.json",
            "\"NetworkMode\": \"none\"",
            "\"NetworkMode\": \"bridge\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Path\": \"/usr/bin/timeout\"",
            "\"Path\": \"/bin/sh\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"600s\"",
            "\"0s\"",
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
            "size=2147483648,mode=1777,rw,rprivate,nosuid,nodev,tmpcopyup",
            "size=0,mode=1777,rw,rprivate,nosuid,nodev,tmpcopyup",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Type\": \"k8s-file\"",
            "\"Type\": \"journald\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Size\": \"16MB\"",
            "\"Size\": \"0B\"",
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
            "JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Djava.awt.headless=true -Xms512m -Xmx2g",
            "JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Djava.awt.headless=true -Xms512m -Xmx3g",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"GroupAdd\": []",
            "\"GroupAdd\": [\"0\"]",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/container-inspect.json",
            "\"Source\": \"/home/srikanth/jenkins-oracle-228/plugins\"",
            "\"Source\": \"/tmp/unsealed-plugins\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/image-inspect.json",
            "\"Architecture\": \"amd64\"",
            "\"Architecture\": \"arm64\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/image-inspect.json",
            "sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02",
            "sha256:a4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/external-network.txt",
            "curl: (7)",
            "HTTP/1.1 200 OK\ncurl: (7)",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/console.txt",
            "Hello World\n[Pipeline] }",
            "Hello World\nunexpected output\n[Pipeline] }",
            "E_JENKINS_LOG",
        ),
        (
            "jenkins/runtime.txt",
            "openjdk version \"21.0.11\"",
            "openjdk version \"22.0.0\"",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/runtime.txt",
            "controller_timeout_seconds=600",
            "controller_timeout_seconds=0",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/runtime.txt",
            "jenkins_home_ceiling_bytes=2147483648",
            "jenkins_home_ceiling_bytes=0",
            "E_JENKINS_CONTAINMENT",
        ),
        (
            "jenkins/file-sha256.txt",
            "/home/srikanth/mcloving-diff001-20260801T174500Z-v43/evidence/jenkins/Jenkinsfile",
            "/tmp/substituted-capture/Jenkinsfile",
            "E_JENKINS_CAPTURE_MANIFEST",
        ),
        (
            "jenkins/file-sha256.txt",
            "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100",
            "766ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100",
            "E_JENKINS_CAPTURE_MANIFEST",
        ),
        (
            "jenkins/PLUGIN_SHA256SUMS",
            "695c029c078e91dd423a4f0b98bd4e24a60469826088e7855ad022fc1a134e92",
            "795c029c078e91dd423a4f0b98bd4e24a60469826088e7855ad022fc1a134e92",
            "E_JENKINS_PLUGINS",
        ),
        (
            "jenkins/init.groovy",
            "new File('/fixture/Jenkinsfile')",
            "new File('/fixture/Otherfile')",
            "E_JENKINS_SOURCE",
        ),
        (
            "mcloving/mcloving-raw.json",
            "48656c6c6f20576f726c640a",
            "476f6f6462796520576f726c640a",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "7b09726b2edfce62285608b12dbd89adc473bb4872ca72e2371dbb58e4d88cd4",
            "8b09726b2edfce62285608b12dbd89adc473bb4872ca72e2371dbb58e4d88cd4",
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
            "\"created\": true",
            "\"created\": false",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"dag_mode\": true",
            "\"dag_mode\": false",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"fail_fast\": true",
            "\"fail_fast\": false",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"kind\": \"work\"",
            "\"kind\": \"post\"",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"priority\": 0,\n      \"status\": \"succeeded\"",
            "\"priority\": 0,\n      \"status\": \"failed\"",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"logical_outcome\": \"succeeded\"",
            "\"logical_outcome\": \"failed\"",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"max_attempts\": 1",
            "\"max_attempts\": 2",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"cancellation_requested\": false",
            "\"cancellation_requested\": true",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"lease_owner\": \"diff-001-agent\"",
            "\"lease_owner\": \"substituted-agent\"",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "\"retry_of\": null",
            "\"retry_of\": \"00000000-0000-0000-0000-000000000001\"",
            "E_MCLOVING",
        ),
        (
            "mcloving/mcloving-raw.json",
            "e3ea476a-96b0-4b0b-8109-19fc2931b12f",
            "f3ea476a-96b0-4b0b-8109-19fc2931b12f",
            "E_MCLOVING",
        ),
        (
            "mcloving/runner-inspect-post.json",
            "\"ReadonlyRootfs\": true",
            "\"ReadonlyRootfs\": false",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "exec 'target/debug/deps/diff_001-3b7075192798a581' --nocapture",
            "exec 'target/debug/mcloving-controller' --help",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"CapAdd\": []",
            "\"CapAdd\": [\"CAP_SYS_ADMIN\"]",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"NetworkMode\": \"bridge\"",
            "\"NetworkMode\": \"host\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"Image\": \"docker.io/library/rust@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa\"",
            "\"Image\": \"docker.io/library/rust@sha256:87fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"NetworkID\": \"mcloving-diff001-net-v33\"",
            "\"NetworkID\": \"external-bridge\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "MCLOVING_TEST_DATABASE_URL=postgres://mcloving@mcloving-diff001-db-v33:5432/mcloving",
            "MCLOVING_TEST_DATABASE_URL=postgres://mcloving@substituted-db:5432/mcloving",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "MCLOVING_DIFF001_EVIDENCE_DIR=/evidence",
            "MCLOVING_DIFF001_EVIDENCE_DIR=/tmp/unsealed-evidence",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"GroupAdd\": []",
            "\"GroupAdd\": [\"0\"]",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runner-inspect-pre.json",
            "\"CAP_SYS_CHROOT\"",
            "\"CAP_SYS_ADMIN\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runtime.txt",
            "groups=1000(1000)",
            "groups=1000(1000),0(root)",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/runtime.txt",
            "7.0.0-28-generic",
            "7.0.0-29-generic",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/test-output.txt",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s\ntest result: FAILED. 0 passed; 1 failed",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"CapAdd\": []",
            "\"CapAdd\": [\"CAP_SYS_ADMIN\"]",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"NetworkMode\": \"bridge\"",
            "\"NetworkMode\": \"host\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"PublishAllPorts\": false",
            "\"PublishAllPorts\": true",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"5432/tcp\": null",
            "\"5432/tcp\": [{\"HostIp\":\"0.0.0.0\",\"HostPort\":\"49152\"}]",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"NetworkID\": \"mcloving-diff001-net-v33\"",
            "\"NetworkID\": \"external-bridge\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/network-inspect.json",
            "\"internal\": true",
            "\"internal\": false",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"Mounts\": []",
            "\"Mounts\": [{\"Type\":\"bind\",\"Source\":\"/run/podman/podman.sock\",\"Destination\":\"/run/podman/podman.sock\",\"RW\":true}]",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "0a2f87bcff0a47c5ac6caa1d36a4fc4daa7cd3c6f0bda689bd06cf3c2e198644",
            "1a2f87bcff0a47c5ac6caa1d36a4fc4daa7cd3c6f0bda689bd06cf3c2e198644",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "\"CAP_SYS_CHROOT\"",
            "\"CAP_SYS_ADMIN\"",
            "E_MCLOVING_CONTAINMENT",
        ),
        (
            "mcloving/postgres-inspect.json",
            "PG_VERSION=17.6",
            "PG_VERSION=17.7",
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
        if path == "jenkins/file-sha256.txt" {
            reseal_outer(temporary.path());
        } else {
            reseal(temporary.path());
        }
        let error = verify_bundle(temporary.path()).expect_err("mutation must fail closed");
        assert_eq!(error.code, code, "unexpected error for {path}: {error}");
    }
}

#[test]
fn contradictory_status_terminal_summary_fails_closed() {
    let temporary = tempfile::tempdir().expect("create mutation root");
    copy_tree(&fixture(), temporary.path());
    let target = temporary.path().join("mcloving/mcloving-raw.json");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&target).expect("read raw receipt"))
            .expect("parse raw receipt");
    raw["status"]["terminal_summary"]["exit_code"] = 23.into();
    raw["status"]["terminal_summary"]["termination"] = "timed_out".into();
    fs::write(
        &target,
        serde_json::to_vec_pretty(&raw).expect("serialize raw receipt"),
    )
    .expect("write raw receipt");
    reseal(temporary.path());
    assert_eq!(
        verify_bundle(temporary.path()).unwrap_err().code,
        "E_MCLOVING"
    );
}

#[test]
fn undeclared_jenkins_mount_fails_closed() {
    let temporary = tempfile::tempdir().expect("create mutation root");
    copy_tree(&fixture(), temporary.path());
    let target = temporary.path().join("jenkins/container-inspect.json");
    let mut inspect: serde_json::Value =
        serde_json::from_slice(&fs::read(&target).expect("read inspect")).expect("parse inspect");
    let container = inspect
        .as_array_mut()
        .and_then(|values| values.first_mut())
        .expect("inspect container");
    let mounts = container["Mounts"].as_array_mut().expect("inspect mounts");
    let mut injected = mounts[0].clone();
    injected["Source"] = "/run/user/1000/podman/podman.sock".into();
    injected["Destination"] = "/run/podman/podman.sock".into();
    mounts.push(injected);
    fs::write(
        &target,
        serde_json::to_vec_pretty(&inspect).expect("serialize inspect"),
    )
    .expect("write inspect");
    reseal(temporary.path());
    assert_eq!(
        verify_bundle(temporary.path()).unwrap_err().code,
        "E_JENKINS_CONTAINMENT"
    );
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
    let capture_manifest = root.join("jenkins/file-sha256.txt");
    let capture = fs::read_to_string(&capture_manifest).expect("read Jenkins capture manifest");
    let mut capture_lines = Vec::new();
    for line in capture.lines() {
        let (_, absolute_path) = line.split_once("  ").expect("parse capture manifest line");
        let name = Path::new(absolute_path)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("capture manifest leaf name");
        let bytes = fs::read(root.join("jenkins").join(name)).expect("read captured Jenkins file");
        capture_lines.push(format!("{}  {absolute_path}", hex(&Sha256::digest(bytes))));
    }
    fs::write(capture_manifest, format!("{}\n", capture_lines.join("\n")))
        .expect("reseal Jenkins capture manifest");
    reseal_outer(root);
}

fn reseal_outer(root: &Path) {
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
