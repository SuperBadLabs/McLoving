use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mcloving_jenkins_inventory::export::{ExportOptions, export_snapshot};
use mcloving_jenkins_inventory::{
    CompatibilityDisposition, inventory_snapshot_sha256, load_bundle, reconcile,
    seal_manifest_directory,
};
use sha2::{Digest, Sha256};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mcloving-export-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create root");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn frozen_home_exports_and_reconciles_without_granting_execution_authority() {
    let root = TestDirectory::new("valid");
    write_snapshot(&root.0);
    let output = root.0.join("inventory");

    export_snapshot(&options(&root.0, &output)).expect("export");
    seal_manifest_directory(&output).expect("seal");
    let bundle = load_bundle(&output).expect("load");
    let fingerprint = inventory_snapshot_sha256(&bundle);
    let ledger = reconcile(&bundle, &fingerprint).expect("reconcile");

    assert_eq!(
        bundle.job_graph.jobs[0].source_sha256,
        digest(
            b"@Library('fixture@v1') _\npipeline { agent none; stages { stage('Verify') { steps { sh 'true && false'; echo '<safe>' } } } }"
        )
    );
    assert_eq!(ledger.population.jobs_total, 1);
    assert_eq!(ledger.population.principals, 1);
    assert_eq!(ledger.population.acl_entries, 1);
    assert_eq!(ledger.population.runtime_dependencies, 1);
    assert_eq!(ledger.population.persistent_record_classes, 1);
    assert_eq!(
        ledger.jobs[0].disposition,
        CompatibilityDisposition::Unsupported
    );
    assert!(!output.join("eligibility-ledger.yaml").exists());
}

#[test]
fn export_is_create_new_and_refuses_to_overwrite_a_reviewed_directory() {
    let root = TestDirectory::new("immutable");
    write_snapshot(&root.0);
    let output = root.0.join("inventory");
    fs::create_dir(&output).expect("precreate output");

    let error = export_snapshot(&options(&root.0, &output)).expect_err("must refuse overwrite");
    assert_eq!(error.code, "INV_IMMUTABLE");
}

#[cfg(unix)]
#[test]
fn export_rejects_symlinks_in_persistent_build_evidence() {
    use std::os::unix::fs::symlink;

    let root = TestDirectory::new("symlink");
    write_snapshot(&root.0);
    let job = root.0.join("home/jobs/example");
    symlink("/etc/passwd", job.join("builds/1/escaped")).expect("create hostile link");

    let error =
        export_snapshot(&options(&root.0, &root.0.join("inventory"))).expect_err("reject symlink");
    assert_eq!(error.code, "INV_EXPORT_FILE_TYPE");
}

fn options(root: &Path, output: &Path) -> ExportOptions {
    ExportOptions {
        snapshot_root: root.to_owned(),
        output: output.to_owned(),
        controller_id: "jenkins/test".to_owned(),
        controller_url: "https://jenkins.invalid".to_owned(),
        epoch_id: "epoch-test".to_owned(),
        source_generation: digest(b"source generation"),
        collected_at: "2026-07-31T06:44:17Z".to_owned(),
        exporter_id: "mcloving-inventory-export".to_owned(),
        exporter_version: "test".to_owned(),
        exporter_sha256: digest(b"exporter"),
        owner: "test-owner".to_owned(),
        provenance: "contained frozen fixture".to_owned(),
    }
}

fn write_snapshot(root: &Path) {
    let job = root.join("home/jobs/example");
    let user = root.join("home/users/admin");
    let build = job.join("builds/1");
    fs::create_dir_all(&build).expect("build tree");
    fs::create_dir_all(&user).expect("user tree");
    fs::create_dir_all(root.join("plugins")).expect("plugins");
    fs::create_dir_all(root.join("corpus")).expect("corpus");
    fs::write(
        root.join("home/config.xml"),
        r#"<hudson>
  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
    <disableSignup>true</disableSignup>
  </securityRealm>
  <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
    <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
  </authorizationStrategy>
</hudson>"#,
    )
    .expect("global config");
    fs::write(
        user.join("config.xml"),
        r#"<user><id>admin</id><fullName>Administrator</fullName></user>"#,
    )
    .expect("user config");
    fs::write(
        job.join("config.xml"),
        r#"<flow-definition>
  <description>sealed corpus file example.Jenkinsfile</description>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
    <script>@Library('fixture@v1') _
pipeline { agent none; stages { stage('Verify') { steps { sh 'true &amp;&amp; false'; echo '&lt;safe&gt;' } } } }</script>
  </definition>
  <triggers/>
  <disabled>true</disabled>
</flow-definition>"#,
    )
    .expect("job config");
    fs::write(
        build.join("build.xml"),
        "<build><result>SUCCESS</result></build>",
    )
    .expect("build");
    fs::write(
        root.join("home/jenkins.install.UpgradeWizard.state"),
        "2.568.1\n",
    )
    .expect("core version");
    fs::write(
        root.join("ROOT_SHA256SUMS"),
        format!("{}  home/config.xml\n", digest(b"root")),
    )
    .expect("root attestation");
    fs::write(
        root.join("JOB_CONFIG_SHA256SUMS"),
        format!("{}  home/jobs/example/config.xml\n", digest(b"job")),
    )
    .expect("job attestation");
    fs::write(
        root.join("PLUGIN_SHA256SUMS"),
        format!("{}  plugins/workflow-cps.jpi\n", digest(b"plugin")),
    )
    .expect("plugin attestation");
    fs::write(
        root.join("CORPUS_SHA256SUMS"),
        format!("{}  corpus/example.Jenkinsfile\n", digest(b"corpus")),
    )
    .expect("corpus attestation");
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
