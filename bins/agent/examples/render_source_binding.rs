//! Operator tool for the dogfood deployment (PAR-005): renders a sealed
//! source binding for one repository the way the product tests do, from a
//! small intent file, and prints the digests a pipeline and a controller
//! catalog need. It writes, owner-private, into the intent's private
//! directory: the pinned acquirer copy, the acquirer configuration with its
//! runtime closure, the credential, the receipt signing key, the secret
//! marker set and the agent bindings file.
//!
//! usage: render_source_binding <intent.json>
//!
//! intent: {"mapping_id","organization_id","project_id","pipeline_id",
//!          "trust_pool","repository_url","private_dir","acquirer_binary",
//!          "transport_root","transport_bytes","output_root",
//!          "deployment_identity","operator_identity","max_files",
//!          "max_total_bytes","max_file_bytes","credential"?,
//!          "launcher_profile"?}
use mcloving_agent::source::{SourceBinding, SourceBindings, SourceLauncher};
use mcloving_source_acquirer::{
    PROTOCOL_VERSION, RepositoryBinding, SourceConfig, content_sha256, inspect_runtime_closure,
    marker_set_digest, runtime_closure_digest, sha256_file,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    mapping_id: String,
    organization_id: String,
    project_id: String,
    pipeline_id: String,
    trust_pool: String,
    repository_url: String,
    private_dir: PathBuf,
    acquirer_binary: PathBuf,
    transport_root: PathBuf,
    transport_bytes: u64,
    output_root: PathBuf,
    deployment_identity: String,
    operator_identity: String,
    max_files: usize,
    max_total_bytes: u64,
    max_file_bytes: u64,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    launcher_profile: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, bytes).expect("write private file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn git_output(args: &[&str]) -> String {
    let output = std::process::Command::new("/usr/bin/git")
        .args(args)
        .output()
        .expect("run git");
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout)
        .expect("git output")
        .trim()
        .to_owned()
}

fn launcher(profile: Option<String>) -> Option<SourceLauncher> {
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .map(|text| text.trim() == "1")
            .unwrap_or(false);
    let profile = profile.or_else(|| restricted.then(|| "mcloving-source-acquirer".to_owned()))?;
    let aa_exec = ["/usr/bin/aa-exec", "/usr/sbin/aa-exec"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("aa-exec is required under the user-namespace restriction");
    Some(SourceLauncher {
        aa_exec_sha256: hex(&Sha256::digest(
            std::fs::read(&aa_exec).expect("read aa-exec"),
        )),
        aa_exec,
        profile,
    })
}

#[tokio::main]
async fn main() {
    let intent_path = std::env::args()
        .nth(1)
        .expect("usage: render_source_binding <intent.json>");
    let intent: Intent = serde_json::from_slice(&std::fs::read(&intent_path).expect("read intent"))
        .expect("parse intent");
    let private = &intent.private_dir;
    std::fs::create_dir_all(private).expect("create private dir");
    std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700))
        .expect("chmod private");

    let executable = private.join("source-acquirer");
    let _ = std::fs::remove_file(&executable);
    std::fs::copy(&intent.acquirer_binary, &executable).expect("copy acquirer");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
        .expect("chmod acquirer");
    let executable_sha256 = hex(&Sha256::digest(
        std::fs::read(&executable).expect("read acquirer"),
    ));

    let git = PathBuf::from("/usr/bin/git");
    let git_remote_https =
        std::fs::canonicalize(Path::new(&git_output(&["--exec-path"])).join("git-remote-https"))
            .expect("git-remote-https");
    let runtime_closure =
        inspect_runtime_closure(&[git.clone(), git_remote_https.clone(), executable.clone()])
            .await
            .expect("runtime closure");

    let parsed = url::Url::parse(&intent.repository_url).expect("repository url");
    assert_eq!(
        parsed.scheme(),
        "https",
        "the dogfood binding names an https repository"
    );
    let credential = intent.credential.clone().unwrap_or_else(|| {
        format!(
            "dogfood-no-credential-{}",
            hex(&Sha256::digest(intent.mapping_id.as_bytes()))
        )
    });
    let signing_key: Vec<u8> = {
        let mut hasher = Sha256::new();
        hasher.update(b"mcloving-dogfood-receipt-signing-key/v1\0");
        hasher.update(intent.deployment_identity.as_bytes());
        hasher.update(intent.mapping_id.as_bytes());
        let seed = hasher.finalize();
        let mut key = seed.to_vec();
        key.extend_from_slice(&Sha256::digest(seed));
        key
    };
    let ca_bundle = PathBuf::from("/etc/ssl/certs/ca-certificates.crt");
    let config = SourceConfig {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        schema_version: "source-acquisition-v1".to_owned(),
        acquirer_id: format!("dogfood-{}", intent.mapping_id),
        deployment_identity: intent.deployment_identity.clone(),
        operator_identity: intent.operator_identity.clone(),
        generation: 1,
        primary_repository: RepositoryBinding {
            provider_identity: parsed.host_str().expect("host").to_owned(),
            repository_identity: parsed
                .path()
                .trim_matches('/')
                .trim_end_matches(".git")
                .to_owned(),
            repository_url: intent.repository_url.clone(),
        },
        allow_untrusted_forks: false,
        allowed_fork_repositories: Vec::new(),
        allowed_submodule_repositories: Vec::new(),
        allowed_ref_prefixes: vec!["refs/heads/".to_owned()],
        allowed_sparse_roots: Vec::new(),
        git_executable_path: git.clone(),
        git_executable_sha256: sha256_file(&git).await.expect("git digest"),
        git_remote_https_executable_path: git_remote_https.clone(),
        git_remote_https_executable_sha256: sha256_file(&git_remote_https)
            .await
            .expect("helper digest"),
        runtime_closure_sha256: runtime_closure_digest(&runtime_closure).expect("closure digest"),
        runtime_closure,
        git_version: git_output(&["--version"]),
        grant_id: format!("dogfood-read-grant-{}", intent.mapping_id),
        grant_version: "grant-v1".to_owned(),
        grant_scope: "repository:read".to_owned(),
        grant_expires_unix_ms: i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("time fits")
            + 365 * 24 * 3_600 * 1_000,
        credential_username: "git".to_owned(),
        credential_sha256: content_sha256(credential.as_bytes()),
        receipt_signing_key_id: format!("dogfood-signing-key-{}", intent.mapping_id),
        receipt_signing_key_sha256: content_sha256(&signing_key),
        secret_marker_set_sha256: marker_set_digest(&[credential.as_bytes().to_vec()]),
        max_depth: 8,
        max_files: intent.max_files,
        max_total_bytes: intent.max_total_bytes,
        max_file_bytes: intent.max_file_bytes,
        max_transport_bytes: intent.transport_bytes,
        max_path_bytes: 512,
        max_submodules: 0,
        command_timeout_ms: 120_000,
        transport_root: intent.transport_root.clone(),
        output_root: intent.output_root.clone(),
        ca_bundle_sha256: Some(hex(&Sha256::digest(
            std::fs::read(&ca_bundle).expect("system CA bundle"),
        ))),
        ca_bundle_path: Some(ca_bundle),
        test_allow_file_repositories: false,
        test_allow_http_loopback: false,
    };
    let config_path = private.join("config.json");
    write_private(
        &config_path,
        &serde_json::to_vec(&config).expect("config json"),
        0o400,
    );
    let credential_path = private.join("credential");
    write_private(&credential_path, credential.as_bytes(), 0o400);
    let signing_key_path = private.join("signing.key");
    write_private(&signing_key_path, &signing_key, 0o400);
    let secret_markers_path = private.join("markers");
    write_private(
        &secret_markers_path,
        &[credential.as_bytes(), b"\n"].concat(),
        0o400,
    );
    let binding = SourceBinding {
        mapping_id: intent.mapping_id.clone(),
        organization_id: intent.organization_id.clone(),
        project_id: intent.project_id.clone(),
        pipeline_id: intent.pipeline_id.clone(),
        trust_pool: intent.trust_pool.clone(),
        executable,
        executable_sha256,
        config_path,
        config_sha256: config.canonical_digest().expect("config digest"),
        credential_path,
        signing_key_path,
        secret_markers_path,
        launcher: launcher(intent.launcher_profile.clone()),
        test_mode: false,
    };
    let mapping_digest = binding.mapping_digest().expect("mapping digest");
    let bindings = SourceBindings {
        schema_version: "mcloving.agent-source-bindings/v1".into(),
        mappings: vec![binding],
    };
    let bindings_bytes = serde_json::to_vec(&bindings).expect("bindings json");
    let bindings_path = private.join("agent-source-bindings.json");
    write_private(&bindings_path, &bindings_bytes, 0o400);
    println!("mapping_id={}", intent.mapping_id);
    println!("mapping_digest={mapping_digest}");
    println!("bindings_path={}", bindings_path.display());
    println!("bindings_sha256={}", hex(&Sha256::digest(&bindings_bytes)));
}
