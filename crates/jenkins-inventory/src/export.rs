//! Read-only export of a frozen Jenkins home into the inventory v1 contract.
//!
//! The exporter is intentionally conservative. Inline CPS definitions are
//! inventoried as an opaque scripted runtime dependency and build history is
//! marked unsupported until the later state-transform ticket certifies it.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use quick_xml::Reader;
use quick_xml::events::{BytesRef, Event};
use sha2::{Digest, Sha256};

use super::{
    AclEntry, ApprovedDisposition, ClientCaller, ClientDirection, ClientRecord,
    CompatibilityDisposition, CountEvidence, DependencyMutability, IDENTITY_CLIENT_FILE,
    IdentityClientManifest, InventoryError, JOB_GRAPH_FILE, JobDependencies, JobGraphManifest,
    JobRecord, JobRequirement, JobStateRecords, OperationalState, PERSISTENT_STATE_FILE,
    PersistentStateManifest, Principal, PrincipalKind, PrincipalLifecycle, RUNTIME_DEPENDENCY_FILE,
    RuntimeDependency, RuntimeDependencyKind, RuntimeDependencyManifest, SCHEMA_VERSION,
    ScopeDisposition, SecurityRealm, SetEvidence, SnapshotBinding, StateRecord,
    StateTransformEvidence, acl_entry_set_sha256, client_set_sha256, count_subject_sha256,
    dependency_set_sha256, job_graph_set_sha256, principal_set_sha256, sha256_hex,
    state_class_set_sha256,
};

const JOB_COLLECTOR: &str = "offline-posix-job-scan-v1";
const IDENTITY_COLLECTOR: &str = "offline-jenkins-identity-scan-v1";
const RUNTIME_COLLECTOR: &str = "offline-cps-runtime-scan-v1";
const STATE_COLLECTOR: &str = "offline-build-history-scan-v1";
const INDEFINITE_RETENTION: &str = "9999-12-31T23:59:59Z";

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub snapshot_root: PathBuf,
    pub output: PathBuf,
    pub controller_id: String,
    pub controller_url: String,
    pub epoch_id: String,
    pub source_generation: String,
    pub collected_at: String,
    pub exporter_id: String,
    pub exporter_version: String,
    pub exporter_sha256: String,
    pub owner: String,
    pub provenance: String,
}

#[derive(Debug)]
struct JobSource {
    id: String,
    config_bytes: Vec<u8>,
    script: String,
    definition_kind: String,
    enabled: bool,
    triggers: Vec<String>,
    description: String,
    build_root: PathBuf,
}

#[derive(Default, Debug)]
struct JobXml {
    root: String,
    description: String,
    script: String,
    definition_class: String,
    disabled: bool,
    triggers: BTreeSet<String>,
}

pub fn export_snapshot(options: &ExportOptions) -> Result<(), InventoryError> {
    validate_snapshot_layout(&options.snapshot_root)?;
    if options.output.exists() {
        return Err(InventoryError::new(
            "INV_IMMUTABLE",
            format!("{} already exists", options.output.display()),
        ));
    }

    let home = options.snapshot_root.join("home");
    let global_config = read_regular(&home.join("config.xml"))?;
    let plugin_profile_sha256 = hash_attestation(&options.snapshot_root.join("PLUGIN_SHA256SUMS"))?;
    let global_config_sha256 = sha256_hex(&global_config);
    let controller_core_version =
        fs::read_to_string(home.join("jenkins.install.UpgradeWizard.state"))
            .map_err(|error| {
                InventoryError::new(
                    "INV_EXPORT_IO",
                    format!("cannot read Jenkins core version: {error}"),
                )
            })?
            .trim()
            .to_owned();

    let binding = SnapshotBinding {
        schema: SCHEMA_VERSION.to_owned(),
        controller_id: options.controller_id.clone(),
        controller_url: options.controller_url.clone(),
        controller_core_version,
        plugin_profile_sha256,
        global_config_sha256: global_config_sha256.clone(),
        epoch_id: options.epoch_id.clone(),
        source_generation: options.source_generation.clone(),
        collected_at: options.collected_at.clone(),
        exporter_id: options.exporter_id.clone(),
        exporter_version: options.exporter_version.clone(),
        exporter_sha256: options.exporter_sha256.clone(),
        provenance: options.provenance.clone(),
    };

    let job_sources = collect_jobs(&home.join("jobs"))?;
    let job_source_evidence =
        hash_attestation(&options.snapshot_root.join("JOB_CONFIG_SHA256SUMS"))?;
    let job_graph = build_job_graph(
        &binding,
        &job_sources,
        &options.owner,
        &options.provenance,
        &job_source_evidence,
    )?;
    let identity_clients = build_identity_manifest(
        &binding,
        &home,
        &global_config,
        &options.owner,
        &options.provenance,
    )?;
    let runtime_dependencies = build_runtime_manifest(
        &binding,
        &job_sources,
        &options.owner,
        &options.provenance,
        &job_source_evidence,
    )?;
    let persistent_state =
        build_state_manifest(&binding, &job_sources, &options.owner, &options.provenance)?;

    fs::create_dir(&options.output).map_err(|error| {
        InventoryError::new(
            "INV_EXPORT_IO",
            format!("cannot create {}: {error}", options.output.display()),
        )
    })?;
    write_yaml_new(options.output.join(JOB_GRAPH_FILE), &job_graph)?;
    write_yaml_new(options.output.join(IDENTITY_CLIENT_FILE), &identity_clients)?;
    write_yaml_new(
        options.output.join(RUNTIME_DEPENDENCY_FILE),
        &runtime_dependencies,
    )?;
    write_yaml_new(
        options.output.join(PERSISTENT_STATE_FILE),
        &persistent_state,
    )?;
    Ok(())
}

fn validate_snapshot_layout(root: &Path) -> Result<(), InventoryError> {
    for relative in [
        "home",
        "home/config.xml",
        "home/jenkins.install.UpgradeWizard.state",
        "home/jobs",
        "home/users",
        "plugins",
        "corpus",
        "ROOT_SHA256SUMS",
        "JOB_CONFIG_SHA256SUMS",
        "PLUGIN_SHA256SUMS",
        "CORPUS_SHA256SUMS",
    ] {
        let path = root.join(relative);
        fs::symlink_metadata(&path).map_err(|error| {
            InventoryError::new(
                "INV_EXPORT_LAYOUT",
                format!(
                    "required frozen-snapshot path {} is unavailable: {error}",
                    path.display()
                ),
            )
        })?;
    }
    Ok(())
}

fn collect_jobs(root: &Path) -> Result<Vec<JobSource>, InventoryError> {
    let mut directories = read_directories(root)?;
    directories.sort();
    let mut jobs = Vec::with_capacity(directories.len());
    for directory in directories {
        let id = utf8_filename(&directory)?;
        let config_path = directory.join("config.xml");
        let config_bytes = read_regular(&config_path)?;
        let xml = parse_job_xml(&config_bytes)?;
        if xml.root != "flow-definition" {
            return Err(InventoryError::new(
                "INV_EXPORT_JOB_KIND",
                format!("job {id} has unsupported Jenkins item type {}", xml.root),
            ));
        }
        if xml.script.is_empty() {
            return Err(InventoryError::new(
                "INV_EXPORT_SOURCE",
                format!("job {id} has no inline Jenkins definition"),
            ));
        }
        jobs.push(JobSource {
            id,
            config_bytes,
            script: xml.script,
            definition_kind: if xml.definition_class.is_empty() {
                "jenkins-inline-unknown".to_owned()
            } else {
                xml.definition_class
            },
            enabled: !xml.disabled,
            triggers: xml.triggers.into_iter().collect(),
            description: xml.description,
            build_root: directory.join("builds"),
        });
    }
    if jobs.is_empty() {
        return Err(InventoryError::new(
            "INV_EXPORT_EMPTY",
            "frozen Jenkins home contains no jobs",
        ));
    }
    Ok(jobs)
}

fn build_job_graph(
    binding: &SnapshotBinding,
    sources: &[JobSource],
    owner: &str,
    provenance: &str,
    source_evidence: &str,
) -> Result<JobGraphManifest, InventoryError> {
    let mut jobs = Vec::with_capacity(sources.len());
    for source in sources {
        let source_sha256 = sha256_hex(source.script.as_bytes());
        let source_name = corpus_source_name(source);
        jobs.push(JobRecord {
            id: source.id.clone(),
            parent_id: None,
            kind: "pipeline".to_owned(),
            owner: owner.to_owned(),
            canonical_source: format!(
                "jenkins://{}/job/{}/inline/{}",
                binding.controller_id, source.id, source_name
            ),
            source_sha256,
            config_sha256: sha256_hex(&source.config_bytes),
            definition_kind: source.definition_kind.clone(),
            operational_state: OperationalState {
                enabled: source.enabled,
                generation: sha256_hex(&source.config_bytes),
                reason: "offline-frozen-source-state".to_owned(),
                actor: "jenkins/system".to_owned(),
            },
            shared_library_refs: scan_library_references(&source.script),
            triggers: source.triggers.clone(),
            platforms: Vec::new(),
            agent_labels: Vec::new(),
            toolchains: Vec::new(),
            node_authority: "parse-only-controller-no-executors-or-nodes".to_owned(),
            publishes_artifacts: source.script.contains("archiveArtifacts"),
            publishes_tests: source.script.contains("junit"),
            direct_child_count: count_evidence(
                binding,
                b"direct-child-count",
                &[source.id.as_bytes()],
                0,
                JOB_COLLECTOR,
                format!("{provenance}; job={} direct-child scan", source.id),
                source_evidence.to_owned(),
            ),
            scope: ApprovedDisposition {
                disposition: ScopeDisposition::InScope,
                approval: None,
            },
        });
    }
    let job_set = SetEvidence {
        collector_id: JOB_COLLECTOR.to_owned(),
        provenance: format!("{provenance}; canonical offline job-record scan"),
        source_sha256: source_evidence.to_owned(),
        entries_sha256: job_graph_set_sha256(binding, &jobs)?,
    };
    Ok(JobGraphManifest {
        binding: binding.clone(),
        controller_job_count: count_evidence(
            binding,
            b"controller-job-count",
            &[],
            u64::try_from(jobs.len())
                .map_err(|_| InventoryError::new("INV_COUNT_OVERFLOW", "job count exceeds u64"))?,
            JOB_COLLECTOR,
            format!("{provenance}; offline Jenkins jobs directory scan"),
            source_evidence.to_owned(),
        ),
        job_set,
        jobs,
    })
}

fn build_identity_manifest(
    binding: &SnapshotBinding,
    home: &Path,
    global_config: &[u8],
    owner: &str,
    provenance: &str,
) -> Result<IdentityClientManifest, InventoryError> {
    let global_xml = parse_selected_xml(global_config)?;
    let realm = global_xml
        .security_realm
        .unwrap_or_else(|| "unknown-security-realm".to_owned());
    let authorization = global_xml
        .authorization_strategy
        .unwrap_or_else(|| "unknown-authorization-strategy".to_owned());
    if authorization != "hudson.security.FullControlOnceLoggedInAuthorizationStrategy" {
        return Err(InventoryError::new(
            "INV_EXPORT_AUTHZ",
            format!("unsupported authorization strategy {authorization}"),
        ));
    }
    if !global_xml.deny_anonymous_read {
        return Err(InventoryError::new(
            "INV_EXPORT_AUTHZ",
            "oracle inventory requires anonymous access to be denied",
        ));
    }

    let mut users = read_directories(&home.join("users"))?;
    users.sort();
    let mut principals = Vec::new();
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(global_config);
    for user in users {
        let config = read_regular(&user.join("config.xml"))?;
        identity_hasher.update((config.len() as u64).to_be_bytes());
        identity_hasher.update(&config);
        let parsed = parse_selected_xml(&config)?;
        let id = parsed.user_id.ok_or_else(|| {
            InventoryError::new(
                "INV_EXPORT_IDENTITY",
                format!("{} has no immutable Jenkins user id", user.display()),
            )
        })?;
        principals.push(Principal {
            id: id.clone(),
            kind: PrincipalKind::User,
            aliases: parsed
                .full_name
                .filter(|name| name != &id)
                .into_iter()
                .collect(),
            historical_names: Vec::new(),
            groups: Vec::new(),
            membership_generation: sha256_hex(&config),
            lifecycle: PrincipalLifecycle::Active,
            provenance: format!("{provenance}; {}", user.display()),
        });
    }
    if principals.is_empty() {
        return Err(InventoryError::new(
            "INV_EXPORT_IDENTITY",
            "private Jenkins realm contains no users",
        ));
    }
    let identity_source_sha256 = hex_digest(identity_hasher.finalize());
    let security_realm = SecurityRealm {
        implementation: realm,
        config_sha256: sha256_hex(global_config),
        identity_provider_generation: identity_source_sha256.clone(),
    };
    let mut acl_entries = Vec::new();
    for job in read_directories(&home.join("jobs"))? {
        let job_id = utf8_filename(&job)?;
        for principal in &principals {
            acl_entries.push(AclEntry {
                job_id: job_id.clone(),
                principal_id: principal.id.clone(),
                scope: "effective-controller-full-control".to_owned(),
                permissions: vec![
                    "job.build".to_owned(),
                    "job.cancel".to_owned(),
                    "job.configure".to_owned(),
                    "job.read".to_owned(),
                    "overall.administer".to_owned(),
                ],
                generation: sha256_hex(global_config),
            });
        }
    }
    acl_entries.sort_by(|left, right| {
        (&left.job_id, &left.principal_id).cmp(&(&right.job_id, &right.principal_id))
    });
    let clients = vec![ClientRecord {
        id: "owner-operator".to_owned(),
        direction: ClientDirection::ReadWrite,
        caller: ClientCaller::Principal {
            principal_id: principals[0].id.clone(),
        },
        authentication: "jenkins-private-realm-session".to_owned(),
        endpoint: binding.controller_url.clone(),
        actions: vec![
            "administer".to_owned(),
            "build".to_owned(),
            "configure".to_owned(),
            "read".to_owned(),
        ],
        scope: "owner-designated-oracle-controller".to_owned(),
        owner: owner.to_owned(),
        observed_use: "owner-designated corpus-oracle administration".to_owned(),
        generation: identity_source_sha256.clone(),
    }];

    Ok(IdentityClientManifest {
        binding: binding.clone(),
        security_realm: security_realm.clone(),
        principal_count: count_evidence(
            binding,
            b"principal-count",
            &[],
            u64_len(principals.len())?,
            IDENTITY_COLLECTOR,
            format!("{provenance}; offline Jenkins users scan"),
            identity_source_sha256.clone(),
        ),
        principal_set: SetEvidence {
            collector_id: IDENTITY_COLLECTOR.to_owned(),
            provenance: format!("{provenance}; canonical realm and principal scan"),
            source_sha256: identity_source_sha256.clone(),
            entries_sha256: principal_set_sha256(binding, &security_realm, &principals)?,
        },
        principals,
        acl_entry_count: count_evidence(
            binding,
            b"acl-count",
            &[],
            u64_len(acl_entries.len())?,
            IDENTITY_COLLECTOR,
            format!("{provenance}; effective authorization-strategy expansion"),
            identity_source_sha256.clone(),
        ),
        acl_entry_set: SetEvidence {
            collector_id: IDENTITY_COLLECTOR.to_owned(),
            provenance: format!("{provenance}; canonical effective ACL expansion"),
            source_sha256: identity_source_sha256.clone(),
            entries_sha256: acl_entry_set_sha256(binding, &acl_entries)?,
        },
        acl_entries,
        client_count: count_evidence(
            binding,
            b"client-count",
            &[],
            u64_len(clients.len())?,
            IDENTITY_COLLECTOR,
            format!("{provenance}; owner-reviewed effective-client scan"),
            identity_source_sha256.clone(),
        ),
        client_set: SetEvidence {
            collector_id: IDENTITY_COLLECTOR.to_owned(),
            provenance: format!("{provenance}; canonical effective-client scan"),
            source_sha256: identity_source_sha256,
            entries_sha256: client_set_sha256(binding, &clients)?,
        },
        clients,
    })
}

fn build_runtime_manifest(
    binding: &SnapshotBinding,
    sources: &[JobSource],
    owner: &str,
    provenance: &str,
    source_evidence: &str,
) -> Result<RuntimeDependencyManifest, InventoryError> {
    let mut jobs = Vec::with_capacity(sources.len());
    for source in sources {
        let dependency = RuntimeDependency {
            id: "opaque-cps-runtime".to_owned(),
            kind: RuntimeDependencyKind::ControllerGlobal,
            requirements: scan_library_references(&source.script)
                .into_iter()
                .map(|reference| JobRequirement::SharedLibrary { reference })
                .chain(
                    source
                        .triggers
                        .iter()
                        .map(|declaration| JobRequirement::Trigger {
                            declaration: declaration.clone(),
                        }),
                )
                .collect(),
            owner: owner.to_owned(),
            implementation_sha256: binding.plugin_profile_sha256.clone(),
            config_sha256: sha256_hex(source.script.as_bytes()),
            resource_scope: format!(
                "entire-inline-jenkinsfile-sha256:{}",
                sha256_hex(source.script.as_bytes())
            ),
            mutability: DependencyMutability::Immutable,
            provenance: format!(
                "{provenance}; job={} opaque Jenkins CPS execution surface",
                source.id
            ),
            confidentiality: "internal".to_owned(),
            credential_reference: None,
            redaction_reference: None,
            secret_consumer: None,
            disposition: CompatibilityDisposition::Scripted,
        };
        let dependencies = vec![dependency];
        jobs.push(JobDependencies {
            job_id: source.id.clone(),
            dependency_count: count_evidence(
                binding,
                b"runtime-dependency-count",
                &[source.id.as_bytes()],
                1,
                RUNTIME_COLLECTOR,
                format!("{provenance}; job={} conservative runtime scan", source.id),
                source_evidence.to_owned(),
            ),
            dependency_set: SetEvidence {
                collector_id: RUNTIME_COLLECTOR.to_owned(),
                provenance: format!(
                    "{provenance}; job={} canonical runtime-dependency scan",
                    source.id
                ),
                source_sha256: source_evidence.to_owned(),
                entries_sha256: dependency_set_sha256(binding, &source.id, &dependencies)?,
            },
            dependencies,
        });
    }
    Ok(RuntimeDependencyManifest {
        binding: binding.clone(),
        jobs,
    })
}

fn build_state_manifest(
    binding: &SnapshotBinding,
    sources: &[JobSource],
    owner: &str,
    provenance: &str,
) -> Result<PersistentStateManifest, InventoryError> {
    let mut jobs = Vec::with_capacity(sources.len());
    for source in sources {
        let (build_count, build_tree_sha256) = count_and_hash_builds(&source.build_root)?;
        let records = if build_count == 0 {
            Vec::new()
        } else {
            vec![StateRecord {
                id: "build-history".to_owned(),
                kind: "build-number-result-log-and-metadata".to_owned(),
                owner: owner.to_owned(),
                record_count: count_evidence(
                    binding,
                    b"state-record-instance-count",
                    &[
                        source.id.as_bytes(),
                        b"build-history",
                        b"build-number-result-log-and-metadata",
                    ],
                    build_count,
                    STATE_COLLECTOR,
                    format!(
                        "{provenance}; job={} numeric build-directory scan",
                        source.id
                    ),
                    build_tree_sha256.clone(),
                ),
                source_sha256: build_tree_sha256.clone(),
                confidentiality: "internal".to_owned(),
                restore_target: format!("jenkins/job/{}/builds", source.id),
                conflict_policy: "reject-divergence".to_owned(),
                retention_policy_id: "jenkins-indefinite-oracle-retention".to_owned(),
                retention_policy_sha256: sha256_hex(b"jenkins-indefinite-oracle-retention-v1"),
                retention_deadline: INDEFINITE_RETENTION.to_owned(),
                forward_transform: unsupported_transform(
                    "mcloving/build-history-forward-unimplemented-v1",
                    "MIG-005A has not certified forward state transformation",
                    provenance,
                ),
                rollback_transform: unsupported_transform(
                    "mcloving/build-history-rollback-unimplemented-v1",
                    "MIG-005A has not certified rollback state transformation",
                    provenance,
                ),
                legal_holds: Vec::new(),
                external_consumers: Vec::new(),
                provenance: format!("{provenance}; job={} frozen build history", source.id),
            }]
        };
        jobs.push(JobStateRecords {
            job_id: source.id.clone(),
            record_class_count: count_evidence(
                binding,
                b"state-class-count",
                &[source.id.as_bytes()],
                u64_len(records.len())?,
                STATE_COLLECTOR,
                format!("{provenance}; job={} state-class scan", source.id),
                build_tree_sha256.clone(),
            ),
            record_class_set: SetEvidence {
                collector_id: STATE_COLLECTOR.to_owned(),
                provenance: format!("{provenance}; job={} canonical state-class scan", source.id),
                source_sha256: build_tree_sha256,
                entries_sha256: state_class_set_sha256(binding, &source.id, &records)?,
            },
            records,
        });
    }
    Ok(PersistentStateManifest {
        binding: binding.clone(),
        jobs,
    })
}

fn unsupported_transform(
    mapping_id: &str,
    reason: &str,
    provenance: &str,
) -> StateTransformEvidence {
    StateTransformEvidence {
        mapping_id: mapping_id.to_owned(),
        disposition: CompatibilityDisposition::Unsupported,
        evidence_sha256: sha256_hex(reason.as_bytes()),
        provenance: format!("{provenance}; {reason}"),
    }
}

fn count_evidence(
    binding: &SnapshotBinding,
    family: &[u8],
    owner_fields: &[&[u8]],
    count: u64,
    collector_id: &str,
    provenance: String,
    source_sha256: String,
) -> CountEvidence {
    CountEvidence {
        count,
        collector_id: collector_id.to_owned(),
        provenance,
        source_sha256,
        subject_sha256: count_subject_sha256(binding, family, owner_fields),
    }
}

fn count_and_hash_builds(root: &Path) -> Result<(u64, String), InventoryError> {
    if !root.exists() {
        return Ok((0, sha256_hex(b"no-build-history")));
    }
    let mut build_count = 0_u64;
    for entry in fs::read_dir(root).map_err(export_io(root))? {
        let entry = entry.map_err(|error| {
            InventoryError::new(
                "INV_EXPORT_IO",
                format!("cannot inspect {}: {error}", root.display()),
            )
        })?;
        if entry
            .file_type()
            .map_err(export_io(&entry.path()))?
            .is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            build_count = build_count.checked_add(1).ok_or_else(|| {
                InventoryError::new("INV_COUNT_OVERFLOW", "build count exceeds u64")
            })?;
        }
    }
    Ok((build_count, digest_tree(root)?))
}

fn digest_tree(root: &Path) -> Result<String, InventoryError> {
    let mut files = Vec::new();
    collect_regular_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (relative, path) in files {
        let bytes = read_regular(&path)?;
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(hex_digest(hasher.finalize()))
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), InventoryError> {
    for entry in fs::read_dir(current).map_err(export_io(current))? {
        let entry = entry.map_err(|error| {
            InventoryError::new(
                "INV_EXPORT_IO",
                format!("cannot inspect {}: {error}", current.display()),
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(export_io(&path))?;
        if file_type.is_symlink() {
            return Err(InventoryError::new(
                "INV_EXPORT_FILE_TYPE",
                format!("frozen snapshot contains symbolic link {}", path.display()),
            ));
        }
        if file_type.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| {
                    InventoryError::new(
                        "INV_EXPORT_PATH",
                        format!("cannot relativize {}: {error}", path.display()),
                    )
                })?
                .to_str()
                .ok_or_else(|| {
                    InventoryError::new(
                        "INV_EXPORT_PATH",
                        format!("{} is not valid UTF-8", path.display()),
                    )
                })?
                .to_owned();
            files.push((relative, path));
        }
    }
    Ok(())
}

fn corpus_source_name(source: &JobSource) -> String {
    let marker = "sealed corpus file ";
    source
        .description
        .split_once(marker)
        .map(|(_, name)| name.trim().to_owned())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 512
                && !name.contains('/')
                && !name.contains('\\')
                && !name.contains("..")
        })
        .unwrap_or_else(|| format!("inline-{}.Jenkinsfile", source.id))
}

fn scan_library_references(script: &str) -> Vec<String> {
    let mut references = BTreeSet::new();
    for marker in ["@Library('", "@Library(\""] {
        let quote = if marker.ends_with('\'') { '\'' } else { '"' };
        let mut remaining = script;
        while let Some((_, suffix)) = remaining.split_once(marker) {
            if let Some((reference, tail)) = suffix.split_once(quote) {
                if !reference.trim().is_empty() && reference.len() <= 256 {
                    references.insert(reference.trim().to_owned());
                }
                remaining = tail;
            } else {
                break;
            }
        }
    }
    references.into_iter().collect()
}

fn parse_job_xml(bytes: &[u8]) -> Result<JobXml, InventoryError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut parsed = JobXml::default();
    let mut path = Vec::<String>::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                if path.is_empty() {
                    parsed.root = name.clone();
                }
                if name == "definition" {
                    for attribute in start.attributes().with_checks(true) {
                        let attribute = attribute.map_err(|error| {
                            InventoryError::new(
                                "INV_EXPORT_XML",
                                format!("invalid definition attribute: {error}"),
                            )
                        })?;
                        if attribute.key.as_ref() == b"class" {
                            parsed.definition_class =
                                String::from_utf8_lossy(attribute.value.as_ref()).into_owned();
                        }
                    }
                }
                if path.last().is_some_and(|parent| parent == "triggers") {
                    parsed.triggers.insert(name.clone());
                }
                path.push(name);
            }
            Ok(Event::Empty(empty)) => {
                let name = String::from_utf8_lossy(empty.name().as_ref()).into_owned();
                if path.last().is_some_and(|parent| parent == "triggers") {
                    parsed.triggers.insert(name);
                }
            }
            Ok(Event::Text(text)) => {
                let decoded = text.decode().map_err(|error| {
                    InventoryError::new("INV_EXPORT_XML", format!("invalid XML text: {error}"))
                })?;
                let value = quick_xml::escape::unescape(&decoded)
                    .map_err(|error| {
                        InventoryError::new(
                            "INV_EXPORT_XML",
                            format!("invalid XML escape: {error}"),
                        )
                    })?
                    .into_owned();
                assign_job_text(&mut parsed, &path, &value);
            }
            Ok(Event::CData(text)) => {
                let value = text.decode().map_err(|error| {
                    InventoryError::new("INV_EXPORT_XML", format!("invalid CDATA: {error}"))
                })?;
                assign_job_text(&mut parsed, &path, &value);
            }
            Ok(Event::GeneralRef(reference)) => {
                let value = decode_general_reference(&reference)?;
                assign_job_text(&mut parsed, &path, &value);
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(InventoryError::new(
                    "INV_EXPORT_XML",
                    format!("cannot parse Jenkins job configuration: {error}"),
                ));
            }
        }
    }
    Ok(parsed)
}

fn assign_job_text(parsed: &mut JobXml, path: &[String], value: &str) {
    let Some(name) = path.last().map(String::as_str) else {
        return;
    };
    match name {
        "description" if path.len() == 2 => parsed.description.push_str(value),
        "script" if path.iter().any(|part| part == "definition") => parsed.script.push_str(value),
        "disabled" if path.len() == 2 => parsed.disabled = value.trim() == "true",
        _ => {}
    }
}

#[derive(Default)]
struct SelectedXml {
    security_realm: Option<String>,
    authorization_strategy: Option<String>,
    deny_anonymous_read: bool,
    user_id: Option<String>,
    full_name: Option<String>,
}

fn parse_selected_xml(bytes: &[u8]) -> Result<SelectedXml, InventoryError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut parsed = SelectedXml::default();
    let mut path = Vec::<String>::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                if matches!(name.as_str(), "securityRealm" | "authorizationStrategy") {
                    for attribute in start.attributes().with_checks(true) {
                        let attribute = attribute.map_err(|error| {
                            InventoryError::new(
                                "INV_EXPORT_XML",
                                format!("invalid global attribute: {error}"),
                            )
                        })?;
                        if attribute.key.as_ref() == b"class" {
                            let value =
                                String::from_utf8_lossy(attribute.value.as_ref()).into_owned();
                            if name == "securityRealm" {
                                parsed.security_realm = Some(value);
                            } else {
                                parsed.authorization_strategy = Some(value);
                            }
                        }
                    }
                }
                path.push(name);
            }
            Ok(Event::Text(text)) => {
                let decoded = text.decode().map_err(|error| {
                    InventoryError::new("INV_EXPORT_XML", format!("invalid XML text: {error}"))
                })?;
                let value = quick_xml::escape::unescape(&decoded)
                    .map_err(|error| {
                        InventoryError::new(
                            "INV_EXPORT_XML",
                            format!("invalid XML escape: {error}"),
                        )
                    })?
                    .into_owned();
                match path.last().map(String::as_str) {
                    Some("denyAnonymousReadAccess") => {
                        parsed.deny_anonymous_read = value.trim() == "true";
                    }
                    Some("id") if path.len() == 2 => parsed.user_id = Some(value),
                    Some("fullName") if path.len() == 2 => parsed.full_name = Some(value),
                    _ => {}
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let value = decode_general_reference(&reference)?;
                match path.last().map(String::as_str) {
                    Some("denyAnonymousReadAccess") => {
                        parsed.deny_anonymous_read = value.trim() == "true";
                    }
                    Some("id") if path.len() == 2 => parsed.user_id = Some(value),
                    Some("fullName") if path.len() == 2 => parsed.full_name = Some(value),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(InventoryError::new(
                    "INV_EXPORT_XML",
                    format!("cannot parse Jenkins configuration: {error}"),
                ));
            }
        }
    }
    Ok(parsed)
}

fn decode_general_reference(reference: &BytesRef<'_>) -> Result<String, InventoryError> {
    let decoded = reference.decode().map_err(|error| {
        InventoryError::new(
            "INV_EXPORT_XML",
            format!("invalid XML general reference: {error}"),
        )
    })?;
    let escaped = format!("&{decoded};");
    quick_xml::escape::unescape(&escaped)
        .map(|value| value.into_owned())
        .map_err(|error| {
            InventoryError::new(
                "INV_EXPORT_XML",
                format!("invalid XML general reference: {error}"),
            )
        })
}

fn read_directories(root: &Path) -> Result<Vec<PathBuf>, InventoryError> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(root).map_err(export_io(root))? {
        let entry = entry.map_err(|error| {
            InventoryError::new(
                "INV_EXPORT_IO",
                format!("cannot inspect {}: {error}", root.display()),
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(export_io(&path))?;
        if file_type.is_symlink() {
            return Err(InventoryError::new(
                "INV_EXPORT_FILE_TYPE",
                format!("frozen snapshot contains symbolic link {}", path.display()),
            ));
        }
        if file_type.is_dir() {
            directories.push(path);
        }
    }
    Ok(directories)
}

fn utf8_filename(path: &Path) -> Result<String, InventoryError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            InventoryError::new(
                "INV_EXPORT_PATH",
                format!("{} has no UTF-8 filename", path.display()),
            )
        })
}

fn read_regular(path: &Path) -> Result<Vec<u8>, InventoryError> {
    let metadata = fs::symlink_metadata(path).map_err(export_io(path))?;
    if !metadata.file_type().is_file() {
        return Err(InventoryError::new(
            "INV_EXPORT_FILE_TYPE",
            format!("{} is not a regular file", path.display()),
        ));
    }
    fs::read(path).map_err(export_io(path))
}

fn hash_attestation(path: &Path) -> Result<String, InventoryError> {
    Ok(sha256_hex(&read_regular(path)?))
}

fn write_yaml_new(path: PathBuf, value: &impl serde::Serialize) -> Result<(), InventoryError> {
    let rendered = serde_saphyr::to_string(value).map_err(|error| {
        InventoryError::new(
            "INV_EXPORT_RENDER",
            format!("cannot render {}: {error}", path.display()),
        )
    })?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(export_io(&path))?;
    output
        .write_all(rendered.as_bytes())
        .map_err(export_io(&path))?;
    output.sync_all().map_err(export_io(&path))
}

fn export_io(path: &Path) -> impl FnOnce(std::io::Error) -> InventoryError + '_ {
    move |error| {
        InventoryError::new(
            "INV_EXPORT_IO",
            format!("cannot access {}: {error}", path.display()),
        )
    }
}

fn u64_len(value: usize) -> Result<u64, InventoryError> {
    u64::try_from(value).map_err(|_| InventoryError::new("INV_COUNT_OVERFLOW", "count exceeds u64"))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
