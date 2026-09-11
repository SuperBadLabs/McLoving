//! Independent host-side observations for the fixed source-only launch path.
//! These fixtures are trusted test code, never submitted source-program authority.
use super::*;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::os::fd::{AsRawFd, OwnedFd};

const PREFIX: &str = "MCLOVING_SOURCE_CONTAINMENT";
const CLEANUP_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(super) enum Scenario {
    Complete,
    SamePipeControls,
    CompleteWithDescendant,
    Terminate,
    Kill,
    ParentDeath,
}

pub(super) struct Launch {
    pub child: Option<tokio::process::Child>,
    ready: tokio::fs::File,
    gate: Option<std::fs::File>,
    _parent_pidfd: OwnedFd,
    pub outer: Identity,
    pub init: Option<Identity>,
    init_verified: bool,
    parent_proxy: Option<Identity>,
    _setup_authority: Option<tempfile::TempDir>,
}

impl Launch {
    pub(super) fn spawn(mut command: tokio::process::Command, image: &std::fs::File) -> Self {
        let (ready_read, ready_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let (gate_read, gate_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let parent_pidfd = pidfd_open(rustix::process::getpid(), PidfdFlags::empty()).unwrap();
        for fd in [&ready_write, &gate_read, &parent_pidfd] {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )
            .unwrap();
        }
        command
            .env(PREFIX, "outer")
            .env(format!("{PREFIX}_IMAGE_FD"), image.as_raw_fd().to_string())
            .env(
                format!("{PREFIX}_PARENT_PIDFD"),
                parent_pidfd.as_raw_fd().to_string(),
            )
            .env(
                format!("{PREFIX}_READY_FD"),
                ready_write.as_raw_fd().to_string(),
            )
            .env(
                format!("{PREFIX}_GATE_FD"),
                gate_read.as_raw_fd().to_string(),
            )
            .env(
                format!("{PREFIX}_DEADLINE_MONOTONIC_NS"),
                monotonic_deadline_after(Duration::from_secs(120)).to_string(),
            );
        let child = command.spawn().expect("fixed source containment process");
        let outer = Identity::open(child.id().unwrap() as i32).expect("pin actual spawned outer");
        drop(ready_write);
        drop(gate_read);
        Self {
            child: Some(child),
            ready: tokio::fs::File::from_std(std::fs::File::from(ready_read)),
            gate: Some(std::fs::File::from(gate_write)),
            _parent_pidfd: parent_pidfd,
            outer,
            init: None,
            init_verified: false,
            parent_proxy: None,
            _setup_authority: None,
        }
    }

    pub(super) async fn phase(&mut self, expected: u8) {
        use tokio::io::AsyncReadExt as _;
        let mut byte = [0_u8];
        tokio::time::timeout(Duration::from_secs(10), self.ready.read_exact(&mut byte))
            .await
            .expect("bounded containment phase")
            .expect("containment ready frame");
        assert_eq!(byte, [expected], "exact containment phase");
        let facts = process_facts(self.outer.pid).expect("live outer process facts");
        assert_eq!(facts.profile, "mcloving-source-acquirer (unconfined)\n");
        if expected == b'R' {
            let mut bytes = [0_u8; 4];
            tokio::time::timeout(Duration::from_secs(5), self.ready.read_exact(&mut bytes))
                .await
                .unwrap()
                .expect("fixed init host PID frame");
            let pid = i32::try_from(u32::from_le_bytes(bytes)).unwrap();
            self.init = Some(Identity::open(pid).expect("pin init while its release gate is held"));
            let init = self.init.as_ref().unwrap();
            assert_eq!(
                init.facts.parent, self.outer.pid,
                "init belongs to exact owned outer"
            );
            assert_eq!(
                init.facts.profile,
                "mcloving-source-acquirer (unconfined)\n"
            );
            assert_eq!(init.facts.namespace_pids.last(), Some(&1));
            assert!(init.facts.namespace_pids.len() > self.outer.facts.namespace_pids.len());
            assert!(!init.exited());
            eprintln!(
                "source init identity pinned before R acknowledgement: outer_host_pid={}, outer_start_time={}, init_host_pid={}, init_start_time={}, namespace_pids={:?}",
                self.outer.pid,
                self.outer.facts.start_time,
                init.pid,
                init.facts.start_time,
                init.facts.namespace_pids
            );
            self.init_verified = true;
        }
    }

    pub(super) fn acknowledge(&mut self, phase: u8) {
        self.gate
            .as_mut()
            .unwrap()
            .write_all(&[phase])
            .expect("containment gate");
        self.gate.as_mut().unwrap().flush().unwrap();
    }

    pub(super) async fn identify_proxy(&mut self) {
        use tokio::io::AsyncReadExt as _;
        let mut bytes = [0_u8; 4];
        tokio::time::timeout(
            Duration::from_secs(5),
            self.child
                .as_mut()
                .unwrap()
                .stdout
                .as_mut()
                .unwrap()
                .read_exact(&mut bytes),
        )
        .await
        .unwrap()
        .expect("real fixture parent reports its exact source child");
        let outer = Identity::open(i32::try_from(u32::from_le_bytes(bytes)).unwrap()).unwrap();
        assert_eq!(outer.facts.parent, self.outer.pid);
        self.parent_proxy = Some(std::mem::replace(&mut self.outer, outer));
    }

    pub(super) fn kill_parent(&self) {
        self.parent_proxy
            .as_ref()
            .expect("actual fixture parent")
            .signal(rustix::process::Signal::KILL);
    }

    pub(super) async fn expect_unavailable(self) {
        self.expect_refusal(false).await;
    }

    async fn expect_capture_refusal(self) {
        self.expect_refusal(true).await;
    }

    async fn expect_refusal(mut self, require_profile: bool) {
        use tokio::io::AsyncReadExt as _;
        let mut marker = [0_u8];
        let first = tokio::time::timeout(Duration::from_secs(10), self.ready.read(&mut marker))
            .await
            .unwrap()
            .unwrap();
        if require_profile {
            assert_eq!(
                first, 1,
                "root-custody negative must reach actual profile selection"
            );
        }
        if first == 1 {
            assert_eq!(
                marker,
                [b'P'],
                "unsupported host may select profile, never authorize namespace worker"
            );
            self.acknowledge(b'P');
            let next = tokio::time::timeout(Duration::from_secs(10), self.ready.read(&mut marker))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                next, 0,
                "unsupported root/namespace authority must refuse before N"
            );
        }
        let output =
            tokio::time::timeout(CLEANUP_LIMIT, self.child.take().unwrap().wait_with_output())
                .await
                .unwrap()
                .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        prove_exited(std::slice::from_ref(&self.outer)).await;
        if require_profile {
            eprintln!(
                "source root-custody negative route: 1 actual post-profile/pre-N refusal, zero worker/native output"
            );
        } else {
            eprintln!(
                "source containment unavailable route: 1 actual fixed launcher refusal, zero worker/native output; this is not a positive acquisition"
            );
        }
    }

    pub(super) async fn admit(&mut self) {
        for phase in b"PNR" {
            self.phase(*phase).await;
            self.acknowledge(*phase);
        }
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        self.gate.take();
        let _ =
            rustix::process::pidfd_send_signal(&self.outer.pidfd, rustix::process::Signal::KILL);
        if let Some(parent) = &self.parent_proxy {
            let _ =
                rustix::process::pidfd_send_signal(&parent.pidfd, rustix::process::Signal::KILL);
        }
        if self.init_verified
            && let Some(init) = &self.init
        {
            let _ = rustix::process::pidfd_send_signal(&init.pidfd, rustix::process::Signal::KILL);
        }
        if let Some(init) = &self.init {
            let start = Instant::now();
            while (init.try_exited() != Some(true) || self.outer.try_exited() != Some(true))
                && start.elapsed() < CLEANUP_LIMIT
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = writeln!(
                std::io::stderr(),
                "fixture emergency cleanup: host_init_pid={}, start_time={}, verified_init={}, exact_init_exit_proven={}, exact_outer_exit_proven={}; explicit emergency signals are not containment-test success, transport state retained",
                init.pid,
                init.facts.start_time,
                self.init_verified,
                init.try_exited() == Some(true),
                self.outer.try_exited() == Some(true)
            );
        } else {
            let _ = writeln!(
                std::io::stderr(),
                "fixture emergency cleanup: init identity unavailable; no namespace-empty proof claimed"
            );
        }
        if let Some(authority) = self._setup_authority.take() {
            let retained = authority.keep();
            let _ = writeln!(
                std::io::stderr(),
                "failed synthetic setup authority retained at {}",
                retained.display()
            );
        }
    }
}

pub(super) fn host_requires_positive() -> bool {
    let full_maps = ["/proc/self/uid_map", "/proc/self/gid_map"]
        .iter()
        .all(|path| {
            std::fs::read_to_string(path).is_ok_and(|text| {
                text.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]
            })
        });
    let profile_available = std::process::Command::new("aa-exec")
        .args([
            "-p",
            "unconfined",
            "--",
            "aa-exec",
            "-p",
            "mcloving-source-acquirer",
            "--",
            "true",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    full_maps && profile_available
}

pub(super) fn command(
    image: &std::fs::File,
    config: &Path,
    credential: &Path,
    key: &Path,
    markers: &Path,
) -> tokio::process::Command {
    // Foundation runs the containing test executable under the source profile.
    // Reset this one child to ordinary unconfined before the fixed source entry;
    // otherwise inherited policy would hide a broken production transition.
    let mut c = native_command("aa-exec", config, credential, key, markers);
    c.args(["-p", "unconfined", "--"])
        .arg(format!("/proc/self/fd/{}", image.as_raw_fd()));
    c
}

pub(super) fn parent_command(
    config: &Path,
    credential: &Path,
    key: &Path,
    markers: &Path,
) -> tokio::process::Command {
    let mut command = native_command("python3", config, credential, key, markers);
    command.arg(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/source_lifetime_fixture/parent_proxy.py"),
    );
    command
}

#[derive(Debug)]
pub(super) struct ProcessFacts {
    pub name: String,
    pub parent: i32,
    pub group: i32,
    pub start_time: u64,
    pub namespace_pids: Vec<i32>,
    pub profile: String,
}

fn process_facts(pid: i32) -> Option<ProcessFacts> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (prefix, tail) = stat.rsplit_once(") ")?;
    let name = prefix.split_once('(')?.1.to_owned();
    let fields: Vec<_> = tail.split_whitespace().collect();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let namespace_pids = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    Some(ProcessFacts {
        name,
        parent: fields.get(1)?.parse().ok()?,
        group: fields.get(2)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
        namespace_pids,
        profile: std::fs::read_to_string(format!("/proc/{pid}/attr/current")).ok()?,
    })
}

#[derive(Debug)]
pub(super) struct Identity {
    pub pid: i32,
    pidfd: OwnedFd,
    pub facts: ProcessFacts,
}
impl Identity {
    fn open(pid: i32) -> Option<Self> {
        let before = process_facts(pid)?;
        let pidfd = pidfd_open(Pid::from_raw(pid)?, PidfdFlags::empty()).ok()?;
        let facts = process_facts(pid)?;
        if before.start_time != facts.start_time {
            return None;
        }
        Some(Self { pid, pidfd, facts })
    }
    fn try_exited(&self) -> Option<bool> {
        let mut fds = [rustix::event::PollFd::new(
            &self.pidfd,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .ok()?;
        Some(fds[0].revents().contains(rustix::event::PollFlags::IN))
    }
    pub(super) fn exited(&self) -> bool {
        self.try_exited().expect("poll exact owned pidfd")
    }
    pub(super) fn signal(&self, signal: rustix::process::Signal) {
        rustix::process::pidfd_send_signal(&self.pidfd, signal)
            .expect("signal pinned fixture child");
    }
}

pub(super) fn descendants(root: i32) -> Vec<Identity> {
    let mut processes = BTreeMap::new();
    let entries = std::fs::read_dir("/proc").unwrap();
    for (index, entry) in entries.enumerate() {
        assert!(index < 100_000, "bounded host process census");
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(facts) = process_facts(pid) {
            processes.insert(pid, facts);
        }
    }
    let mut selected = BTreeSet::from([root]);
    loop {
        let before = selected.len();
        for (pid, facts) in &processes {
            if selected.contains(&facts.parent) {
                selected.insert(*pid);
            }
        }
        if selected.len() == before {
            break;
        }
    }
    selected.remove(&root);
    selected
        .into_iter()
        .filter_map(|pid| {
            let snapshot = processes.get(&pid)?;
            let pinned = Identity::open(pid)?;
            (pinned.facts.start_time == snapshot.start_time
                && pinned.facts.parent == snapshot.parent
                && !pinned.exited())
            .then_some(pinned)
        })
        .collect()
}

pub(super) async fn prove_exited(identities: &[Identity]) {
    tokio::time::timeout(CLEANUP_LIMIT, async {
        while identities.iter().any(|id| !id.exited()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every pinned descendant must exit by the cleanup deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_authenticates_and_verifies_native_receipt() {
    super::run_sealed_native_source(Some(Scenario::Complete)).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_sigterm_stops_authenticated_native_descendants() {
    super::run_sealed_native_source(Some(Scenario::Terminate)).await;
}
#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_sigkill_stops_authenticated_native_descendants() {
    super::run_sealed_native_source(Some(Scenario::Kill)).await;
}

async fn setup_only(proxy: bool) -> Launch {
    setup_with_config(proxy, false, false, false).await
}

async fn setup_with_config(
    proxy: bool,
    owned_runtime: bool,
    remapped: bool,
    proc_overlay: bool,
) -> Launch {
    let image = sealed_image(Path::new(env!("CARGO_BIN_EXE_mcloving-source-acquirer")));
    let authority = tempfile::tempdir().unwrap();
    let repository = RepositoryFixture::new(authority.path(), "setup-only");
    // This creates only fixture-owned configuration/runtime identities. The
    // launched worker's credential/key/marker paths deliberately do not exist,
    // and none of these tests releases the R gate to authorize worker startup.
    let context = Context::new(&repository, Vec::new(), Vec::new(), false).await;
    let mut config = context.config.clone();
    if owned_runtime {
        let runtime_copy = authority.path().join("caller-owned-runtime.so");
        std::fs::copy(&config.runtime_closure[0].path, &runtime_copy).unwrap();
        std::fs::set_permissions(&runtime_copy, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            sha256_file(&runtime_copy).await.unwrap(),
            config.runtime_closure[0].sha256
        );
        config.runtime_closure[0].path = std::fs::canonicalize(&runtime_copy).unwrap();
        config.runtime_closure.sort();
        config.runtime_closure_sha256 = runtime_closure_digest(&config.runtime_closure).unwrap();
    }
    let config_path = authority.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let missing = authority.path().join("must-not-open-source-authority");
    let mut command = if remapped {
        let mut command = native_command("aa-exec", &config_path, &missing, &missing, &missing);
        if proc_overlay {
            command.env("MCLOVING_FIXTURE_PROC_MAP_OVERLAY", "1");
        }
        command
            .args([
                "-p",
                "mcloving-source-acquirer",
                "--",
                "unshare",
                "--user",
                "--map-root-user",
                "--mount",
                "--",
                "python3",
            ])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/source_lifetime_fixture/parent_proxy.py"),
            );
        if proc_overlay {
            command.env("MCLOVING_FIXTURE_PROC_MAP_OVERLAY", "1");
        }
        command
    } else if proxy {
        parent_command(&config_path, &missing, &missing, &missing)
    } else {
        command(&image, &config_path, &missing, &missing, &missing)
    };
    command.env(
        "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256",
        config.canonical_digest().unwrap(),
    );
    let mut launch = Launch::spawn(command, &image);
    launch._setup_authority = Some(authority);
    if proxy || remapped {
        launch.identify_proxy().await;
    }
    launch
}

#[derive(Clone, Copy, Debug)]
enum SetupAction {
    Terminate,
    Kill,
    CloseGate,
    ParentDeath,
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_setup_gates_close_on_signals_cancellation_and_parent_death() {
    if !host_requires_positive() {
        setup_only(false).await.expect_unavailable().await;
        return;
    }

    let mut cases = 0;
    let mut init_cases = 0;
    for target in b"PNR" {
        for action in [
            SetupAction::Terminate,
            SetupAction::Kill,
            SetupAction::CloseGate,
            SetupAction::ParentDeath,
        ] {
            let mut launch = setup_only(matches!(action, SetupAction::ParentDeath)).await;
            for stage in b"PNR" {
                launch.phase(*stage).await;
                if stage == target {
                    break;
                }
                launch.acknowledge(*stage);
            }
            let observed = descendants(launch.outer.pid);
            if *target == b'R' {
                assert!(launch.init.is_some());
                assert!(!observed.is_empty());
                init_cases += 1;
            } else {
                assert!(launch.init.is_none());
                assert!(
                    observed.is_empty(),
                    "no worker is authorized before init stage"
                );
            }
            match action {
                SetupAction::Terminate => launch.outer.signal(rustix::process::Signal::TERM),
                SetupAction::Kill => launch.outer.signal(rustix::process::Signal::KILL),
                SetupAction::CloseGate => {
                    launch.gate.take();
                }
                SetupAction::ParentDeath => launch
                    .parent_proxy
                    .as_ref()
                    .unwrap()
                    .signal(rustix::process::Signal::KILL),
            }
            let output = tokio::time::timeout(
                CLEANUP_LIMIT,
                launch.child.take().unwrap().wait_with_output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!output.status.success(), "{target} {action:?}");
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            prove_exited(std::slice::from_ref(&launch.outer)).await;
            if let Some(init) = &launch.init {
                prove_exited(std::slice::from_ref(init)).await;
            }
            prove_exited(&observed).await;
            cases += 1;
        }
    }
    assert_eq!(cases, 12);
    assert_eq!(init_cases, 4);
    eprintln!(
        "source containment setup: {cases} executed cases, {init_cases} pinned PID1 teardown cases; no worker release or source credential authority"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_parent_exit_before_first_handshake_is_bounded() {
    if !host_requires_positive() {
        setup_only(false).await.expect_unavailable().await;
        return;
    }

    for _ in 0..8 {
        let mut launch = setup_only(true).await;
        launch
            .parent_proxy
            .as_ref()
            .unwrap()
            .signal(rustix::process::Signal::KILL);
        let output = tokio::time::timeout(
            CLEANUP_LIMIT,
            launch.child.take().unwrap().wait_with_output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        prove_exited(std::slice::from_ref(&launch.outer)).await;
    }
    eprintln!(
        "source containment early parent death: 8 actual parent exits before any phase acknowledgement"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_containment_parent_death_stops_authenticated_native_descendants() {
    super::run_sealed_native_source(Some(Scenario::ParentDeath)).await;
}

#[test]
fn fixed_source_containment_rejects_unowned_or_reused_identity_and_launch_substitution() {
    let cases = [
        "unsealed-image",
        "different-sealed-inode",
        "wrong-live-parent",
        "dead-parent-pidfd",
        "aliased-control-fds",
        "ordinary-file-parent",
        "expired-deadline",
        "extra-argument",
    ];
    for case in cases {
        let output = std::process::Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/source_lifetime_fixture/invalid_binding.py"),
            )
            .arg(env!("CARGO_BIN_EXE_mcloving-source-acquirer"))
            .arg(case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_ne!(result["status"], 0, "{case}");
        assert_eq!(result["phase_bytes"], 0, "{case}");
        assert_eq!(result["stdout_bytes"], 0, "{case}");
        assert_eq!(result["stderr_bytes"], 0, "{case}");
    }
    eprintln!(
        "source containment caller identity: 8 executed refusal cases, no profile-ready frame or native response; dead pidfd refuses independently of numeric PID reuse"
    );
}

pub(super) fn retire_owned_fixture_transport(root: &Path, acquisition: Uuid, init: &Identity) {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    assert!(
        init.exited(),
        "fixture teardown requires exact namespace PID1 exit proof"
    );
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(root.join(".coordination-v1.lock"))
        .unwrap();
    let _lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .expect("fixture must own native transport exclusion before offline retirement");
    let prefix = format!(".transport-{acquisition}-");
    let mut owned = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name() == ".coordination-v1.lock" {
            continue;
        }
        let name = entry.file_name().into_string().unwrap();
        let suffix = name
            .strip_prefix(&prefix)
            .expect("never erase unrelated or unknown transport state");
        Uuid::parse_str(suffix).expect("native transport allocation suffix");
        let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        owned.push(entry.path());
    }
    assert_eq!(
        owned.len(),
        1,
        "this actual fetch owns exactly one synthetic allocation"
    );
    let before = content_sha256(&serde_json::to_vec(&inventory(root)).unwrap());
    for path in owned {
        std::fs::remove_dir_all(path).unwrap();
    }
    assert!(transport_root_is_clean(root));
    let after = content_sha256(&serde_json::to_vec(&inventory(root)).unwrap());
    eprintln!(
        "fixture-only offline transport retirement after pinned init exit: acquisition={acquisition}, allocations=1, before_inventory_sha256={before}, after_inventory_sha256={after}; no product replay/reclamation policy implied"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_root_custody_refuses_caller_owned_runtime_and_remapped_origin() {
    if !host_requires_positive() {
        setup_only(false).await.expect_unavailable().await;
        return;
    }
    let mut cases = 0;
    if nix::unistd::geteuid().as_raw() != 0 {
        let launch = setup_with_config(false, true, false, false).await;
        launch.expect_capture_refusal().await;
        cases += 1;
    } else {
        // A host administrator-owned copy really is root-owned. Exercise the
        // unchanged accepted setup instead of calling that an owner negative.
        let mut launch = setup_with_config(false, true, false, false).await;
        for phase in b"PNR" {
            launch.phase(*phase).await;
            if *phase != b'R' {
                launch.acknowledge(*phase);
            }
        }
        launch.outer.signal(rustix::process::Signal::KILL);
        let _ = launch
            .child
            .take()
            .unwrap()
            .wait_with_output()
            .await
            .unwrap();
        prove_exited(std::slice::from_ref(launch.init.as_ref().unwrap())).await;
        eprintln!(
            "root runtime ownership route: privileged host-root copy accepted as actual root authority; nonroot-owner refusal is owed by nonroot host lane"
        );
    }
    for owned_runtime in [false, true] {
        let launch = setup_with_config(true, owned_runtime, true, false).await;
        launch.expect_capture_refusal().await;
        cases += 1;
    }
    assert!(cases >= 2);
    eprintln!(
        "root runtime custody: {cases} actual pre-N refusals; remapped namespace-root never substitutes for original host root ownership"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_root_custody_refuses_static_proc_identity_map_overlays() {
    use tokio::io::AsyncReadExt as _;
    if !host_requires_positive() {
        setup_only(false).await.expect_unavailable().await;
        return;
    }
    let mut launch = setup_with_config(true, true, true, true).await;
    launch.phase(b'P').await;
    launch
        .parent_proxy
        .as_ref()
        .unwrap()
        .signal(rustix::process::Signal::USR1);
    let mut evidence = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let byte = launch
                .child
                .as_mut()
                .unwrap()
                .stdout
                .as_mut()
                .unwrap()
                .read_u8()
                .await
                .unwrap();
            if byte == b'\n' {
                break;
            }
            evidence.push(byte);
            assert!(evidence.len() < 2048);
        }
    })
    .await
    .unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(&evidence).unwrap();
    let overlays = evidence["proc_map_overlays"].as_array().unwrap();
    assert_eq!(overlays.len(), 2);
    for overlay in overlays {
        assert_eq!(
            overlay["status"], 0,
            "owned namespace overlay must actually be installed"
        );
        assert_eq!(
            overlay["value"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["0", "0", "4294967295"]
        );
    }
    launch.acknowledge(b'P');
    let mut byte = [0_u8];
    let next = tokio::time::timeout(Duration::from_secs(10), launch.ready.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        next, 0,
        "static fake full UID/GID maps must not authorize runtime custody"
    );
    let output = tokio::time::timeout(
        CLEANUP_LIMIT,
        launch.child.take().unwrap().wait_with_output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    prove_exited(std::slice::from_ref(&launch.outer)).await;
    eprintln!(
        "source root custody static overlay: 2 real UID/GID bind overlays installed only inside fixture-owned mount/user namespace; actual source refused before N/worker authority"
    );
}

pub(super) fn uses_deliberate_descendant(scenario: Scenario) -> bool {
    !matches!(scenario, Scenario::Complete | Scenario::SamePipeControls)
}

pub(super) fn wrap_git(actual_git: &Path, root: &Path, port: u16) -> PathBuf {
    let auth = format!(
        "Basic {}",
        STANDARD.encode(format!("git:{}", String::from_utf8_lossy(CREDENTIAL)))
    );
    let header = format!(
        "#define REAL_GIT {}\n#define HEARTBEAT_PORT {port}\n#define HEARTBEAT_AUTH {}\n",
        serde_json::to_string(path_text(actual_git)).unwrap(),
        serde_json::to_string(&auth).unwrap()
    );
    std::fs::write(root.join("git_descendant_config.h"), header).unwrap();
    let binary = root.join("fixture-pinned-git-with-descendant");
    let output = std::process::Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/source_lifetime_fixture/git_descendant.c"),
        )
        .arg("-I")
        .arg(root)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git wrapper compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o500)).unwrap();
    binary
}

pub(super) fn prove_deliberate_group(identities: &[Identity]) {
    let child = identities
        .iter()
        .find(|id| id.facts.name == "src-fixture-pg")
        .expect("actual fixture-created setsid descendant must be observed");
    let parent = identities
        .iter()
        .find(|id| id.pid == child.facts.parent)
        .expect("deliberate descendant's actual live Git parent is pinned");
    assert_ne!(
        child.facts.group, parent.facts.group,
        "setsid child is outside its native parent's PGID"
    );
    assert!(child.facts.namespace_pids.len() >= 3);
    assert!(
        child.exited() && parent.exited(),
        "live snapshot assertions are evaluated only after exact namespace teardown"
    );
    eprintln!(
        "deliberate source descendant: host_pid={}, host_pgid={}, parent_host_pid={}, parent_host_pgid={}, start_time={}",
        child.pid, child.facts.group, parent.pid, parent.facts.group, child.facts.start_time
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_normal_completion_tears_down_deliberate_separate_group() {
    super::run_sealed_native_source(Some(Scenario::CompleteWithDescendant)).await;
}

pub(super) fn assert_observed_descendants(identities: &[Identity], deliberate: bool) {
    assert!(
        !identities.is_empty(),
        "actual source descendant denominator"
    );
    if deliberate {
        prove_deliberate_group(identities);
    }
    let groups = identities
        .iter()
        .map(|id| id.facts.group)
        .collect::<BTreeSet<_>>();
    assert!(
        groups.len() > 1,
        "native source creates independent process groups"
    );
    assert!(
        identities
            .iter()
            .any(|id| id.facts.namespace_pids.len() >= 3),
        "actual nested native transport namespace"
    );
    for identity in identities {
        assert_eq!(
            identity.facts.profile,
            "mcloving-source-acquirer (unconfined)\n"
        );
    }
}

pub(super) struct RetainFailedFixture(Option<tempfile::TempDir>);
impl RetainFailedFixture {
    pub(super) fn new() -> Self {
        Self(Some(tempfile::tempdir().expect("standalone tempdir")))
    }
    pub(super) fn path(&self) -> &Path {
        self.0.as_ref().unwrap().path()
    }
}
impl Drop for RetainFailedFixture {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(temporary) = self.0.take()
        {
            let retained = temporary.keep();
            let _ = writeln!(
                std::io::stderr(),
                "failed synthetic source fixture retained at {}",
                retained.display()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_private_entries_reject_forged_parent_before_capsule_authority() {
    if !host_requires_positive() {
        setup_only(false).await.expect_unavailable().await;
        return;
    }
    for mode in ["init", "worker"] {
        for variant in [
            "sealed-capsule",
            "unsealed-capsule",
            "runtime-image-alias",
            "config-mismatch",
        ] {
            let output = std::process::Command::new("python3")
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/source_lifetime_fixture/forged_lineage.py"),
                )
                .arg(env!("CARGO_BIN_EXE_mcloving-source-acquirer"))
                .arg(mode)
                .arg(variant)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}/{variant}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_ne!(result["status"], 0, "{mode}/{variant}");
            for field in ["phase_bytes", "stdout_bytes", "stderr_bytes"] {
                assert_eq!(result[field], 0, "{mode}/{variant}/{field}");
            }
        }
    }
    eprintln!(
        "forged private entries: 8 actual init/worker namespace launches refused before parent lineage could authorize substituted/unsealed/aliased/config-mismatched capsule; downstream capsule parser coverage is not claimed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_source_distinct_control_fds_on_same_pipe_refuse_before_private_authority() {
    super::run_sealed_native_source(Some(Scenario::SamePipeControls)).await;
}
