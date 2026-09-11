//! Standalone, closed source launch prerequisite. No submitted-job capability
//! selects this protocol. Only the same sealed image can run within it.
//!
//! Linux PID-namespace init exit kills and reaps every namespace descendant,
//! including new process groups and nested PID namespaces. The outer process
//! waits for that exact child; persisted PIDs are never recovery authority.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Command, Stdio};

use mcloving_source_acquirer::runtime_custody::RuntimeCustody;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, SealFlag, fcntl};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::prctl::set_pdeathsig;
use nix::sys::signal::{SigEvent, SigevNotify, Signal};
use nix::sys::time::{TimeSpec, TimeValLike as _};
use nix::sys::timer::{Expiration, Timer, TimerSetTimeFlags};
use nix::time::ClockId;
use nix::unistd::{getegid, geteuid, getpid, getppid, pipe2};

const MODE: &str = "MCLOVING_SOURCE_CONTAINMENT";
const IMAGE: &str = "MCLOVING_SOURCE_CONTAINMENT_IMAGE_FD";
const PARENT: &str = "MCLOVING_SOURCE_CONTAINMENT_PARENT_PIDFD";
const READY: &str = "MCLOVING_SOURCE_CONTAINMENT_READY_FD";
const GATE: &str = "MCLOVING_SOURCE_CONTAINMENT_GATE_FD";
const DEADLINE: &str = "MCLOVING_SOURCE_CONTAINMENT_DEADLINE_MONOTONIC_NS";
const CUSTODY: &str = "MCLOVING_SOURCE_CONTAINMENT_RUNTIME_FD";
const MAX_LIFETIME_NS: i64 = 15 * 60 * 1_000_000_000;

// Authority paths are forwarded without being opened by either supervisor.
// Internal askpass/resolver/transport switches and arbitrary loader variables
// are intentionally absent. The trusted caller must also strip its launch env
// before the dynamic loader starts this outer image.
const SOURCE_ENVIRONMENT: &[&str] = &[
    "MCLOVING_SOURCE_ACQUIRER_CONFIG",
    "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256",
    "MCLOVING_SOURCE_ACQUIRER_CREDENTIAL_FILE",
    "MCLOVING_SOURCE_ACQUIRER_SIGNING_KEY_FILE",
    "MCLOVING_SOURCE_ACQUIRER_SECRET_MARKERS_FILE",
    "MCLOVING_SOURCE_ACQUIRER_TEST_MODE",
    "MCLOVING_SOURCE_ACQUIRER_TEST_READY_FILE",
];

fn required_fd(name: &str) -> Result<i32, ()> {
    let value = std::env::var(name).map_err(|_| ())?;
    let fd = value.parse::<i32>().map_err(|_| ())?;
    if fd < 3 || value != fd.to_string() {
        return Err(());
    }
    Ok(fd)
}

fn bounded_text(path: &str) -> Result<String, ()> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| ())?
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|_| ())?;
    if text.len() > 4096 {
        return Err(());
    }
    Ok(text)
}

fn profile() -> Result<(), ()> {
    mcloving_source_acquirer::runtime_custody::verify_source_profile().map_err(|_| ())
}

fn arm_deadline() -> Result<Timer, ()> {
    let deadline = std::env::var(DEADLINE)
        .map_err(|_| ())?
        .parse::<i64>()
        .map_err(|_| ())?;
    let clock = ClockId::CLOCK_MONOTONIC;
    let remaining = deadline
        .checked_sub(clock.now().map_err(|_| ())?.num_nanoseconds())
        .ok_or(())?;
    if !(1..=MAX_LIFETIME_NS).contains(&remaining) {
        return Err(());
    }
    let mut timer = Timer::new(
        clock,
        SigEvent::new(SigevNotify::SigevSignal {
            signal: Signal::SIGKILL,
            si_value: 0,
        }),
    )
    .map_err(|_| ())?;
    timer
        .set(
            Expiration::OneShot(TimeSpec::nanoseconds(deadline)),
            TimerSetTimeFlags::TFD_TIMER_ABSTIME,
        )
        .map_err(|_| ())?;
    Ok(timer)
}

fn verify_parent(fd: i32) -> Result<(), ()> {
    mcloving_source_acquirer::runtime_custody::verify_source_parent(fd).map_err(|_| ())
}

fn image() -> Result<File, ()> {
    let raw = required_fd(IMAGE)?;
    let file = File::open(format!("/proc/self/fd/{raw}")).map_err(|_| ())?;
    let actual = file.metadata().map_err(|_| ())?;
    let running = std::fs::metadata("/proc/self/exe").map_err(|_| ())?;
    let seals = SealFlag::F_SEAL_WRITE
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_SEAL;
    if !actual.is_file()
        || actual.len() == 0
        || actual.len() > 512 * 1024 * 1024
        || actual.dev() != running.dev()
        || actual.ino() != running.ino()
        || fcntl(&file, FcntlArg::F_GET_SEALS).map_err(|_| ())? & seals.bits() != seals.bits()
    {
        return Err(());
    }
    inheritable(&file)?;
    Ok(file)
}

fn inheritable(file: &File) -> Result<(), ()> {
    fcntl(file, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_| ())?;
    Ok(())
}

fn close_other_fds(allowed: &[i32]) -> Result<(), ()> {
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| ())?
        .map(|entry| {
            entry
                .map_err(|_| ())?
                .file_name()
                .to_str()
                .ok_or(())?
                .parse::<i32>()
                .map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for fd in descriptors {
        if fd >= 3 && !allowed.contains(&fd) {
            // The read_dir descriptor has already closed. EBADF is expected
            // for that one entry; there are no concurrent threads opening FDs.
            match nix::unistd::close(fd) {
                Ok(()) | Err(nix::errno::Errno::EBADF) => {}
                Err(_) => return Err(()),
            }
        }
    }
    Ok(())
}

fn control(name: &str, write: bool) -> Result<File, ()> {
    let file = std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .open(format!("/proc/self/fd/{}", required_fd(name)?))
        .map_err(|_| ())?;
    if file.metadata().map_err(|_| ())?.mode() & nix::libc::S_IFMT != nix::libc::S_IFIFO {
        return Err(());
    }
    Ok(file)
}

fn distinct_control_pipes(ready: &File, gate: &File) -> Result<(), ()> {
    let ready = ready.metadata().map_err(|_| ())?;
    let gate = gate.metadata().map_err(|_| ())?;
    if (ready.dev(), ready.ino()) == (gate.dev(), gate.ino()) {
        return Err(());
    }
    Ok(())
}

fn phase(ready: &mut File, gate: &mut File, value: u8) -> Result<(), ()> {
    ready.write_all(&[value]).map_err(|_| ())?;
    let mut ack = [0];
    gate.read_exact(&mut ack).map_err(|_| ())?;
    if ack != [value] {
        return Err(());
    }
    Ok(())
}

fn source_command(
    image: &File,
    mode: &str,
    custody: &RuntimeCustody,
    parent: &File,
) -> Result<Command, ()> {
    let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("LD_BIND_NOW", "1")
        .env(MODE, mode)
        .env(IMAGE, image.as_raw_fd().to_string())
        .env(CUSTODY, custody.descriptor().to_string())
        .env(PARENT, parent.as_raw_fd().to_string())
        .env(DEADLINE, std::env::var(DEADLINE).map_err(|_| ())?)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for name in SOURCE_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    Ok(command)
}

pub(super) fn outer() -> Result<i32, ()> {
    if std::env::args_os().count() != 1 {
        return Err(());
    }
    let parent = required_fd(PARENT)?;
    let unique = [
        parent,
        required_fd(IMAGE)?,
        required_fd(READY)?,
        required_fd(GATE)?,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if unique.len() != 4 {
        return Err(());
    }
    verify_parent(parent)?;
    set_pdeathsig(Signal::SIGKILL).map_err(|_| ())?;
    verify_parent(parent)?;
    let _timer = arm_deadline()?;
    let image = image()?;
    let mut ready = control(READY, true)?;
    let mut gate = control(GATE, false)?;
    distinct_control_pipes(&ready, &gate)?;
    close_other_fds(&[
        parent,
        image.as_raw_fd(),
        ready.as_raw_fd(),
        gate.as_raw_fd(),
    ])?;
    // A profile-name lookup is not transition evidence. Select only this fixed
    // profile and check the actual label on this running source image.
    mcloving_source_acquirer::runtime_custody::select_source_profile().map_err(|_| ())?;
    phase(&mut ready, &mut gate, b'P')?;

    // Pin configuration before reading runtime authority; neither supervisor
    // opens credentials, signing keys or marker files.
    let config_path = std::env::var_os("MCLOVING_SOURCE_ACQUIRER_CONFIG").ok_or(())?;
    use std::os::unix::fs::OpenOptionsExt as _;
    let config_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(config_path)
        .map_err(|_| ())?;
    if !config_file.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    let mut config_bytes = Vec::new();
    config_file
        .take(256 * 1024 + 1)
        .read_to_end(&mut config_bytes)
        .map_err(|_| ())?;
    if config_bytes.len() > 256 * 1024 {
        return Err(());
    }
    let config: mcloving_source_acquirer::SourceConfig =
        mcloving_source_acquirer::parse_json_no_duplicates(&config_bytes).map_err(|_| ())?;
    let custody = RuntimeCustody::capture(&config).map_err(|_| ())?;

    let uid = geteuid().as_raw();
    let gid = getegid().as_raw();
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID).map_err(|_| ())?;
    // Credential/namespace transitions must not silently remove the death
    // link. Re-arm and check the held original parent identity before mapping.
    set_pdeathsig(Signal::SIGKILL).map_err(|_| ())?;
    verify_parent(parent)?;
    std::fs::write("/proc/self/setgroups", b"deny").map_err(|_| ())?;
    // The inner init must retain capabilities in this new user namespace
    // across exec to create its private mount namespace and proc mount. Map
    // namespace root only to the caller's host identity; no additional host
    // identity or UID/GID range is delegated. Caller-owned authority files
    // are correspondingly reported as owned by UID 0 within the namespace.
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).map_err(|_| ())?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).map_err(|_| ())?;
    set_pdeathsig(Signal::SIGKILL).map_err(|_| ())?;
    verify_parent(parent)?;
    profile()?;
    phase(&mut ready, &mut gate, b'N')?;

    let (init_ready_read, init_ready_write) = pipe2(OFlag::O_CLOEXEC).map_err(|_| ())?;
    let (init_gate_read, init_gate_write) = pipe2(OFlag::O_CLOEXEC).map_err(|_| ())?;
    let init_ready_write = File::from(init_ready_write);
    let init_gate_read = File::from(init_gate_read);
    inheritable(&init_ready_write)?;
    inheritable(&init_gate_read)?;
    let own_pidfd = File::from(
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(getpid().as_raw()).ok_or(())?,
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(|_| ())?,
    );
    inheritable(&own_pidfd)?;
    let mut child = source_command(&image, "init", &custody, &own_pidfd)?
        .env(READY, init_ready_write.as_raw_fd().to_string())
        .env(GATE, init_gate_read.as_raw_fd().to_string())
        .spawn()
        .map_err(|_| ())?;
    drop(init_ready_write);
    drop(init_gate_read);
    let result = (|| {
        let mut init_ready = File::from(init_ready_read);
        let mut marker = [0];
        init_ready.read_exact(&mut marker).map_err(|_| ())?;
        if marker != *b"R" {
            return Err(());
        }
        // Pin this exact namespace init before releasing the last gate. A
        // caller cancelling the outer process must additionally join the init
        // pidfd: observing outer death alone does not prove teardown finished.
        let init_pid = child.id();
        if init_pid <= 1 || init_pid > i32::MAX as u32 {
            return Err(());
        }
        ready.write_all(b"R").map_err(|_| ())?;
        ready.write_all(&init_pid.to_le_bytes()).map_err(|_| ())?;
        let mut ack = [0];
        gate.read_exact(&mut ack).map_err(|_| ())?;
        if ack != *b"R" {
            return Err(());
        }
        verify_parent(parent)?;
        File::from(init_gate_write)
            .write_all(b"R")
            .map_err(|_| ())?;
        Ok(())
    })();
    if result.is_err() {
        // This live Child owns the exact unreaped init identity; no persisted
        // PID is accepted. Init SIGKILL tears down the complete namespace.
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| ())?;
    result?;
    Ok(if status.success() { 0 } else { 1 })
}

pub(super) fn init() -> Result<i32, ()> {
    if getpid().as_raw() != 1 || std::env::args_os().count() != 1 {
        return Err(());
    }
    // The parent lives outside this PID namespace, so getppid() is 0. The
    // ready/gate protocol closes the pre-PDEATHSIG parent-exit race: no worker
    // starts unless a live outer parent releases the gate after this setup.
    set_pdeathsig(Signal::SIGKILL).map_err(|_| ())?;
    let _timer = arm_deadline()?;
    let mut ready = control(READY, true)?;
    let mut gate = control(GATE, false)?;
    distinct_control_pipes(&ready, &gate)?;
    profile()?;
    let custody = RuntimeCustody::receive().map_err(|_| ())?;
    let image = image()?;
    let mut allowed = custody.inherited_descriptors();
    allowed.extend([image.as_raw_fd(), ready.as_raw_fd(), gate.as_raw_fd()]);
    close_other_fds(&allowed)?;
    unshare(CloneFlags::CLONE_NEWNS).map_err(|_| ())?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|_| ())?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|_| ())?;
    profile()?;
    if bounded_text("/proc/self/stat")?.split_whitespace().next() != Some("1") {
        return Err(());
    }
    phase(&mut ready, &mut gate, b'R')?;
    drop(ready);
    drop(gate);
    let own_pidfd = File::from(
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(1).ok_or(())?,
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(|_| ())?,
    );
    inheritable(&own_pidfd)?;
    let status = source_command(&image, "worker", &custody, &own_pidfd)?
        .spawn()
        .map_err(|_| ())?
        .wait()
        .map_err(|_| ())?;
    // Returning makes main exit PID1. Linux kills/reaps all remaining namespace
    // processes before the outer wait completes, regardless of their PGIDs.
    Ok(if status.success() { 0 } else { 1 })
}

pub(super) fn verify_worker() -> Result<RuntimeCustody, ()> {
    if getpid().as_raw() <= 1 || getppid().as_raw() != 1 || std::env::args_os().count() != 1 {
        return Err(());
    }
    profile()?;
    let custody = RuntimeCustody::receive().map_err(|_| ())?;
    let image = image()?;
    let mut allowed = custody.inherited_descriptors();
    allowed.push(image.as_raw_fd());
    close_other_fds(&allowed)?;
    // Config pinning is mandatory on this closed path. Ordinary standalone
    // acquisition retains its existing optional guard for compatibility.
    let digest =
        std::env::var("MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256").map_err(|_| ())?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    Ok(custody)
}
