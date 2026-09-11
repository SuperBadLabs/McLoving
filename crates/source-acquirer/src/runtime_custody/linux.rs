use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use nix::fcntl::{FcntlArg, FdFlag, SealFlag, fcntl};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{RuntimeBinding, SourceConfig, SourceError, parse_json_no_duplicates};

pub const CUSTODY_ENV: &str = "MCLOVING_SOURCE_CONTAINMENT_RUNTIME_FD";
const MODE_ENV: &str = "MCLOVING_SOURCE_CONTAINMENT";
const IMAGE_ENV: &str = "MCLOVING_SOURCE_CONTAINMENT_IMAGE_FD";
const PARENT_ENV: &str = "MCLOVING_SOURCE_CONTAINMENT_PARENT_PIDFD";
const CONFIG_ENV: &str = "MCLOVING_SOURCE_ACQUIRER_EXPECTED_CONFIG_SHA256";
const MAX_FILES: usize = 256;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST: u64 = 256 * 1024;

// Proc text is authority only when read from the kernel task directory with
// mount crossings refused. Procfs magic alone would accept bind-mounted fake
// uid maps or another task's files. The trusted launch bootstrap excludes
// active same-UID mount/ptrace/loader interference; static overlays fail here.
struct ProcRoot(File);
struct ProcTask(File);
impl ProcRoot {
    fn open() -> Result<Self, SourceError> {
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open("/proc")
            .map_err(|_| denied())?;
        if root.metadata().map_err(|_| denied())?.ino() != 1
            || rustix::fs::fstatfs(&root).map_err(|_| denied())?.f_type
                != rustix::fs::PROC_SUPER_MAGIC
        {
            return Err(denied());
        }
        Ok(Self(root))
    }
    fn task(&self, pid: i32) -> Result<ProcTask, SourceError> {
        if pid < 1 {
            return Err(denied());
        }
        let fd = rustix::fs::openat2(
            &self.0,
            pid.to_string(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve(),
        )
        .map_err(|_| denied())?;
        Ok(ProcTask(File::from(fd)))
    }
    fn current(&self) -> Result<(i32, ProcTask), SourceError> {
        let link = pin_link(&self.0, "self")?;
        let value = rustix::fs::readlinkat(&link, "", Vec::new()).map_err(|_| denied())?;
        let text = value.to_str().map_err(|_| denied())?;
        let pid: i32 = text.parse().map_err(|_| denied())?;
        if text != pid.to_string() {
            return Err(denied());
        }
        Ok((pid, self.task(pid)?))
    }
}
fn resolve() -> rustix::fs::ResolveFlags {
    rustix::fs::ResolveFlags::BENEATH
        | rustix::fs::ResolveFlags::NO_XDEV
        | rustix::fs::ResolveFlags::NO_SYMLINKS
}
fn pin_link(directory: &File, path: &str) -> Result<File, SourceError> {
    let fd = rustix::fs::openat2(
        directory,
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        resolve(),
    )
    .map_err(|_| denied())?;
    let file = File::from(fd);
    if !file
        .metadata()
        .map_err(|_| denied())?
        .file_type()
        .is_symlink()
    {
        return Err(denied());
    }
    Ok(file)
}
impl ProcTask {
    fn read(&self, path: &str, maximum: u64) -> Result<Vec<u8>, SourceError> {
        let fd = rustix::fs::openat2(
            &self.0,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve(),
        )
        .map_err(|_| denied())?;
        bounded(File::from(fd), maximum)
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), SourceError> {
        let fd = rustix::fs::openat2(
            &self.0,
            path,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            resolve(),
        )
        .map_err(|_| denied())?;
        File::from(fd).write_all(bytes).map_err(|_| denied())
    }
    fn link(&self, path: &str) -> Result<std::ffi::CString, SourceError> {
        let pinned = pin_link(&self.0, path)?;
        rustix::fs::readlinkat(&pinned, "", Vec::new()).map_err(|_| denied())
    }
    fn magic(&self, path: &str) -> Result<File, SourceError> {
        // Following a genuine proc magic link necessarily leaves the proc
        // mount, so NO_XDEV cannot accompany that final follow. Pin and check
        // the actual proc symlink on both sides; reject static bind overlays.
        let link = pin_link(&self.0, path)?;
        let file = File::from(
            rustix::fs::openat(
                &self.0,
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| denied())?,
        );
        let again = pin_link(&self.0, path)?;
        let a = link.metadata().map_err(|_| denied())?;
        let b = again.metadata().map_err(|_| denied())?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err(denied());
        }
        Ok(file)
    }
}

fn denied() -> SourceError {
    SourceError::InvalidConfig
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    protocol: String,
    config_sha256: String,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    binding: RuntimeBinding,
    fd: i32,
    metadata: Identity,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl Identity {
    fn read(file: &File) -> Result<Self, SourceError> {
        let metadata = file.metadata().map_err(|_| denied())?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BYTES {
            return Err(denied());
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            mtime: metadata.mtime(),
            mtime_ns: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_ns: metadata.ctime_nsec(),
        })
    }
}

/// A held runtime closure proven by the fixed source outer supervisor. Fields
/// are private and receiving one always verifies the live supervisor lineage.
pub struct RuntimeCustody {
    config_sha256: String,
    entries: Vec<(RuntimeBinding, File, Identity)>,
    manifest: File,
}

fn seals() -> SealFlag {
    SealFlag::F_SEAL_WRITE | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_SEAL
}

fn sealed(file: &File) -> Result<(), SourceError> {
    if fcntl(file, FcntlArg::F_GET_SEALS).map_err(|_| denied())? & seals().bits() != seals().bits()
    {
        return Err(denied());
    }
    Ok(())
}

fn inheritable(file: &File) -> Result<(), SourceError> {
    fcntl(file, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|_| denied())?;
    Ok(())
}

fn fd_env(name: &str) -> Result<i32, SourceError> {
    let text = std::env::var(name).map_err(|_| denied())?;
    let fd: i32 = text.parse().map_err(|_| denied())?;
    if fd < 3 || fd.to_string() != text {
        return Err(denied());
    }
    Ok(fd)
}

fn bounded(file: File, maximum: u64) -> Result<Vec<u8>, SourceError> {
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if bytes.len() as u64 > maximum {
        return Err(denied());
    }
    Ok(bytes)
}

fn open_fd(fd: i32) -> Result<File, SourceError> {
    if fd < 3 {
        return Err(denied());
    }
    ProcRoot::open()?.current()?.1.magic(&format!("fd/{fd}"))
}

fn verify_bytes(
    file: &File,
    binding: &RuntimeBinding,
    identity: &Identity,
) -> Result<(), SourceError> {
    let mut input = file.try_clone().map_err(|_| denied())?;
    use std::io::{Seek as _, SeekFrom};
    input.seek(SeekFrom::Start(0)).map_err(|_| denied())?;
    let mut input = input.take(identity.size + 1);
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer).map_err(|_| denied())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hasher.update(&buffer[..count]);
    }
    if size != identity.size
        || format!("{:x}", hasher.finalize()) != binding.sha256
        || Identity::read(file)? != *identity
    {
        return Err(denied());
    }
    Ok(())
}

fn parent_pid(pidfd: i32) -> Result<i32, SourceError> {
    let task = ProcRoot::open()?.current()?.1;
    if task.link(&format!("fd/{pidfd}"))?.as_bytes() != b"anon_inode:[pidfd]" {
        return Err(denied());
    }
    let bytes = task.read(&format!("fdinfo/{pidfd}"), 4096)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| denied())?;
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:\t"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(denied());
    }
    let pid = values[0].parse::<i32>().map_err(|_| denied())?;
    if pid < 1 {
        return Err(denied());
    }
    Ok(pid)
}

fn verify_lineage(manifest_fd: i32) -> Result<(), SourceError> {
    let mode = std::env::var(MODE_ENV).map_err(|_| denied())?;
    let expected_parent_mode = match mode.as_str() {
        "init" if nix::unistd::getpid().as_raw() == 1 => {
            b"MCLOVING_SOURCE_CONTAINMENT=outer".as_slice()
        }
        "worker" if nix::unistd::getppid().as_raw() == 1 => {
            b"MCLOVING_SOURCE_CONTAINMENT=init".as_slice()
        }
        _ => return Err(denied()),
    };
    let pidfd = fd_env(PARENT_ENV)?;
    let pid = parent_pid(pidfd)?;
    // Before init remounts proc, this reports its host parent even though
    // getppid() is zero across the new PID namespace boundary.
    let proc = ProcRoot::open()?;
    let current = proc.current()?.1;
    let status = current.read("status", 65536)?;
    let status = std::str::from_utf8(&status).map_err(|_| denied())?;
    let parents = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:\t"))
        .collect::<Vec<_>>();
    if parents.len() != 1 || parents[0].parse::<i32>().map_err(|_| denied())? != pid {
        return Err(denied());
    }
    let parent = proc.task(pid)?;
    let parent_image = parent.magic("exe")?;
    let running_image = current.magic("exe")?;
    let inherited_image = open_fd(fd_env(IMAGE_ENV)?)?;
    for image in [&parent_image, &running_image, &inherited_image] {
        sealed(image)?;
    }
    let expected = running_image.metadata().map_err(|_| denied())?;
    for image in [&parent_image, &inherited_image] {
        let actual = image.metadata().map_err(|_| denied())?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            return Err(denied());
        }
    }
    let environment = parent.read("environ", 65536)?;
    if environment.last() != Some(&0) {
        return Err(denied());
    }
    let mut names = BTreeSet::new();
    let mut parent_mode = None;
    for field in environment[..environment.len() - 1].split(|byte| *byte == 0) {
        let equal = field
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(denied)?;
        if equal == 0 || !names.insert(&field[..equal]) {
            return Err(denied());
        }
        if &field[..equal] == MODE_ENV.as_bytes() {
            parent_mode = Some(field);
        }
    }
    if parent_mode != Some(expected_parent_mode) {
        return Err(denied());
    }
    // The capsule itself must still be held at the same FD by that exact
    // producer parent, not merely supplied by a separate process.
    let parent_manifest = parent.magic(&format!("fd/{manifest_fd}"))?;
    let manifest = open_fd(manifest_fd)?;
    sealed(&parent_manifest)?;
    sealed(&manifest)?;
    let a = parent_manifest.metadata().map_err(|_| denied())?;
    let b = manifest.metadata().map_err(|_| denied())?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) || parent_pid(pidfd)? != pid {
        return Err(denied());
    }
    Ok(())
}

/// Select only the fixed source profile through a genuine, same-mount proc
/// attribute. A static bind overlay cannot impersonate transition success.
pub fn select_source_profile() -> Result<(), SourceError> {
    ProcRoot::open()?
        .current()?
        .1
        .write("attr/current", b"changeprofile mcloving-source-acquirer")?;
    verify_source_profile()
}

/// Verify the actual running source label without a pathname fallback.
pub fn verify_source_profile() -> Result<(), SourceError> {
    let bytes = ProcRoot::open()?.current()?.1.read("attr/current", 4096)?;
    if std::str::from_utf8(&bytes)
        .map_err(|_| denied())?
        .trim_end()
        != "mcloving-source-acquirer (unconfined)"
    {
        return Err(denied());
    }
    Ok(())
}

/// Check the exact inherited outer owner's live pidfd identity through guarded
/// kernel fdinfo. This is also rechecked after parent-death signal setup.
pub fn verify_source_parent(fd: i32) -> Result<(), SourceError> {
    let pid = parent_pid(fd)?;
    if pid <= 1 || nix::unistd::getppid().as_raw() != pid {
        return Err(denied());
    }
    Ok(())
}

impl RuntimeCustody {
    /// Capture only from the operator's full identity UID/GID context. This
    /// refuses unprivileged namespace-root impersonation; privileged host
    /// administrators remain outside the supported adversary boundary.
    pub fn capture(config: &SourceConfig) -> Result<Self, SourceError> {
        let proc = ProcRoot::open()?;
        let (pid, task) = proc.current()?;
        if pid != nix::unistd::getpid().as_raw() {
            return Err(denied());
        }
        for path in ["uid_map", "gid_map"] {
            let bytes = task.read(path, 4096)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| denied())?;
            if text.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"] {
                return Err(denied());
            }
        }
        if config.runtime_closure.is_empty() || config.runtime_closure.len() > MAX_FILES {
            return Err(denied());
        }
        let config_sha256 = config.canonical_digest()?;
        if std::env::var(CONFIG_ENV).map_err(|_| denied())? != config_sha256 {
            return Err(denied());
        }
        let mut entries = Vec::new();
        let mut total = 0u64;
        let mut objects = BTreeSet::new();
        for binding in &config.runtime_closure {
            if !binding.path.is_absolute()
                || binding.path.as_os_str().len() > 4096
                || std::fs::canonicalize(&binding.path).map_err(|_| denied())? != binding.path
            {
                return Err(denied());
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&binding.path)
                .map_err(|_| denied())?;
            let metadata = file.metadata().map_err(|_| denied())?;
            let identity = Identity::read(&file)?;
            total = total.checked_add(identity.size).ok_or_else(denied)?;
            if metadata.uid() != 0
                || identity.mode & 0o022 != 0
                || total > MAX_BYTES
                || !objects.insert((identity.dev, identity.ino))
            {
                return Err(denied());
            }
            verify_bytes(&file, binding, &identity)?;
            inheritable(&file)?;
            entries.push((binding.clone(), file, identity));
        }
        Self::build(config_sha256, entries)
    }

    /// Import only after proving the current init/worker's live, exact sealed
    /// producer lineage. No public constructor accepts a claimed root UID or
    /// an environment assertion that a check previously happened.
    pub fn receive() -> Result<Self, SourceError> {
        let manifest_fd = fd_env(CUSTODY_ENV)?;
        verify_lineage(manifest_fd)?;
        let manifest_file = open_fd(manifest_fd)?;
        sealed(&manifest_file)?;
        let manifest: Manifest = parse_json_no_duplicates(&bounded(manifest_file, MAX_MANIFEST)?)?;
        if manifest.protocol != "mcloving.source-runtime-custody/v1"
            || manifest.config_sha256 != std::env::var(CONFIG_ENV).map_err(|_| denied())?
            || manifest.entries.is_empty()
            || manifest.entries.len() > MAX_FILES
        {
            return Err(denied());
        }
        let mut total = 0u64;
        let mut fds = BTreeSet::new();
        let mut objects = BTreeSet::new();
        let mut entries = Vec::new();
        for entry in manifest.entries {
            let file = open_fd(entry.fd)?;
            let actual = Identity::read(&file)?;
            total = total.checked_add(actual.size).ok_or_else(denied)?;
            if entry.fd == manifest_fd
                || !fds.insert(entry.fd)
                || !objects.insert((actual.dev, actual.ino))
                || actual != entry.metadata
                || actual.mode & 0o022 != 0
                || total > MAX_BYTES
            {
                return Err(denied());
            }
            verify_bytes(&file, &entry.binding, &actual)?;
            inheritable(&file)?;
            entries.push((entry.binding, file, actual));
        }
        verify_lineage(manifest_fd)?;
        Self::build(manifest.config_sha256, entries)
    }

    fn build(
        config_sha256: String,
        entries: Vec<(RuntimeBinding, File, Identity)>,
    ) -> Result<Self, SourceError> {
        let manifest = Manifest {
            protocol: "mcloving.source-runtime-custody/v1".to_owned(),
            config_sha256: config_sha256.clone(),
            entries: entries
                .iter()
                .map(|(binding, file, metadata)| Entry {
                    binding: binding.clone(),
                    fd: file.as_raw_fd(),
                    metadata: metadata.clone(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|_| denied())?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(denied());
        }
        let fd = nix::sys::memfd::memfd_create(
            "mcloving-source-runtime-custody",
            nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
        )
        .map_err(|_| denied())?;
        let mut file = File::from(fd);
        file.write_all(&bytes).map_err(|_| denied())?;
        fcntl(&file, FcntlArg::F_ADD_SEALS(seals())).map_err(|_| denied())?;
        inheritable(&file)?;
        Ok(Self {
            config_sha256,
            entries,
            manifest: file,
        })
    }

    pub fn descriptor(&self) -> i32 {
        self.manifest.as_raw_fd()
    }
    pub fn inherited_descriptors(&self) -> Vec<i32> {
        std::iter::once(self.descriptor())
            .chain(self.entries.iter().map(|(_, file, _)| file.as_raw_fd()))
            .collect()
    }
    pub(crate) fn matches(&self, config: &SourceConfig) -> bool {
        config
            .canonical_digest()
            .is_ok_and(|value| value == self.config_sha256)
            && self
                .entries
                .iter()
                .map(|(binding, _, _)| binding)
                .eq(config.runtime_closure.iter())
    }
    pub(crate) fn file(&self, binding: &RuntimeBinding) -> Result<File, SourceError> {
        let (_, file, identity) = self
            .entries
            .iter()
            .find(|(candidate, _, _)| candidate == binding)
            .ok_or_else(denied)?;
        if Identity::read(file)? != *identity {
            return Err(denied());
        }
        file.try_clone().map_err(|_| denied())
    }
}
