//! Agent-owned Podman command inputs shared by launch and recovery.
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CONTAINERS_CONFIGURATION: &[u8] =
    b"# McLoving agent-owned workload configuration.\n[containers]\n";
pub const STORAGE_CONFIGURATION: &[u8] =
    b"# Storage is selected by explicit command arguments.\n[storage]\n";
const PINNED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// This value is captured once and used for the journal, launch and teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanContext {
    pub graph_root: PathBuf,
    pub run_root: PathBuf,
    pub driver: String,
    pub storage_options: Vec<String>,
    pub config_path: PathBuf,
    /// Original HOME selects bootstrap storage only; commands use config parent.
    pub home: Option<OsString>,
    pub runtime_dir: Option<OsString>,
    pub user: Option<OsString>,
    pub temporary_dir: Option<OsString>,
}
impl PodmanContext {
    pub fn config_root(&self) -> PathBuf {
        self.config_path
            .parent()
            .expect("validated configuration path")
            .join(".config")
    }
    pub fn storage_config(&self) -> PathBuf {
        self.config_path
            .parent()
            .expect("validated configuration path")
            .join("storage.conf")
    }
    pub fn arguments(&self) -> Vec<OsString> {
        let mut args = vec![
            "--root".into(),
            self.graph_root.as_os_str().to_owned(),
            "--runroot".into(),
            self.run_root.as_os_str().to_owned(),
            "--storage-driver".into(),
            self.driver.clone().into(),
            "--transient-store=false".into(),
        ];
        // Explicit root/driver options cause Podman to ignore ambient storage options.
        if self.storage_options.is_empty() {
            args.push("--storage-opt=".into());
        }
        for option in &self.storage_options {
            args.push("--storage-opt".into());
            args.push(option.into());
        }
        args
    }
    pub fn environment(&self) -> Vec<(OsString, OsString)> {
        let mut env = vec![
            ("PATH".into(), PINNED_PATH.into()),
            ("LANG".into(), "C.UTF-8".into()),
            // Storage's ID-mapping reexec inherits environment rather than
            // the parent's Podman flags. Keep its driver selection pinned.
            ("STORAGE_DRIVER".into(), self.driver.clone().into()),
            // Rootless implicit mounts are selected from HOME/.config on
            // supported Podman versions, independently of CONTAINERS_CONF.
            (
                "HOME".into(),
                self.config_path
                    .parent()
                    .expect("validated configuration path")
                    .as_os_str()
                    .to_owned(),
            ),
            (
                "CONTAINERS_CONF".into(),
                self.config_path.as_os_str().to_owned(),
            ),
            (
                "XDG_CONFIG_HOME".into(),
                self.config_root().into_os_string(),
            ),
            (
                "CONTAINERS_STORAGE_CONF".into(),
                self.storage_config().into_os_string(),
            ),
        ];
        for (name, value) in [
            ("XDG_RUNTIME_DIR", &self.runtime_dir),
            ("USER", &self.user),
            ("TMPDIR", &self.temporary_dir),
        ] {
            if let Some(value) = value {
                env.push((name.into(), value.clone()));
            }
        }
        env
    }
    /// Hex preserves unset/empty, non-UTF-8 and delimiter-bearing values exactly.
    pub fn identity(&self, runtime: &Path) -> String {
        let hex = |v: &std::ffi::OsStr| {
            v.as_encoded_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let mut fields = vec![
            "v3".to_owned(),
            format!("runtime={}", hex(runtime.as_os_str())),
            format!("root={}", hex(self.graph_root.as_os_str())),
            format!("runroot={}", hex(self.run_root.as_os_str())),
            format!("driver={}", hex(std::ffi::OsStr::new(&self.driver))),
            format!("config={}", hex(self.config_path.as_os_str())),
            format!(
                "HOME={}",
                hex(self
                    .config_path
                    .parent()
                    .expect("validated configuration path")
                    .as_os_str())
            ),
            format!(
                "mounts={}",
                hex(self
                    .config_root()
                    .join("containers/mounts.conf")
                    .as_os_str())
            ),
        ];
        for option in &self.storage_options {
            fields.push(format!("opt={}", hex(std::ffi::OsStr::new(option))));
        }
        for (name, value) in [
            ("SOURCE_HOME", &self.home),
            ("XDG_RUNTIME_DIR", &self.runtime_dir),
            ("USER", &self.user),
            ("TMPDIR", &self.temporary_dir),
        ] {
            fields.push(format!(
                "{name}={}",
                value.as_deref().map_or_else(|| "unset".to_owned(), hex)
            ));
        }
        fields.join("|")
    }
    pub fn validate_configuration(&self) -> std::io::Result<()> {
        if !self.graph_root.is_absolute()
            || !self.run_root.is_absolute()
            || self.driver.is_empty()
            || self.driver.len() > 128
            || !self
                .driver
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || self.storage_options.len() > 32
            || self
                .storage_options
                .iter()
                .any(|v| v.len() > 4225 || v.contains(['\n', '\0']) || !v.contains('='))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid Podman store identity",
            ));
        }
        validate_configuration(&self.config_path)
    }
}

/// Verify the exact installed configuration, including its empty override mounts file.
/// No user-provided TOML can add client environment, volumes, modules or hooks.
#[cfg(unix)]
pub fn validate_configuration(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let refuse = || {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Podman configuration custody",
        )
    };
    if !path.is_absolute() || path.file_name() != Some(std::ffi::OsStr::new("containers.conf")) {
        return Err(refuse());
    }
    if std::fs::canonicalize(path)? != path {
        return Err(refuse());
    }
    let parent = path.parent().ok_or_else(refuse)?;
    for dir in parent.ancestors() {
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir()
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
            || (m.uid() != 0 && m.uid() != nix::unistd::geteuid().as_raw())
        {
            return Err(refuse());
        }
    }
    for (file, expected) in [
        (path.to_owned(), CONTAINERS_CONFIGURATION),
        (parent.join("storage.conf"), STORAGE_CONFIGURATION),
        (
            parent.join(".config/containers/mounts.conf"),
            b"".as_slice(),
        ),
    ] {
        for dir in file
            .parent()
            .ok_or_else(refuse)?
            .ancestors()
            .take_while(|dir| dir.starts_with(parent))
        {
            let m = std::fs::symlink_metadata(dir)?;
            if !m.is_dir() || m.uid() != nix::unistd::geteuid().as_raw() || m.mode() & 0o077 != 0 {
                return Err(refuse());
            }
        }
        let handle: File = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&file)?;
        let m = handle.metadata()?;
        if !m.is_file()
            || m.uid() != nix::unistd::geteuid().as_raw()
            || m.mode() & 0o7777 != 0o400
            || m.nlink() != 1
            || m.len() != expected.len() as u64
        {
            return Err(refuse());
        }
        let mut bytes = Vec::new();
        handle
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes != expected {
            return Err(refuse());
        }
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn validate_configuration(_: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Podman requires Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn configuration(root: &Path) -> PathBuf {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = root.join("podman");
        std::fs::create_dir_all(dir.join(".config/containers")).unwrap();
        for d in [&dir, &dir.join(".config"), &dir.join(".config/containers")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (p, bytes) in [
            (dir.join("containers.conf"), CONTAINERS_CONFIGURATION),
            (dir.join("storage.conf"), STORAGE_CONFIGURATION),
            (dir.join(".config/containers/mounts.conf"), b"".as_slice()),
        ] {
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        dir.join("containers.conf")
    }
    #[test]
    fn controlled_configuration_refuses_modes_links_and_nonempty_mounts() {
        let root = tempfile::tempdir().unwrap();
        let config = configuration(root.path());
        validate_configuration(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_configuration(&config).is_err());
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o400)).unwrap();
        let alias = root.path().join("alias");
        std::fs::hard_link(&config, &alias).unwrap();
        assert!(validate_configuration(&config).is_err());
        std::fs::remove_file(alias).unwrap();
        let mounts = config
            .parent()
            .unwrap()
            .join(".config/containers/mounts.conf");
        std::fs::remove_file(&mounts).unwrap();
        std::fs::write(&mounts, b"/host:/escaped\n").unwrap();
        std::fs::set_permissions(&mounts, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(validate_configuration(&config).is_err());
        std::fs::remove_file(&mounts).unwrap();
        std::os::unix::fs::symlink(&config, &mounts).unwrap();
        assert!(validate_configuration(&config).is_err());
    }
    #[test]
    fn command_and_journal_identity_bind_store_options_and_exact_bytes() {
        let root = tempfile::tempdir().unwrap();
        let context = PodmanContext {
            graph_root: "/private/graph".into(),
            run_root: "/private/run".into(),
            driver: "overlay".into(),
            storage_options: vec!["overlay.mount_program=/usr/bin/fuse-overlayfs".into()],
            config_path: configuration(root.path()),
            home: Some("/home/service".into()),
            runtime_dir: Some("/run/service".into()),
            user: None,
            temporary_dir: None,
        };
        let identity = context.identity(Path::new("/usr/bin/podman"));
        assert!(identity.starts_with("v3|runtime="));
        assert!(identity.contains("|root="));
        assert!(identity.contains("|opt="));
        let mut changed = context.clone();
        changed.graph_root = "/private/other".into();
        assert_ne!(identity, changed.identity(Path::new("/usr/bin/podman")));
        changed = context.clone();
        changed.storage_options.clear();
        assert_ne!(identity, changed.identity(Path::new("/usr/bin/podman")));
        changed = context.clone();
        changed.home = Some("".into());
        assert_ne!(identity, changed.identity(Path::new("/usr/bin/podman")));
        assert!(context.arguments().contains(&"--root".into()));
        assert!(context.arguments().contains(&"--storage-opt".into()));
        assert!(
            context
                .environment()
                .iter()
                .any(|(k, v)| k == "CONTAINERS_CONF" && v == context.config_path.as_os_str())
        );
    }
    #[test]
    fn journal_identity_distinguishes_non_utf8_unset_empty_and_delimiters() {
        use std::os::unix::ffi::OsStringExt;
        let mut context = PodmanContext {
            graph_root: "/graph".into(),
            run_root: "/run".into(),
            driver: "vfs".into(),
            storage_options: Vec::new(),
            config_path: "/private/containers.conf".into(),
            home: None,
            runtime_dir: None,
            user: None,
            temporary_dir: None,
        };
        let runtime = Path::new("/usr/bin/pod|man");
        type Input = fn(&mut PodmanContext) -> &mut Option<OsString>;
        let inputs: [(&str, Input); 4] = [
            ("SOURCE_HOME", |c| &mut c.home),
            ("XDG_RUNTIME_DIR", |c| &mut c.runtime_dir),
            ("USER", |c| &mut c.user),
            ("TMPDIR", |c| &mut c.temporary_dir),
        ];
        for (name, input) in inputs {
            *input(&mut context) = None;
            let unset = context.identity(runtime);
            assert!(unset.contains(&format!("|{name}=unset")));
            *input(&mut context) = Some(OsString::new());
            let empty = context.identity(runtime);
            assert_ne!(unset, empty, "{name} unset versus empty");
            *input(&mut context) = Some(OsString::from_vec(vec![0xff]));
            let non_utf8 = context.identity(runtime);
            *input(&mut context) = Some("\u{fffd}".into());
            assert_ne!(non_utf8, context.identity(runtime), "{name} exact bytes");
            *input(&mut context) = Some("a|USER=b".into());
            let delimiter = context.identity(runtime);
            assert!(delimiter.contains(&format!("|{name}=617c555345523d62")));
            *input(&mut context) = Some("a".into());
            assert_ne!(delimiter, context.identity(runtime), "{name} delimiter");
            *input(&mut context) = None;
        }
        assert_ne!(
            context.identity(runtime),
            context.identity(Path::new("/usr/bin/pod|man "))
        );
    }
}
