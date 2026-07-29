use std::path::PathBuf;

use mcloving_agent::{AgentConfig, journal_health, probe_once, run_until_stopped};
#[cfg(windows)]
use mcloving_agent::{
    run_creation_boundary_service_smoke, run_execution_service_smoke, run_service_smoke,
};
use tokio_util::sync::CancellationToken;

fn main() {
    if let Err(error) = dispatch(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn dispatch(arguments: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let command = arguments
        .first()
        .map(String::as_str)
        .unwrap_or("foreground");
    match command {
        "foreground" => {
            let config = AgentConfig::from_environment()?;
            runtime()?.block_on(async {
                let stop = CancellationToken::new();
                let signal = stop.clone();
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        signal.cancel();
                    }
                });
                run_until_stopped(&config, stop).await
            })?;
        }
        "probe" => {
            let config = AgentConfig::from_environment()?;
            let receipt = runtime()?.block_on(probe_once(&config))?;
            println!(
                "session_epoch={} active_attempts={}",
                receipt.session_epoch, receipt.active_attempts
            );
        }
        "journal-check" => {
            let path = required_path(&arguments, 1, "JOURNAL")?;
            let (mode, integrity, active) = journal_health(&path)?;
            println!("journal_mode={mode} integrity={integrity} active_attempts={active}");
        }
        "service" => run_windows_service(ServiceMode::Production)?,
        "service-smoke" => {
            run_windows_service(ServiceMode::Smoke(required_path(&arguments, 1, "JOURNAL")?))?;
        }
        "service-execution-smoke" => {
            run_windows_service(ServiceMode::ExecutionSmoke {
                journal: required_path(&arguments, 1, "JOURNAL")?,
                workspace_root: required_path(&arguments, 2, "WORKSPACE_ROOT")?,
                marker_root: required_path(&arguments, 3, "MARKER_ROOT")?,
            })?;
        }
        "workload-tree-smoke" => {
            run_windows_workload_tree_smoke(&required_path(&arguments, 1, "MARKER_ROOT")?)?;
        }
        "workload-sleep-smoke" => run_windows_workload_sleep_smoke()?,
        "service-creation-boundary-smoke" => {
            let boundary = required_value(&arguments, 5, "BOUNDARY")?;
            let record_before_pause = match boundary.as_str() {
                "contained-before-record" => false,
                "recorded-before-resume" => true,
                _ => {
                    return Err(
                        "BOUNDARY must be contained-before-record or recorded-before-resume".into(),
                    );
                }
            };
            run_windows_service(ServiceMode::CreationBoundarySmoke {
                journal: required_path(&arguments, 1, "JOURNAL")?,
                workspace_root: required_path(&arguments, 2, "WORKSPACE_ROOT")?,
                script: required_path(&arguments, 3, "SCRIPT")?,
                marker: required_path(&arguments, 4, "MARKER")?,
                record_before_pause,
            })?;
        }
        _ => {
            return Err(
                "usage: mcloving-agent [foreground|probe|journal-check PATH|service|service-smoke PATH|service-execution-smoke JOURNAL WORKSPACE_ROOT MARKER_ROOT|service-creation-boundary-smoke JOURNAL WORKSPACE_ROOT SCRIPT MARKER BOUNDARY]"
                    .into(),
            );
        }
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn required_path(
    arguments: &[String],
    index: usize,
    label: &'static str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .get(index)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{label} path is required").into())
}

fn required_value(
    arguments: &[String],
    index: usize,
    label: &'static str,
) -> Result<String, Box<dyn std::error::Error>> {
    arguments
        .get(index)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("{label} is required").into())
}

enum ServiceMode {
    Production,
    Smoke(PathBuf),
    ExecutionSmoke {
        journal: PathBuf,
        workspace_root: PathBuf,
        marker_root: PathBuf,
    },
    CreationBoundarySmoke {
        journal: PathBuf,
        workspace_root: PathBuf,
        script: PathBuf,
        marker: PathBuf,
        record_before_pause: bool,
    },
}

#[cfg(windows)]
fn run_windows_service(mode: ServiceMode) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_services::{Command, Service};

    let config = match &mode {
        ServiceMode::Production => Some(AgentConfig::from_environment()?),
        ServiceMode::Smoke(_)
        | ServiceMode::ExecutionSmoke { .. }
        | ServiceMode::CreationBoundarySmoke { .. } => None,
    };
    let stop = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    Service::new()
        .can_stop()
        .run(move |_, command| match command {
            Command::Start if !started.swap(true, Ordering::SeqCst) => {
                let stop = stop.clone();
                let config = config.clone();
                let service_task = match &mode {
                    ServiceMode::Production => ServiceTask::Production,
                    ServiceMode::Smoke(path) => ServiceTask::Smoke(path.clone()),
                    ServiceMode::ExecutionSmoke {
                        journal,
                        workspace_root,
                        marker_root,
                    } => ServiceTask::ExecutionSmoke {
                        journal: journal.clone(),
                        workspace_root: workspace_root.clone(),
                        marker_root: marker_root.clone(),
                    },
                    ServiceMode::CreationBoundarySmoke {
                        journal,
                        workspace_root,
                        script,
                        marker,
                        record_before_pause,
                    } => ServiceTask::CreationBoundarySmoke {
                        journal: journal.clone(),
                        workspace_root: workspace_root.clone(),
                        script: script.clone(),
                        marker: marker.clone(),
                        record_before_pause: *record_before_pause,
                    },
                };
                std::thread::spawn(move || {
                    let result = runtime().and_then(|runtime| {
                        runtime
                            .block_on(async move {
                                match (config, service_task) {
                                    (Some(config), ServiceTask::Production) => {
                                        run_until_stopped(&config, stop).await
                                    }
                                    (None, ServiceTask::Smoke(path)) => {
                                        run_service_smoke(&path, stop).await
                                    }
                                    (
                                        None,
                                        ServiceTask::ExecutionSmoke {
                                            journal,
                                            workspace_root,
                                            marker_root,
                                        },
                                    ) => {
                                        run_execution_service_smoke(
                                            &journal,
                                            &workspace_root,
                                            &marker_root,
                                            stop,
                                        )
                                        .await
                                    }
                                    (
                                        None,
                                        ServiceTask::CreationBoundarySmoke {
                                            journal,
                                            workspace_root,
                                            script,
                                            marker,
                                            record_before_pause,
                                        },
                                    ) => {
                                        run_creation_boundary_service_smoke(
                                            &journal,
                                            &workspace_root,
                                            &script,
                                            &marker,
                                            record_before_pause,
                                            stop,
                                        )
                                        .await
                                    }
                                    _ => unreachable!("service mode is internally consistent"),
                                }
                            })
                            .map_err(std::io::Error::other)
                    });
                    if let Err(error) = result {
                        eprintln!("Windows service worker failed: {error}");
                        // The SCM must observe a failed service process rather
                        // than a dispatcher that remains alive without its
                        // production worker.
                        std::process::exit(1);
                    }
                });
            }
            Command::Stop => stop.cancel(),
            _ => {}
        })
        .map_err(std::io::Error::other)?;
    Ok(())
}

#[cfg(not(windows))]
fn run_windows_service(mode: ServiceMode) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        ServiceMode::Production => {}
        ServiceMode::Smoke(path) => {
            let _ = path;
        }
        ServiceMode::ExecutionSmoke {
            journal,
            workspace_root,
            marker_root,
        } => {
            let _ = (journal, workspace_root, marker_root);
        }
        ServiceMode::CreationBoundarySmoke {
            journal,
            workspace_root,
            script,
            marker,
            record_before_pause,
        } => {
            let _ = (journal, workspace_root, script, marker, record_before_pause);
        }
    }
    Err("Windows service mode is only available on Windows".into())
}

#[cfg(windows)]
enum ServiceTask {
    Production,
    Smoke(PathBuf),
    ExecutionSmoke {
        journal: PathBuf,
        workspace_root: PathBuf,
        marker_root: PathBuf,
    },
    CreationBoundarySmoke {
        journal: PathBuf,
        workspace_root: PathBuf,
        script: PathBuf,
        marker: PathBuf,
        record_before_pause: bool,
    },
}

#[cfg(windows)]
fn run_windows_workload_tree_smoke(
    marker_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    fn write_pid(path: &std::path::Path, process_id: u32) -> Result<(), std::io::Error> {
        let mut marker = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        writeln!(marker, "{process_id}")?;
        marker.sync_all()
    }

    write_pid(&marker_root.join("parent.pid"), std::process::id())?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg("workload-sleep-smoke")
        .spawn()?;
    write_pid(&marker_root.join("child.pid"), child.id())?;
    child.wait()?;
    Ok(())
}

#[cfg(not(windows))]
fn run_windows_workload_tree_smoke(
    _marker_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows workload-tree smoke is only available on Windows".into())
}

#[cfg(windows)]
fn run_windows_workload_sleep_smoke() -> Result<(), Box<dyn std::error::Error>> {
    std::thread::sleep(std::time::Duration::from_secs(300));
    Ok(())
}

#[cfg(not(windows))]
fn run_windows_workload_sleep_smoke() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows workload sleep smoke is only available on Windows".into())
}
