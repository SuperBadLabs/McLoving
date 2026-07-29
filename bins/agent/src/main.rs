use std::path::PathBuf;

use mcloving_agent::{AgentConfig, journal_health, probe_once, run_until_stopped};
#[cfg(windows)]
use mcloving_agent::{run_execution_service_smoke, run_service_smoke};
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
            let path = required_path(&arguments, 1)?;
            let (mode, integrity, active) = journal_health(&path)?;
            println!("journal_mode={mode} integrity={integrity} active_attempts={active}");
        }
        "service" => run_windows_service(ServiceMode::Production)?,
        "service-smoke" => {
            run_windows_service(ServiceMode::Smoke(required_path(&arguments, 1)?))?;
        }
        "service-execution-smoke" => {
            run_windows_service(ServiceMode::ExecutionSmoke {
                journal: required_path(&arguments, 1)?,
                workspace_root: required_path(&arguments, 2)?,
                script: required_path(&arguments, 3)?,
            })?;
        }
        _ => {
            return Err(
                "usage: mcloving-agent [foreground|probe|journal-check PATH|service|service-smoke PATH|service-execution-smoke JOURNAL WORKSPACE_ROOT SCRIPT]"
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
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .get(index)
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "journal path is required".into())
}

enum ServiceMode {
    Production,
    Smoke(PathBuf),
    ExecutionSmoke {
        journal: PathBuf,
        workspace_root: PathBuf,
        script: PathBuf,
    },
}

#[cfg(windows)]
fn run_windows_service(mode: ServiceMode) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_services::{Command, Service};

    let config = match &mode {
        ServiceMode::Production => Some(AgentConfig::from_environment()?),
        ServiceMode::Smoke(_) | ServiceMode::ExecutionSmoke { .. } => None,
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
                        script,
                    } => ServiceTask::ExecutionSmoke {
                        journal: journal.clone(),
                        workspace_root: workspace_root.clone(),
                        script: script.clone(),
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
                                            script,
                                        },
                                    ) => {
                                        run_execution_service_smoke(
                                            &journal,
                                            &workspace_root,
                                            &script,
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
            script,
        } => {
            let _ = (journal, workspace_root, script);
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
        script: PathBuf,
    },
}
