use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mcloving_controller_api::Client;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "mcloving", version, about = "McLoving public API client")]
struct Arguments {
    #[arg(long, env = "MCLOVING_URL")]
    server: String,
    #[arg(long, env = "MCLOVING_API_TOKEN", hide_env_values = true)]
    token: String,
    #[arg(long, env = "MCLOVING_ORGANIZATION_ID")]
    organization: Uuid,
    #[arg(long, env = "MCLOVING_PROJECT_ID")]
    project: Option<Uuid>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Submit {
        pipeline: PathBuf,
        #[arg(long)]
        idempotency_key: String,
    },
    Status {
        build: Uuid,
    },
    Logs {
        build: Uuid,
    },
    Cancel {
        build: Uuid,
    },
    Explain {
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long, default_value = "trusted-linux")]
        trust_pool: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let client = Client::new(&arguments.server, &arguments.token);
    match arguments.command {
        Command::Submit {
            pipeline,
            idempotency_key,
        } => {
            let project = required_project(arguments.project)?;
            let source = tokio::fs::read_to_string(&pipeline)
                .await
                .with_context(|| format!("read {}", pipeline.display()))?;
            print_json(
                &client
                    .submit(arguments.organization, project, &idempotency_key, source)
                    .await?,
            )?;
        }
        Command::Status { build } => {
            print_json(
                &client
                    .status(
                        arguments.organization,
                        required_project(arguments.project)?,
                        build,
                    )
                    .await?,
            )?;
        }
        Command::Logs { build } => {
            print_json(
                &client
                    .logs(
                        arguments.organization,
                        required_project(arguments.project)?,
                        build,
                    )
                    .await?,
            )?;
        }
        Command::Cancel { build } => {
            print_json(
                &client
                    .cancel(
                        arguments.organization,
                        required_project(arguments.project)?,
                        build,
                    )
                    .await?,
            )?;
        }
        Command::Explain {
            capabilities,
            trust_pool,
        } => {
            print_json(
                &client
                    .explain_in_pool(arguments.organization, &capabilities, &trust_pool)
                    .await?,
            )?;
        }
    }
    Ok(())
}

fn required_project(project: Option<Uuid>) -> Result<Uuid> {
    project.context("--project or MCLOVING_PROJECT_ID is required for this command")
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
