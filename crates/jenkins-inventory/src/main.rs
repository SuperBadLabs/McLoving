use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mcloving_jenkins_inventory::{
    LEDGER_FILE,
    export::{ExportOptions, export_snapshot},
    inventory_snapshot_sha256, load_bundle, reconcile, seal_manifest_directory,
    validate_ledger_output_path, write_ledger,
};

#[derive(Parser)]
#[command(
    name = "mcloving-inventory",
    about = "Seal and reconcile fail-closed Jenkins inventory manifests"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Export {
        #[arg(long)]
        snapshot_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        controller_id: String,
        #[arg(long)]
        controller_url: String,
        #[arg(long)]
        epoch_id: String,
        #[arg(long)]
        source_generation: String,
        #[arg(long)]
        collected_at: String,
        #[arg(long)]
        exporter_version: String,
        #[arg(long)]
        exporter_sha256: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        provenance: String,
    },
    Seal {
        #[arg(long)]
        root: PathBuf,
    },
    Fingerprint {
        #[arg(long)]
        root: PathBuf,
    },
    Reconcile {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        expected_snapshot_sha256: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        expected_snapshot_sha256: String,
    },
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Export {
            snapshot_root,
            output,
            controller_id,
            controller_url,
            epoch_id,
            source_generation,
            collected_at,
            exporter_version,
            exporter_sha256,
            owner,
            provenance,
        } => {
            export_snapshot(&ExportOptions {
                snapshot_root,
                output,
                controller_id,
                controller_url,
                epoch_id,
                source_generation,
                collected_at,
                exporter_id: "mcloving-inventory-export".to_owned(),
                exporter_version,
                exporter_sha256,
                owner,
                provenance,
            })
            .context("inventory export failed")?;
        }
        Command::Seal { root } => {
            seal_manifest_directory(&root).context("inventory sealing failed")?;
        }
        Command::Fingerprint { root } => {
            let bundle = load_bundle(&root).context("inventory verification failed")?;
            println!("{}", inventory_snapshot_sha256(&bundle));
        }
        Command::Reconcile {
            root,
            expected_snapshot_sha256,
            output,
        } => {
            let bundle = load_bundle(&root).context("inventory verification failed")?;
            let ledger = reconcile(&bundle, &expected_snapshot_sha256)
                .context("inventory reconciliation failed")?;
            let output = output.unwrap_or_else(|| root.join(LEDGER_FILE));
            validate_ledger_output_path(&root, &output)
                .context("eligibility ledger output validation failed")?;
            write_ledger(&output, &ledger).context("eligibility ledger publication failed")?;
            println!("{}", output.display());
        }
        Command::Verify {
            root,
            expected_snapshot_sha256,
        } => {
            let bundle = load_bundle(&root).context("inventory verification failed")?;
            let ledger = reconcile(&bundle, &expected_snapshot_sha256)
                .context("inventory reconciliation failed")?;
            println!(
                "inventory-ok controller={} epoch={} jobs={} dependencies={} state-records={}",
                ledger.binding.controller_id,
                ledger.binding.epoch_id,
                ledger.population.jobs_in_scope,
                ledger.population.runtime_dependencies,
                ledger.population.persistent_record_classes
            );
        }
    }
    Ok(())
}
