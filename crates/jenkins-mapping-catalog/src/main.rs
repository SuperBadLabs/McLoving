use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use mcloving_jenkins_mapping_catalog::{validate_catalog_bytes, verify_bundle};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        usage();
        return ExitCode::from(64);
    };
    let Some(path) = args.next() else {
        usage();
        return ExitCode::from(64);
    };
    if args.next().is_some() {
        usage();
        return ExitCode::from(64);
    }

    let result = if command == "verify" {
        verify(Path::new(&path))
    } else if command == "digest" {
        digest(Path::new(&path))
    } else {
        usage();
        return ExitCode::from(64);
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn verify(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match verify_bundle(root) {
        Ok(receipt) => {
            println!(
                "mapping-catalog-ok schema={} catalog={} version={} mappings={} earned-cases={} catalog-sha256={} semantic-sha256={}",
                receipt.schema,
                receipt.catalog_id,
                receipt.catalog_version,
                receipt.mappings,
                receipt.earned_cases,
                receipt.catalog_sha256,
                receipt.semantic_sha256
            );
            Ok(())
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn digest(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let (catalog_sha256, semantic_sha256) = validate_catalog_bytes(&bytes)?;
    println!("catalog-sha256={catalog_sha256} semantic-sha256={semantic_sha256}");
    Ok(())
}

fn usage() {
    eprintln!(
        "usage: mcloving-jenkins-mapping-catalog verify BUNDLE_ROOT\n       mcloving-jenkins-mapping-catalog digest CATALOG"
    );
}
