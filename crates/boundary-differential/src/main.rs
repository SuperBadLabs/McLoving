use std::path::PathBuf;

use mcloving_boundary_differential::verify_bundle;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let root = arguments.next().map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: mcloving-boundary-differential BUNDLE");
        std::process::exit(2);
    });
    if arguments.next().is_some() {
        eprintln!("usage: mcloving-boundary-differential BUNDLE");
        std::process::exit(2);
    }

    match verify_bundle(&root) {
        Ok(receipt) => {
            println!("schema={}", receipt.schema);
            println!("case={}", receipt.case);
            println!("boundaries={}", receipt.boundaries);
            println!("scenarios={}", receipt.scenarios);
            println!("joins={}", receipt.joins);
            println!(
                "production_boundary_mappings={}",
                receipt.production_boundary_mappings
            );
            println!("duplicate_effects={}", receipt.duplicate_effects);
            println!(
                "secret_marker_disclosures={}",
                receipt.secret_marker_disclosures
            );
            println!("evidence_sha256={}", receipt.evidence_sha256);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
