use std::path::PathBuf;

use mcloving_state_policy_differential::verify_bundle;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let root = arguments.next().map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: mcloving-state-policy-differential BUNDLE");
        std::process::exit(2);
    });
    if arguments.next().is_some() {
        eprintln!("usage: mcloving-state-policy-differential BUNDLE");
        std::process::exit(2);
    }

    match verify_bundle(&root) {
        Ok(receipt) => {
            println!("schema={}", receipt.schema);
            println!("case={}", receipt.case);
            println!("principals={}", receipt.principals);
            println!("decisions={}", receipt.decisions);
            println!("operational_cases={}", receipt.operational_cases);
            println!("adversarial_scenarios={}", receipt.adversarial_scenarios);
            println!("evidence_sha256={}", receipt.evidence_sha256);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
