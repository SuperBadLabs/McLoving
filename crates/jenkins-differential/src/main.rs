use std::path::PathBuf;

use mcloving_jenkins_differential::verify_bundle;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let root = arguments.next().map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: mcloving-jenkins-differential BUNDLE");
        std::process::exit(2);
    });
    if arguments.next().is_some() {
        eprintln!("usage: mcloving-jenkins-differential BUNDLE");
        std::process::exit(2);
    }
    match verify_bundle(&root) {
        Ok(receipt) => {
            println!("schema={}", receipt.schema);
            println!("case={}", receipt.case);
            println!("files={}", receipt.files);
            println!("admitted_cases={}", receipt.admitted_cases);
            println!("certified_cases={}", receipt.certified_cases);
            println!("non_admitted_cases={}", receipt.non_admitted_cases);
            println!("trace_sha256={}", receipt.trace_sha256);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
