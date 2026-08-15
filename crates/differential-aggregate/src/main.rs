use std::path::PathBuf;

use mcloving_differential_aggregate::verify_bundle;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let bundle = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage());
    let repository = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage());
    if arguments.next().is_some() {
        usage();
    }

    match verify_bundle(&bundle, &repository) {
        Ok(receipt) => {
            println!("schema={}", receipt.schema);
            println!("case={}", receipt.case);
            println!("aggregate_sha256={}", receipt.aggregate_sha256);
            println!("verified_inputs={}", receipt.verified_inputs);
            for metric in receipt.coverage {
                println!(
                    "coverage.{}={}/{} {}",
                    metric.name, metric.numerator, metric.denominator, metric.unit
                );
            }
            println!("production_authority={}", receipt.production_authority);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: mcloving-differential-aggregate BUNDLE REPOSITORY_ROOT");
    std::process::exit(2);
}
