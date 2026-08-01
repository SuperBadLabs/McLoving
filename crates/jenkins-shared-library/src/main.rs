use std::env;
use std::path::Path;
use std::process::ExitCode;

use mcloving_jenkins_shared_library::{
    digest_ledger_file, digest_source, verify_bundle, verify_corpus, verify_sources,
};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        return usage();
    };
    let Some(bundle) = args.next() else {
        return usage();
    };
    let result = match command.to_str() {
        Some("digest-source") if args.next().is_none() => digest_source(Path::new(&bundle)).map(|receipt| {
            println!("tree-sha256={}", receipt.tree_sha256);
            for namespace in receipt.namespaces {
                println!(
                    "namespace={} present={} files={} bytes={} sha256={}",
                    namespace.name, namespace.present, namespace.files, namespace.bytes, namespace.sha256
                );
            }
        }),
        Some("digest") if args.next().is_none() => digest_ledger_file(Path::new(&bundle))
            .map(|(raw, semantic)| println!("ledger-sha256={raw} semantic-sha256={semantic}")),
        Some("verify") if args.next().is_none() => verify_bundle(Path::new(&bundle)).map(|receipt| {
            println!(
                "shared-library-ledger-ok observations={} live={} resolved={} executable={} ledger-sha256={} semantic-sha256={}",
                receipt.observations,
                receipt.live_observations,
                receipt.resolutions,
                receipt.executable,
                receipt.ledger_sha256,
                receipt.semantic_sha256
            );
        }),
        Some("verify-sources") => {
            let Some(sources) = args.next() else {
                return usage();
            };
            if args.next().is_some() {
                return usage();
            }
            verify_sources(Path::new(&bundle), Path::new(&sources)).map(|receipt| {
                println!(
                    "shared-library-sources-ok resolutions={} files={} bytes={}",
                    receipt.resolutions, receipt.files, receipt.bytes
                );
            })
        }
        Some("verify-corpus") => {
            let Some(corpus) = args.next() else {
                return usage();
            };
            if args.next().is_some() {
                return usage();
            }
            verify_corpus(Path::new(&bundle), Path::new(&corpus)).map(|receipt| {
                println!(
                    "shared-library-corpus-ok observations={} observed-files={} corpus-files=228",
                    receipt.observations, receipt.files
                );
            })
        }
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: mcloving-jenkins-shared-library digest LEDGER\n       mcloving-jenkins-shared-library digest-source SOURCE\n       mcloving-jenkins-shared-library verify BUNDLE\n       mcloving-jenkins-shared-library verify-corpus BUNDLE CORPUS\n       mcloving-jenkins-shared-library verify-sources BUNDLE SOURCES"
    );
    ExitCode::from(64)
}
