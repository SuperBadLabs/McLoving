use std::env;
use std::path::Path;

use mcloving_canary_qualification::{
    MAX_SESSION_BYTES, parse_independent_pins, verify_session_bytes,
};
use mcloving_external_connector::read_private_bounded_regular_file;

const MAX_PINS_BYTES: usize = 4_096;

fn main() {
    if run().is_err() {
        // Private ceremony data can reach parser errors. Keep the process
        // boundary deliberately non-reflective.
        eprintln!("canary qualification failed: CANARY_QUALIFICATION_FAILED");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().collect::<Vec<_>>();
    let [_, command, session_path, pins_path] = arguments.as_slice() else {
        return Err("usage: mcloving-canary-qualification verify <session> <pins>".into());
    };
    if command != "verify" {
        return Err("unknown command".into());
    }
    let session = read_private_bounded_regular_file(Path::new(session_path), MAX_SESSION_BYTES)?;
    let pins = read_private_bounded_regular_file(Path::new(pins_path), MAX_PINS_BYTES)?;
    let pins = parse_independent_pins(&pins)?;
    let receipt = verify_session_bytes(&session, &pins)?;
    println!("schema={}", receipt.schema);
    println!(
        "verified_pre_action_gates={}",
        receipt.verified_pre_action_gates
    );
    println!(
        "verified_windows_interruption_proofs={}",
        receipt.verified_windows_interruption_proofs
    );
    println!(
        "verified_authoritative_outcomes={}",
        receipt.verified_authoritative_outcomes
    );
    println!(
        "verified_shadow_replays={}",
        receipt.verified_shadow_replays
    );
    println!(
        "verified_destination_observations={}",
        receipt.verified_destination_observations
    );
    println!(
        "verified_authority_ledgers={}",
        receipt.verified_authority_ledgers
    );
    println!("duplicate_effects={}", receipt.duplicate_effects);
    println!("canary_qualified={}", receipt.canary_qualified);
    println!(
        "authority_granted_by_verifier={}",
        receipt.authority_granted_by_verifier
    );
    Ok(())
}
