use std::env;
use std::fs;

use mcloving_jenkins_compiler_admission::{
    ExpectedAdmission, ValidatedResponse, validate_response,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 6 {
        return Err(
            "usage: mcloving-jenkins-compiler-admission RESPONSE SOURCE REQUEST_ID JOB_ID JOB_GENERATION"
                .into(),
        );
    }
    let response = fs::read(&arguments[1])?;
    let source = fs::read(&arguments[2])?;
    let validated = validate_response(
        &response,
        ExpectedAdmission {
            request_id: &arguments[3],
            job_id: &arguments[4],
            job_generation: &arguments[5],
            source: &source,
        },
    )?;
    match validated {
        ValidatedResponse::Admitted(receipt) => {
            println!("status=admitted");
            println!("request_id={}", receipt.request_id);
            println!("job_id={}", receipt.job_id);
            println!("state={}", receipt.state);
            println!("source_sha256={}", receipt.source_sha256);
            println!("pipeline_yaml_sha256={}", receipt.pipeline_yaml_sha256);
            println!("jobstate_yaml_sha256={}", receipt.jobstate_yaml_sha256);
            println!("semantic_ir_sha256={}", receipt.semantic_ir_sha256);
            println!("canonical_ir_sha256={}", receipt.canonical_ir_sha256);
            println!("stages={}", receipt.stages);
            println!("steps={}", receipt.steps);
        }
        ValidatedResponse::Unsupported { code } => {
            println!("status=unsupported");
            println!("code={code}");
        }
        ValidatedResponse::Rejected { code } => {
            println!("status=rejected");
            println!("code={code}");
        }
    }
    Ok(())
}
