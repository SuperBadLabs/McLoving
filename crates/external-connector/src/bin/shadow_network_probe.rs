use std::io::ErrorKind;
use std::net::TcpStream;
use std::process::ExitCode;

use mcloving_external_connector::require_shadow_apparmor_enforcement;

fn main() -> ExitCode {
    if let Err(error) = require_shadow_apparmor_enforcement() {
        eprintln!("shadow network probe is not confined: {}", error.code());
        return ExitCode::from(2);
    }
    match TcpStream::connect("127.0.0.1:9") {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            eprintln!("shadow network denied under the enforcing AppArmor profile");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("shadow network was not policy-denied: {error}");
            ExitCode::from(2)
        }
        Ok(_) => {
            eprintln!("shadow network probe unexpectedly connected");
            ExitCode::from(2)
        }
    }
}
