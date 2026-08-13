use std::io::ErrorKind;
use std::net::TcpStream;
use std::process::ExitCode;

fn main() -> ExitCode {
    match TcpStream::connect("127.0.0.1:9") {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => ExitCode::SUCCESS,
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
