use std::io::ErrorKind;
use std::net::TcpStream;
use std::process::ExitCode;

fn main() -> ExitCode {
    let label = match std::fs::read_to_string("/proc/self/attr/current") {
        Ok(label)
            if label.starts_with("mcloving-external-shadow-replay")
                && !label.contains("complain") =>
        {
            label
        }
        Ok(label) => {
            eprintln!("shadow network probe has unexpected AppArmor label: {label:?}");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("shadow network probe cannot read its AppArmor label: {error}");
            return ExitCode::from(2);
        }
    };
    match TcpStream::connect("127.0.0.1:9") {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            eprintln!("shadow network denied under AppArmor label {label:?}");
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
