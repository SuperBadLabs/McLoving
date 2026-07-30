use anyhow::Result;
use clap::Parser;
use mcloving_cli::{Arguments, execute, render};

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let output = execute(&arguments).await?;
    print!("{}", render(arguments.output, output)?);
    Ok(())
}
