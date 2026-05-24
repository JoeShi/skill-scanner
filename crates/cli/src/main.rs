use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "skillchk")]
#[command(version = "0.2.0")]
#[command(about = "Scan agent skills for security risks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a skill package
    Scan { target: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { target } => {
            println!("Scanning {target}... (no rules registered yet)");
        }
    }

    Ok(())
}
