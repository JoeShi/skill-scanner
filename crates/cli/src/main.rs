use clap::{Parser, Subcommand, ValueEnum};
use skill_scanner_cli::{render, scan, ColorChoice, OutputFormat, ScanArgs, ScanVerdict};
use skill_scanner_ruleset::{TrustPolicy, TrustedKey};
use std::path::PathBuf;
use std::process;

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
    /// Scan a skill package at the given path
    Scan {
        /// Path to the skill directory
        skill_path: PathBuf,
        /// Custom ruleset file(s) to load (repeatable)
        #[arg(long = "ruleset")]
        rulesets: Vec<PathBuf>,
        /// Trust policy for custom rulesets
        #[arg(long = "ruleset-trust-policy", default_value = "unverified")]
        trust_policy: TrustPolicyArg,
        /// Trusted Ed25519 public key (format: ID:HEX64, repeatable)
        #[arg(long = "ruleset-trust-key")]
        trust_keys: Vec<String>,
        /// Output format
        #[arg(long, default_value = "text")]
        format: FormatArg,
        /// Color output
        #[arg(long, default_value = "auto")]
        color: ColorArg,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Clone, ValueEnum)]
enum TrustPolicyArg {
    Unverified,
    RequireSignature,
}

#[derive(Clone, ValueEnum)]
enum FormatArg {
    Text,
    Json,
}

#[derive(Clone, ValueEnum)]
enum ColorArg {
    Always,
    Never,
    Auto,
}

fn parse_trust_key(s: &str) -> Result<TrustedKey, String> {
    let (id, hex_str) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid trust key (expected ID:HEX64): {}", s))?;
    if hex_str.len() != 64 {
        return Err(format!(
            "trust key hex must be 64 chars, got {}: {}",
            hex_str.len(),
            s
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex in trust key: {}", e))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(TrustedKey {
        identifier: id.to_string(),
        public_key: pk,
    })
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            skill_path,
            rulesets,
            trust_policy,
            trust_keys,
            format,
            color,
            verbose,
        } => {
            let trusted_keys: Vec<TrustedKey> = trust_keys
                .iter()
                .map(|s| {
                    parse_trust_key(s).unwrap_or_else(|e| {
                        eprintln!("error: {}", e);
                        process::exit(2);
                    })
                })
                .collect();

            let policy = match trust_policy {
                TrustPolicyArg::Unverified => TrustPolicy::Unverified,
                TrustPolicyArg::RequireSignature => TrustPolicy::RequireSignature { trusted_keys },
            };

            let out_format = match format {
                FormatArg::Text => OutputFormat::Text,
                FormatArg::Json => OutputFormat::Json,
            };
            let out_color = match color {
                ColorArg::Always => ColorChoice::Always,
                ColorArg::Never => ColorChoice::Never,
                ColorArg::Auto => ColorChoice::Auto,
            };

            let args = ScanArgs {
                skill_path,
                rulesets,
                trust_policy: policy,
                format: out_format.clone(),
                color: out_color.clone(),
                verbose,
            };

            match scan(args) {
                Ok(report) => {
                    let output = render(&report, out_format, out_color);
                    println!("{}", output);
                    if report.verdict == ScanVerdict::Fail {
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(2);
                }
            }
        }
    }
}
