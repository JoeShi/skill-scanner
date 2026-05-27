use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;

use skill_scanner_core::engine::create_default_engine;
use skill_scanner_core::marketplace::clawhub_adapter::ClawHubAdapter;
use skill_scanner_core::marketplace::local_adapter::LocalDirectoryAdapter;
use skill_scanner_core::marketplace::registry::create_default_registry;
use skill_scanner_core::marketplace::skills_sh_adapter::SkillsShAdapter;
use skill_scanner_core::marketplace::types::{FetchOptions, MarketplaceRegistry};
use skill_scanner_core::reporter::{create_reporter, ReporterFormat};
use skill_scanner_core::types::{RulesetTrustPolicy, Severity};

/// Exit codes
const EXIT_PASS: i32 = 0;
const EXIT_BLOCKED: i32 = 1;
const EXIT_ERROR: i32 = 2;

/// skillchk - Scan agent skills for security risks
#[derive(Parser, Debug)]
#[command(name = "skillchk", version, about = "Scan agent skills for security risks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a skill package (local path or marketplace URL)
    Scan {
        /// Skill path or marketplace URL to scan
        target: String,

        /// Fail threshold: P0 (default), P1, or none
        #[arg(long = "fail-on", default_value = "P0")]
        fail_on: FailLevel,

        /// Output format: terminal (default), json, markdown, sarif
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,

        /// Force refetch even if cached
        #[arg(long)]
        force: bool,

        /// Keep extracted files after scan
        #[arg(long = "keep-extracted")]
        keep_extracted: bool,

        /// Custom ruleset YAML path
        #[arg(long)]
        ruleset: Option<String>,

        /// Ruleset trust policy: signed, warn (default), allow
        #[arg(long = "ruleset-trust-policy", default_value = "warn")]
        ruleset_trust_policy: TrustPolicy,
    },

    /// List supported marketplaces
    ListMarketplaces,
}

#[derive(Debug, Clone, ValueEnum)]
enum FailLevel {
    #[value(name = "P0", alias = "p0")]
    P0,
    #[value(name = "P1", alias = "p1")]
    P1,
    #[value(name = "none")]
    None,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, ValueEnum)]
enum TrustPolicy {
    Signed,
    Warn,
    Allow,
}

impl From<&TrustPolicy> for RulesetTrustPolicy {
    fn from(p: &TrustPolicy) -> Self {
        match p {
            TrustPolicy::Signed => RulesetTrustPolicy::Signed,
            TrustPolicy::Warn => RulesetTrustPolicy::Warn,
            TrustPolicy::Allow => RulesetTrustPolicy::Allow,
        }
    }
}

impl From<&OutputFormat> for ReporterFormat {
    fn from(f: &OutputFormat) -> Self {
        match f {
            OutputFormat::Terminal => ReporterFormat::Terminal,
            OutputFormat::Json => ReporterFormat::Json,
            OutputFormat::Markdown => ReporterFormat::Markdown,
            OutputFormat::Sarif => ReporterFormat::Sarif,
        }
    }
}

fn create_registry_with_defaults() -> impl MarketplaceRegistry {
    let mut registry = create_default_registry();
    registry.register(Box::new(LocalDirectoryAdapter));
    registry.register(Box::new(SkillsShAdapter));
    registry.register(Box::new(ClawHubAdapter));
    registry
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            fail_on,
            format,
            force,
            keep_extracted: _keep_extracted,
            ruleset: _ruleset,
            ruleset_trust_policy: _ruleset_trust_policy,
        } => {
            run_scan(&target, &fail_on, &format, force);
        }
        Commands::ListMarketplaces => {
            run_list_marketplaces();
        }
    }
}

fn run_scan(target: &str, fail_on: &FailLevel, format: &OutputFormat, force: bool) {
    let registry = create_registry_with_defaults();

    let source = match registry.find_source(target) {
        Some(s) => s,
        None => {
            eprintln!(
                "{} Cannot recognize marketplace source for \"{}\"",
                "Error:".red().bold(),
                target
            );
            eprintln!("Supported: local directory, GitHub URLs (skills.sh), ClawHub URLs/slugs");
            process::exit(EXIT_ERROR);
        }
    };

    eprintln!("Fetching from {}...", source.name());

    let fetch_opts = FetchOptions {
        force,
        ..Default::default()
    };

    let skill = match source.fetch(target, &fetch_opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} Failed to fetch skill: {}", "Error:".red().bold(), e);
            process::exit(EXIT_ERROR);
        }
    };

    eprintln!("Scanning {}...", skill.skill_name);

    let engine = create_default_engine();
    let result = match engine.scan(&skill.path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Scan failed: {}", "Error:".red().bold(), e);
            process::exit(EXIT_ERROR);
        }
    };

    // Render report
    let reporter_format: ReporterFormat = format.into();
    let reporter = create_reporter(reporter_format);
    let output = reporter.render(&result);
    println!("{}", output);

    // Apply exit code based on --fail-on threshold
    let blocked = match fail_on {
        FailLevel::P0 => result
            .findings
            .iter()
            .any(|f| f.severity.rank() <= Severity::P0.rank()),
        FailLevel::P1 => result
            .findings
            .iter()
            .any(|f| f.severity.rank() <= Severity::P1.rank()),
        FailLevel::None => false,
    };

    if blocked {
        process::exit(EXIT_BLOCKED);
    }

    process::exit(EXIT_PASS);
}

fn run_list_marketplaces() {
    let registry = create_registry_with_defaults();
    println!("Supported marketplaces:");
    for name in registry.list_sources() {
        println!("  - {}", name);
    }
}
