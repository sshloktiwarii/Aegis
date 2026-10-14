use aegis_sandbox::{CommandSanitizer, Isolator, McpServer, SandboxConfig, IsolationBackend};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "Deterministic middleware gateway & sandbox for safe autonomous agent execution", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a command string for dangerous primitives and injection vectors without executing
    Scan {
        #[arg(short, long)]
        command: String,
    },
    /// Execute a command within the deterministic sandbox boundary
    Exec {
        #[arg(short, long)]
        command: String,

        #[arg(short, long, default_value = ".")]
        workspace: PathBuf,

        #[arg(long, default_value_t = false)]
        docker: bool,
    },
    /// Start the Model Context Protocol (MCP) JSON-RPC stdio server
    Mcp {
        #[arg(short, long, default_value = ".")]
        workspace: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { command } => {
            let sanitizer = CommandSanitizer::new();
            match sanitizer.sanitize(&command) {
                Ok(report) => {
                    println!("VERDICT: ALLOWED");
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                Err(err) => {
                    eprintln!("VERDICT: REJECTED (SECURITY VIOLATION)");
                    eprintln!("Error: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Exec {
            command,
            workspace,
            docker,
        } => {
            let sanitizer = CommandSanitizer::new();
            sanitizer.sanitize(&command)?;

            let backend = if docker {
                IsolationBackend::Docker
            } else {
                IsolationBackend::ProcessSandbox
            };

            let mut config = SandboxConfig::default();
            config.workspace_dir = workspace;

            let isolator = Isolator::new(config, backend);
            let res = isolator.execute(&command).await?;

            print!("{}", String::from_utf8_lossy(&res.stdout));
            eprint!("{}", String::from_utf8_lossy(&res.stderr));

            println!("\n--- Cryptographic Audit Receipt ---");
            println!("{}", serde_json::to_string_pretty(&res.receipt)?);

            std::process::exit(res.exit_code);
        }
        Commands::Mcp { workspace } => {
            let server = McpServer::new(workspace);
            server.run_stdio().await?;
        }
    }

    Ok(())
}
