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

        #[arg(long, default_value = "seatbelt")]
        backend: String,

        #[arg(long, default_value_t = false)]
        json: bool,
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
            backend,
            json,
        } => {
            let sanitizer = CommandSanitizer::new();
            let _ = sanitizer.sanitize(&command);

            let isolation_backend = if docker || backend == "docker" {
                IsolationBackend::Docker
            } else if backend == "process" {
                IsolationBackend::ProcessSandbox
            } else if backend == "bwrap" || backend == "bubblewrap" {
                IsolationBackend::Bubblewrap
            } else if backend == "linux-namespaces" || backend == "unshare" {
                IsolationBackend::LinuxNamespaces
            } else {
                IsolationBackend::SeatbeltOrNamespaces
            };

            let mut config = SandboxConfig::default();
            config.workspace_dir = workspace;

            let isolator = Isolator::new(config, isolation_backend);
            let res = isolator.execute(&command).await?;

            if json {
                let json_output = serde_json::json!({
                    "exit_code": res.exit_code,
                    "stdout": String::from_utf8_lossy(&res.stdout),
                    "stderr": String::from_utf8_lossy(&res.stderr),
                    "receipt": res.receipt,
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
                std::process::exit(res.exit_code);
            }

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
