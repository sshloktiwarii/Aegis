use crate::audit::AuditReceipt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Error, Debug)]
pub enum IsolationError {
    #[error("Execution timed out after {0} ms")]
    Timeout(u64),

    #[error("I/O error during sandboxed process dispatch: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Sandbox directory error: {0}")]
    DirectoryError(String),

    #[error("Container runtime failed: {0}")]
    ContainerFailure(String),
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub receipt: AuditReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationBackend {
    Docker,
    ProcessSandbox,
}

pub struct SandboxConfig {
    pub workspace_dir: PathBuf,
    pub timeout_duration: Duration,
    pub memory_limit_mb: u32,
    pub cpu_quota: f32,
    pub read_only_root: bool,
    pub allow_network: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            workspace_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            timeout_duration: Duration::from_secs(15),
            memory_limit_mb: 512,
            cpu_quota: 1.0,
            read_only_root: true,
            allow_network: false,
        }
    }
}

pub struct Isolator {
    config: SandboxConfig,
    preferred_backend: IsolationBackend,
}

impl Isolator {
    pub fn new(config: SandboxConfig, preferred_backend: IsolationBackend) -> Self {
        Self {
            config,
            preferred_backend,
        }
    }

    /// Check if Docker daemon is responsive locally
    pub async fn is_docker_available() -> bool {
        let output = Command::new("docker")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;

        match output {
            Ok(status) => status.status.success(),
            Err(_) => false,
        }
    }

    /// Execute command within the requested isolation boundary
    pub async fn execute(
        &self,
        command_str: &str,
    ) -> Result<ExecutionResult, IsolationError> {
        let start = Instant::now();

        let use_docker = self.preferred_backend == IsolationBackend::Docker && Self::is_docker_available().await;

        let (exit_code, stdout, stderr, backend_name) = if use_docker {
            self.execute_in_docker(command_str).await?
        } else {
            self.execute_in_process_sandbox(command_str).await?
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        let receipt = AuditReceipt::new(
            command_str,
            command_str,
            backend_name,
            exit_code,
            &stdout,
            &stderr,
            duration_ms,
        );

        Ok(ExecutionResult {
            exit_code,
            stdout,
            stderr,
            receipt,
        })
    }

    async fn execute_in_docker(
        &self,
        command_str: &str,
    ) -> Result<(i32, Vec<u8>, Vec<u8>, &'static str), IsolationError> {
        let abs_workspace = self
            .config
            .workspace_dir
            .canonicalize()
            .map_err(|e| IsolationError::DirectoryError(e.to_string()))?;

        let mount_flag = if self.config.read_only_root {
            format!("{}:/workspace:ro", abs_workspace.display())
        } else {
            format!("{}:/workspace:rw", abs_workspace.display())
        };

        let mem_arg = format!("{}m", self.config.memory_limit_mb);
        let cpus_arg = format!("{:.1}", self.config.cpu_quota);

        let mut cmd = Command::new("docker");
        cmd.arg("run")
            .arg("--rm")
            .arg("--network")
            .arg(if self.config.allow_network { "bridge" } else { "none" })
            .arg("--memory")
            .arg(mem_arg)
            .arg("--cpus")
            .arg(cpus_arg)
            .arg("--cap-drop")
            .arg("ALL")
            .arg("-v")
            .arg(mount_flag)
            .arg("-w")
            .arg("/workspace")
            .arg("alpine:latest")
            .arg("sh")
            .arg("-c")
            .arg(command_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let execution = timeout(self.config.timeout_duration, cmd.output()).await;

        match execution {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                Ok((exit_code, output.stdout, output.stderr, "docker_container"))
            }
            Ok(Err(e)) => Err(IsolationError::IoError(e)),
            Err(_) => Err(IsolationError::Timeout(self.config.timeout_duration.as_millis() as u64)),
        }
    }

    async fn execute_in_process_sandbox(
        &self,
        command_str: &str,
    ) -> Result<(i32, Vec<u8>, Vec<u8>, &'static str), IsolationError> {
        let target_dir = if self.config.workspace_dir.exists() {
            self.config.workspace_dir.clone()
        } else {
            Path::new(".").to_path_buf()
        };

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(command_str)
            .current_dir(target_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let execution = timeout(self.config.timeout_duration, cmd.output()).await;

        match execution {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                Ok((exit_code, output.stdout, output.stderr, "process_sandbox"))
            }
            Ok(Err(e)) => Err(IsolationError::IoError(e)),
            Err(_) => Err(IsolationError::Timeout(self.config.timeout_duration.as_millis() as u64)),
        }
    }
}
