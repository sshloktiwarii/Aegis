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
    SeatbeltOrNamespaces,
    LinuxNamespaces,
    ProcessSandbox,
}

pub struct SandboxConfig {
    pub workspace_dir: PathBuf,
    pub timeout_duration: Duration,
    pub memory_limit_mb: u32,
    pub cpu_quota: f32,
    pub allow_network: bool,
    pub enable_landlock: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            workspace_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            timeout_duration: Duration::from_secs(15),
            memory_limit_mb: 512,
            cpu_quota: 1.0,
            allow_network: false,
            enable_landlock: true,
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

    /// Check if Apple Seatbelt sandbox-exec is present on host
    pub fn is_seatbelt_available() -> bool {
        Path::new("/usr/bin/sandbox-exec").exists()
    }

    /// Check if Linux unshare binary is present on host for user/mount/net/pid namespaces
    pub fn is_unshare_available() -> bool {
        Path::new("/usr/bin/unshare").exists() || Path::new("/bin/unshare").exists()
    }

    /// Execute command within the requested kernel/container isolation boundary
    pub async fn execute(
        &self,
        command_str: &str,
    ) -> Result<ExecutionResult, IsolationError> {
        let start = Instant::now();

        let (exit_code, stdout, stderr, backend_name) = match self.preferred_backend {
            IsolationBackend::Docker => {
                if Self::is_docker_available().await {
                    self.execute_in_docker(command_str).await?
                } else if Self::is_seatbelt_available() {
                    self.execute_in_seatbelt(command_str).await?
                } else if Self::is_unshare_available() {
                    self.execute_in_unshare(command_str).await?
                } else {
                    self.execute_in_process_sandbox(command_str).await?
                }
            }
            IsolationBackend::SeatbeltOrNamespaces => {
                if Self::is_seatbelt_available() {
                    self.execute_in_seatbelt(command_str).await?
                } else if Self::is_unshare_available() {
                    self.execute_in_unshare(command_str).await?
                } else {
                    self.execute_in_process_sandbox(command_str).await?
                }
            }
            IsolationBackend::LinuxNamespaces => {
                if Self::is_unshare_available() {
                    self.execute_in_unshare(command_str).await?
                } else {
                    self.execute_in_process_sandbox(command_str).await?
                }
            }
            IsolationBackend::ProcessSandbox => {
                self.execute_in_process_sandbox(command_str).await?
            }
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

    /// Apple Seatbelt kernel boundary isolation profile (macOS)
    async fn execute_in_seatbelt(
        &self,
        command_str: &str,
    ) -> Result<(i32, Vec<u8>, Vec<u8>, &'static str), IsolationError> {
        let workspace = self
            .config
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| self.config.workspace_dir.clone());

        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/Users/nobody".to_string());

        // Generate dynamic Apple Seatbelt profile
        let profile = format!(
            r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/opt/homebrew"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/dev"))
(allow file-read* (subpath "{ws}"))
(allow file-write* (subpath "{ws}"))
(allow file* (subpath "/private/tmp"))
(allow file* (subpath "/tmp"))
(allow file* (subpath "/var/folders"))
(deny network*)
(deny file* (subpath "{home}/.ssh"))
(deny file* (subpath "{home}/.aws"))
(deny file* (subpath "{home}/.gnupg"))
(deny file* (subpath "{home}/.kube"))
"#,
            ws = workspace.display(),
            home = home_dir
        );

        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-p")
            .arg(profile)
            .arg("sh")
            .arg("-c")
            .arg(command_str)
            .current_dir(&workspace)
            .env_clear()
            .env("PATH", "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TMPDIR", "/private/tmp")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let execution = timeout(self.config.timeout_duration, cmd.output()).await;

        match execution {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                Ok((exit_code, output.stdout, output.stderr, "macos_seatbelt"))
            }
            Ok(Err(e)) => Err(IsolationError::IoError(e)),
            Err(_) => Err(IsolationError::Timeout(self.config.timeout_duration.as_millis() as u64)),
        }
    }

    /// Native Linux namespaces driver utilizing unshare (user, mount, pid, net)
    /// Enables non-Docker rootless isolation on bare-metal or cloud VMs
    async fn execute_in_unshare(
        &self,
        command_str: &str,
    ) -> Result<(i32, Vec<u8>, Vec<u8>, &'static str), IsolationError> {
        let workspace = self
            .config
            .workspace_dir
            .canonicalize()
            .unwrap_or_else(|_| self.config.workspace_dir.clone());

        let unshare_bin = if Path::new("/usr/bin/unshare").exists() {
            "/usr/bin/unshare"
        } else {
            "unshare"
        };

        let mut cmd = Command::new(unshare_bin);
        // -r: map current user to root in new user namespace (unprivileged)
        // -m: unshare mount namespace
        // -p: unshare pid namespace
        // -f: fork child so child becomes PID 1 in new namespace
        cmd.arg("-r")
            .arg("-m")
            .arg("-p")
            .arg("-f");

        if !self.config.allow_network {
            cmd.arg("-n"); // unshare network namespace
        }

        cmd.arg("--")
            .arg("sh")
            .arg("-c")
            .arg(command_str)
            .current_dir(&workspace)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TMPDIR", "/tmp")
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let execution = timeout(self.config.timeout_duration, cmd.output()).await;

        match execution {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                Ok((exit_code, output.stdout, output.stderr, "linux_namespaces"))
            }
            Ok(Err(e)) => Err(IsolationError::IoError(e)),
            Err(_) => Err(IsolationError::Timeout(self.config.timeout_duration.as_millis() as u64)),
        }
    }

    /// Production-grade ephemeral Docker containerization with writable scratch overlays
    async fn execute_in_docker(
        &self,
        command_str: &str,
    ) -> Result<(i32, Vec<u8>, Vec<u8>, &'static str), IsolationError> {
        let abs_workspace = self
            .config
            .workspace_dir
            .canonicalize()
            .map_err(|e| IsolationError::DirectoryError(e.to_string()))?;

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
            .arg("--security-opt=no-new-privileges")
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--tmpfs")
            .arg("/tmp:rw,noexec,nosuid,size=256m")
            .arg("--tmpfs")
            .arg("/run:rw,noexec")
            .arg("-v")
            .arg(format!("{}:/workspace:rw", abs_workspace.display()))
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
