use aegis_sandbox::{Isolator, SandboxConfig, IsolationBackend};
use tempfile::tempdir;

#[tokio::test]
async fn test_sandboxed_command_execution() {
    let tmp = tempdir().unwrap();
    let mut config = SandboxConfig::default();
    config.workspace_dir = tmp.path().to_path_buf();

    let isolator = Isolator::new(config, IsolationBackend::ProcessSandbox);
    let result = isolator.execute("echo 'aegis-verified'").await;

    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.exit_code, 0);

    let stdout_str = String::from_utf8_lossy(&res.stdout);
    assert!(stdout_str.contains("aegis-verified"));

    // Verify cryptographic audit receipt
    assert!(res.receipt.verify(&res.stdout, &res.stderr));
}

#[tokio::test]
async fn test_failing_command_receipt() {
    let tmp = tempdir().unwrap();
    let mut config = SandboxConfig::default();
    config.workspace_dir = tmp.path().to_path_buf();

    let isolator = Isolator::new(config, IsolationBackend::ProcessSandbox);
    let result = isolator.execute("exit 42").await;

    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.exit_code, 42);
    assert!(res.receipt.verify(&res.stdout, &res.stderr));
}

#[tokio::test]
async fn test_kernel_seatbelt_blocks_directory_escape() {
    if !Isolator::is_seatbelt_available() {
        return;
    }

    let tmp = tempdir().unwrap();
    let mut config = SandboxConfig::default();
    config.workspace_dir = tmp.path().to_path_buf();

    let isolator = Isolator::new(config, IsolationBackend::SeatbeltOrNamespaces);
    // Attempting to write to /etc/evil_test_file should be blocked by the kernel seatbelt
    let result = isolator.execute("touch /etc/evil_test_file").await;

    assert!(result.is_ok());
    let res = result.unwrap();
    // Non-zero exit code due to kernel EPERM / SIGABRT / Operation not permitted
    assert_ne!(res.exit_code, 0);
    let stderr_str = String::from_utf8_lossy(&res.stderr);
    // On modern macOS (Sonoma/Sequoia), kernel kills the sandbox-exec process immediately
    // with SIGABRT (exit code -6 or 134), while on older versions touch exits with stderr message.
    let is_kernel_aborted = res.exit_code == -6 || res.exit_code == 134 || res.exit_code == -1;
    let has_permission_error = stderr_str.contains("Operation not permitted") || stderr_str.contains("Permission denied");
    assert!(
        is_kernel_aborted || has_permission_error,
        "Expected kernel rejection or SIGABRT, got exit_code: {}, stderr: {}",
        res.exit_code,
        stderr_str
    );
}

#[tokio::test]
async fn test_linux_namespaces_driver() {
    if !Isolator::is_unshare_available() {
        return;
    }

    let tmp = tempdir().unwrap();
    let mut config = SandboxConfig::default();
    config.workspace_dir = tmp.path().to_path_buf();

    let isolator = Isolator::new(config, IsolationBackend::LinuxNamespaces);
    let result = isolator.execute("echo 'unshare-isolated'").await;

    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.exit_code, 0);
    let stdout_str = String::from_utf8_lossy(&res.stdout);
    assert!(stdout_str.contains("unshare-isolated"));
    assert_eq!(res.receipt.isolation_backend, "linux_namespaces");
    assert!(res.receipt.verify(&res.stdout, &res.stderr));
}

