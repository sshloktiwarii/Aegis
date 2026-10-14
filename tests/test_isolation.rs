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
