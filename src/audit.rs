use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cryptographically verifiable audit record of every tool/command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReceipt {
    pub execution_id: String,
    pub timestamp: DateTime<Utc>,
    pub raw_command: String,
    pub sanitized_command: String,
    pub isolation_backend: String,
    pub exit_code: i32,
    pub stdout_hash: String,
    pub stderr_hash: String,
    pub execution_receipt_hash: String,
    pub duration_ms: u64,
}

impl AuditReceipt {
    pub fn new(
        raw_command: &str,
        sanitized_command: &str,
        isolation_backend: &str,
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
        duration_ms: u64,
    ) -> Self {
        let execution_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let stdout_hash = blake3::hash(stdout).to_hex().to_string();
        let stderr_hash = blake3::hash(stderr).to_hex().to_string();

        let mut hasher = blake3::Hasher::new();
        hasher.update(execution_id.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(raw_command.as_bytes());
        hasher.update(sanitized_command.as_bytes());
        hasher.update(isolation_backend.as_bytes());
        hasher.update(&exit_code.to_le_bytes());
        hasher.update(stdout_hash.as_bytes());
        hasher.update(stderr_hash.as_bytes());
        hasher.update(&duration_ms.to_le_bytes());
        let execution_receipt_hash = hasher.finalize().to_hex().to_string();

        Self {
            execution_id,
            timestamp,
            raw_command: raw_command.to_string(),
            sanitized_command: sanitized_command.to_string(),
            isolation_backend: isolation_backend.to_string(),
            exit_code,
            stdout_hash,
            stderr_hash,
            execution_receipt_hash,
            duration_ms,
        }
    }

    pub fn verify(&self, stdout: &[u8], stderr: &[u8]) -> bool {
        let expected_stdout_hash = blake3::hash(stdout).to_hex().to_string();
        let expected_stderr_hash = blake3::hash(stderr).to_hex().to_string();

        if self.stdout_hash != expected_stdout_hash || self.stderr_hash != expected_stderr_hash {
            return false;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(self.execution_id.as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.raw_command.as_bytes());
        hasher.update(self.sanitized_command.as_bytes());
        hasher.update(self.isolation_backend.as_bytes());
        hasher.update(&self.exit_code.to_le_bytes());
        hasher.update(self.stdout_hash.as_bytes());
        hasher.update(self.stderr_hash.as_bytes());
        hasher.update(&self.duration_ms.to_le_bytes());

        hasher.finalize().to_hex().to_string() == self.execution_receipt_hash
    }
}
