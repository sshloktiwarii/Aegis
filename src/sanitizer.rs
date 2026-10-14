use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SanitizationError {
    #[error("Destructive system command rejected: {0}")]
    DestructiveCommand(String),

    #[error("Unauthorized outbound network attempt rejected: {0}")]
    OutboundNetwork(String),

    #[error("Sensitive path or credential file traversal detected: {0}")]
    SensitivePathAccess(String),

    #[error("Denial of service / fork bomb primitive rejected: {0}")]
    ResourceExhaustion(String),

    #[error("Unauthorized privilege escalation attempt rejected: {0}")]
    PrivilegeEscalation(String),

    #[error("Obfuscated or dynamically evaluated execution payload rejected: {0}")]
    ObfuscatedExecution(String),

    #[error("Syntax parsing failure: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizationReport {
    pub allowed: bool,
    pub original_command: String,
    pub sanitized_tokens: Vec<String>,
    pub security_violations: Vec<String>,
}

pub struct CommandSanitizer {
    destructive_patterns: Vec<Regex>,
    network_patterns: Vec<Regex>,
    sensitive_path_patterns: Vec<Regex>,
    dos_patterns: Vec<Regex>,
    escalation_patterns: Vec<Regex>,
    obfuscation_patterns: Vec<Regex>,
}

impl Default for CommandSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandSanitizer {
    pub fn new() -> Self {
        Self {
            destructive_patterns: vec![
                Regex::new(r"(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+([/~]|\.\./)").unwrap(),
                Regex::new(r"(?i)\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+([/~]|\.\./)").unwrap(),
                Regex::new(r"(?i)\brmdir\s+--ignore-fail-on-non-empty\s+/").unwrap(),
                Regex::new(r"(?i)\bmkfs(\.[a-z0-9]+)?\b").unwrap(),
                Regex::new(r"(?i)\bdd\s+.*of=/dev/(sd|nvme|hd|vd|disk)[a-z0-9]*").unwrap(),
                Regex::new(r"(?i)\b(fdisk|parted|gdisk)\b").unwrap(),
                Regex::new(r"(?i)>\s*/dev/sd[a-z]").unwrap(),
            ],
            network_patterns: vec![
                Regex::new(r"(?i)\b(curl|wget|fetch)\s+").unwrap(),
                Regex::new(r"(?i)\b(nc|ncat|netcat|socat|telnet)\b").unwrap(),
                Regex::new(r"/dev/(tcp|udp)/").unwrap(),
                Regex::new(r"(?i)\bssh\s+").unwrap(),
                Regex::new(r"(?i)\bscp\s+").unwrap(),
                Regex::new(r"(?i)\brsync\s+.*:\s*").unwrap(),
                Regex::new(r"(?i)\bping\s+").unwrap(),
                Regex::new(r"(?i)\bdig\s+").unwrap(),
                Regex::new(r"(?i)\bnslookup\s+").unwrap(),
            ],
            sensitive_path_patterns: vec![
                Regex::new(r"(/etc/shadow|/etc/passwd|/etc/master.passwd)").unwrap(),
                Regex::new(r"(~|\$HOME|/Users/[^/]+|/root)/\.ssh").unwrap(),
                Regex::new(r"(~|\$HOME|/Users/[^/]+|/root)/\.aws").unwrap(),
                Regex::new(r"(~|\$HOME|/Users/[^/]+|/root)/\.gnupg").unwrap(),
                Regex::new(r"(~|\$HOME|/Users/[^/]+|/root)/\.kube").unwrap(),
                Regex::new(r"(^|\s|/)(\.env|\.env\.[a-z0-9_\-]+)(\s|$)").unwrap(),
                Regex::new(r"(^|\s|/)id_rsa(\s|$)").unwrap(),
            ],
            dos_patterns: vec![
                Regex::new(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:").unwrap(),
                Regex::new(r"(?i)while\s+true\s*;\s*do\s+.*&\s*done").unwrap(),
                Regex::new(r"(?i)cat\s+/dev/(zero|urandom)\s+>\s+").unwrap(),
            ],
            escalation_patterns: vec![
                Regex::new(r"(?i)\b(sudo|su|doas)\b").unwrap(),
                Regex::new(r"(?i)\bchmod\s+(-[a-z]*R[a-z]*\s+)?(777|0777|a\+rwx)\s+/").unwrap(),
                Regex::new(r"(?i)\bchown\s+(-[a-z]*R[a-z]*\s+)?root\b").unwrap(),
            ],
            obfuscation_patterns: vec![
                Regex::new(r"(?i)\bbase64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh)").unwrap(),
                Regex::new(r"(?i)echo\s+.*\|\s*(xxd\s+-r|base64\s+-d)\s*\|\s*(sh|bash|zsh)").unwrap(),
                Regex::new(r"(?i)python([0-9\.]+)?\s+-c\s+.*import\s+socket").unwrap(),
                Regex::new(r"(?i)eval\s*\(\s*(base64_decode|unescape)").unwrap(),
            ],
        }
    }

    /// Evaluates a raw shell command string and produces a sanitization report.
    pub fn sanitize(&self, command: &str) -> Result<SanitizationReport, SanitizationError> {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return Err(SanitizationError::ParseError("Empty command string".to_string()));
        }

        let mut violations = Vec::new();

        // 1. Destructive Commands
        for pattern in &self.destructive_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Destructive command pattern matched: {}", pattern.as_str()));
                return Err(SanitizationError::DestructiveCommand(trimmed.to_string()));
            }
        }

        // 2. Outbound Network & Exfiltration
        for pattern in &self.network_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Network exfiltration pattern matched: {}", pattern.as_str()));
                return Err(SanitizationError::OutboundNetwork(trimmed.to_string()));
            }
        }

        // 3. Sensitive Paths & Credentials
        for pattern in &self.sensitive_path_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Sensitive path/credential access matched: {}", pattern.as_str()));
                return Err(SanitizationError::SensitivePathAccess(trimmed.to_string()));
            }
        }

        // 4. DoS / Fork Bombs
        for pattern in &self.dos_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Resource exhaustion DoS pattern matched: {}", pattern.as_str()));
                return Err(SanitizationError::ResourceExhaustion(trimmed.to_string()));
            }
        }

        // 5. Privilege Escalation
        for pattern in &self.escalation_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Privilege escalation pattern matched: {}", pattern.as_str()));
                return Err(SanitizationError::PrivilegeEscalation(trimmed.to_string()));
            }
        }

        // 6. Obfuscated / Dynamic Execution
        for pattern in &self.obfuscation_patterns {
            if pattern.is_match(trimmed) {
                violations.push(format!("Obfuscated execution payload matched: {}", pattern.as_str()));
                return Err(SanitizationError::ObfuscatedExecution(trimmed.to_string()));
            }
        }

        // Tokenize command safely
        let tokens: Vec<String> = trimmed
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        Ok(SanitizationReport {
            allowed: true,
            original_command: command.to_string(),
            sanitized_tokens: tokens,
            security_violations: Vec::new(),
        })
    }
}
