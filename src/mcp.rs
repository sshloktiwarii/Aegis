use crate::isolator::{Isolator, SandboxConfig, IsolationBackend};
use crate::sanitizer::CommandSanitizer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub struct McpServer {
    sanitizer: CommandSanitizer,
    isolator: Isolator,
}

impl McpServer {
    pub fn new(workspace_dir: PathBuf) -> Self {
        let mut config = SandboxConfig::default();
        config.workspace_dir = workspace_dir;

        Self {
            sanitizer: CommandSanitizer::new(),
            isolator: Isolator::new(config, IsolationBackend::ProcessSandbox),
        }
    }

    pub async fn run_stdio(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let reader = stdin.lock();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let request: Result<JsonRpcRequest, _> = serde_json::from_str(&line);
            match request {
                Ok(req) => {
                    let response = self.handle_request(req).await;
                    let resp_str = serde_json::to_string(&response)?;
                    writeln!(stdout, "{}", resp_str)?;
                    stdout.flush()?;
                }
                Err(err) => {
                    let err_response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: None,
                        result: None,
                        error: Some(json!({
                            "code": -32700,
                            "message": format!("Parse error: {}", err)
                        })),
                    };
                    let resp_str = serde_json::to_string(&err_response)?;
                    writeln!(stdout, "{}", resp_str)?;
                    stdout.flush()?;
                }
            }
        }

        Ok(())
    }

    pub async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "aegis-sandbox",
                        "version": "0.1.0"
                    }
                })),
                error: None,
            },
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(json!({
                    "tools": [
                        {
                            "name": "execute_command",
                            "description": "Executes a sandboxed shell command after AST verification and security scanning",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "string",
                                        "description": "Shell command to sanitize and execute in isolated container/sandbox"
                                    }
                                },
                                "required": ["command"]
                            }
                        },
                        {
                            "name": "scan_command",
                            "description": "Inspects a command string for dangerous primitives, exfiltration vectors, or sensitive path traversal without executing it",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {
                                        "type": "string",
                                        "description": "Command string to analyze"
                                    }
                                },
                                "required": ["command"]
                            }
                        }
                    ]
                })),
                error: None,
            },
            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

                match tool_name {
                    "scan_command" => {
                        let cmd = arguments.get("command").and_then(|v| v.as_str()).unwrap_or("");
                        match self.sanitizer.sanitize(cmd) {
                            Ok(report) => JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: Some(json!({
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": serde_json::to_string_pretty(&report).unwrap()
                                        }
                                    ]
                                })),
                                error: None,
                            },
                            Err(err) => JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: Some(json!({
                                    "isError": true,
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("SECURITY VIOLATION REJECTED: {}", err)
                                        }
                                    ]
                                })),
                                error: None,
                            },
                        }
                    }
                    "execute_command" => {
                        let cmd = arguments.get("command").and_then(|v| v.as_str()).unwrap_or("");
                        match self.sanitizer.sanitize(cmd) {
                            Ok(_) => match self.isolator.execute(cmd).await {
                                Ok(res) => {
                                    let stdout_str = String::from_utf8_lossy(&res.stdout).to_string();
                                    let stderr_str = String::from_utf8_lossy(&res.stderr).to_string();
                                    JsonRpcResponse {
                                        jsonrpc: "2.0".to_string(),
                                        id: req.id,
                                        result: Some(json!({
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": stdout_str
                                                }
                                            ],
                                            "metadata": {
                                                "exit_code": res.exit_code,
                                                "stderr": stderr_str,
                                                "receipt": res.receipt
                                            }
                                        })),
                                        error: None,
                                    }
                                }
                                Err(err) => JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    id: req.id,
                                    result: Some(json!({
                                        "isError": true,
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": format!("Isolation runtime error: {}", err)
                                            }
                                        ]
                                    })),
                                    error: None,
                                },
                            },
                            Err(err) => JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req.id,
                                result: Some(json!({
                                    "isError": true,
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("GATEWAY BLOCKED COMMAND: {}", err)
                                        }
                                    ]
                                })),
                                error: None,
                            },
                        }
                    }
                    _ => JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(json!({
                            "code": -32601,
                            "message": format!("Method not found: {}", tool_name)
                        })),
                    },
                }
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(json!({
                    "code": -32601,
                    "message": format!("Unsupported method: {}", req.method)
                })),
            },
        }
    }
}
