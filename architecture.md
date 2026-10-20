# Architecture Specification: aegis-sandbox

## 1. System Architecture Diagram

```mermaid
graph TD
    Agent["Autonomous Agent / CLI"] -->|aegis run -- cmd| Sanitizer["Command Sanitizer & AST Guard"]
    
    Sanitizer -->|Validated Command| Isolator["Sandbox Isolator Engine"]
    
    subgraph "Kernel Driver Selection"
        Isolator -->|Darwin / macOS| Seatbelt["macOS Seatbelt Driver<br/>(sandbox_init_with_parameters)"]
        Isolator -->|Linux Cloud / CI| Bwrap["Bubblewrap Driver (bwrap)<br/>(User, Mount, PID, IPC Namespaces)"]
        Isolator -->|Container Fallback| DockerDriver["Docker Isolated Driver"]
    end
    
    subgraph "Sandboxed Execution"
        Seatbelt --> Child["Child Process Inode Boundary"]
        Bwrap --> Child
        DockerDriver --> Child
    end
    
    Child -->|Exit Code & Blocked Syscalls| Telemetry["Structured JSON Security Report"]
```

---

## 2. Component Blueprint
- **`src/sanitizer.rs`**: Regex and AST-level rule engine inspecting command arguments against exfiltration strings, fork bombs, and root directory traversal.
- **`src/isolator.rs`**: Cross-platform driver abstraction detecting host operating system and configuring the tightest sandbox isolation backend.
- **`src/main.rs`**: CLI entry point parsing command arguments and returning standard POSIX exit codes.
