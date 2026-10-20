# Project Breakdown: aegis-sandbox

## 1. Why It Exists (The Problem)
Autonomous AI coding agents have terminal access to your computer. A hallucinated or malicious command (such as `rm -rf /`, credential harvesting, or reverse-shell piping) can wipe a hard drive or leak environment secrets in seconds. Standard software-level checks can be bypassed by shell obfuscation, symlinks, or eval statements.

---

## 2. What It Does (The Solution)
Aegis is an unbypassable kernel-level containment sandbox for autonomous AI agents:
- **macOS Darwin Seatbelt:** Compiles Scheme (`.sb`) profiles dynamically and binds child processes via `sandbox_init_with_parameters(3)`.
- **Cloud Linux Bubblewrap (`bwrap`):** Creates unprivileged user, mount, PID, IPC, and network namespaces.
- **Read-Only System Root:** Mounts `/usr`, `/bin`, `/sbin`, and `/lib` as strictly immutable, isolating file modifications to an ephemeral temporary folder or targeted project directory.
- **AST Command Sanitization:** Pre-filters shell strings against dangerous command patterns, fork bombs, and credential file targets before execution.

---

## 3. Targeted Niche & Use Cases
Developers, autonomous coding agent frameworks (Devin, AutoGPT, OpenCode), and CI/CD pipelines needing absolute kernel-enforced guarantees that agent code execution cannot escape the assigned workspace.
