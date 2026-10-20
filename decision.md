# Architecture Decision Record (ADR): aegis-sandbox

## Status
Accepted & Implemented (Commit `4797f0b`)

## Context
Aegis was originally built solely on macOS Darwin Seatbelt (`libsystem_sandbox.dylib`). This prevented it from running on standard Linux CI/CD runners (like GitHub Actions) and cloud production servers where autonomous coding agents are increasingly deployed.

## Decisions

### 1. Implement Bubblewrap (`bwrap`) Linux Driver
- **Decision:** Use Bubblewrap to create unprivileged user namespaces on Linux systems without requiring root or setuid privileges.
- **Consequence:** Full cross-platform parity between developer macOS laptops and cloud Linux runners.

### 2. Dual-Layer Defense (Sanitizer + Kernel Trap)
- **Decision:** Do not rely exclusively on kernel denial; intercept obvious destructive patterns (fork bombs, `~/.ssh` accesses) before child process fork.
- **Consequence:** Clean, human-readable error messages for users instead of opaque OS abort signals.
