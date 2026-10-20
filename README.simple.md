# Aegis Sandbox — Plain-English Guide

## What is Aegis?

Aegis is a security guard for AI coding agents.

When you let an AI tool (like Claude Code, Cursor, or Codex) run commands on your computer, it has the power to do anything — delete files, steal passwords, download malware. One bad command and your whole system is compromised.

Aegis sits between the AI and your computer. Every command the AI tries to run goes through Aegis first. If the command is dangerous, Aegis blocks it before it can do any damage.

## What does it block?

- **Destructive commands** — `rm -rf /`, disk formatting, file wiping
- **Data theft** — Attempts to read your SSH keys, .env files, cloud credentials
- **Network exfiltration** — Piping your data to a remote server via curl, wget, or netcat
- **Fork bombs** — Commands that spawn infinite processes to crash your machine

## How does it work?

1. The AI agent sends a command to Aegis instead of running it directly
2. Aegis parses the command and checks it against a set of safety rules
3. If the command is safe, Aegis runs it inside an isolated sandbox (like a virtual box)
4. The sandbox has no network access and can only touch files in your project folder
5. After the command runs, Aegis creates a cryptographic receipt (a tamper-proof record of what happened)

## What's it built with?

- **Rust** — Fast, memory-safe systems language
- **macOS Seatbelt / Linux namespaces** — Operating system-level isolation
- **Blake3** — Cryptographic hashing for audit receipts
- **MCP (Model Context Protocol)** — Standard interface for AI tools

## Who is it for?

Anyone running AI coding agents who wants to make sure the AI can't accidentally (or intentionally) destroy their system.
