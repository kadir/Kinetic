# ⚡ WellQ / Kinetic (v0.2.5)

### The High-Velocity, Agentic Offensive MCP Gateway

![WellQ Kinetic Logo](assets/logo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docker: Supported](https://img.shields.io/badge/Docker-Ready-cyan.svg)](https://www.docker.com/)
[![MCP: Enabled](https://img.shields.io/badge/MCP-FastMCP-orange.svg)](https://modelcontextprotocol.io)

**WellQ / Kinetic** is a next-generation Model Context Protocol (MCP) gateway designed for professional Red Teams and Vulnerability Researchers. It transforms Claude into an autonomous security operator by providing a multi-threaded, dockerized, and "safe-shell" execution environment.

---

## 🚀 Key Features

- ⚡ **Multi-Threaded Execution**  
  Powered by a FastAPI-based *Strike Engine* that handles concurrent Nmap, Nuclei, and Ffuf scans.

- 🛡️ **Safe-Shell Validator**  
  Strict Pydantic-based input validation with YAML-defined tool allowlists.

- 👁️ **Visual Intel**  
  Integrated Selenium sidecar for automated XSS verification and page screenshots.

- 🧬 **Researcher Arsenal**  
  Pre-installed tools:
  - Semgrep
  - Gitleaks
  - Subfinder
  - Amass
  - Arjun

- 📦 **One-Click Deployment**  
  Fully dockerized architecture with a dedicated workspace manager for ephemeral git cloning.

- 🛑 **Emergency Brake**  
  Global `abort_scan` tool for instant termination of rogue processes.

---

## 🏗️ Architecture

WellQ / Kinetic utilizes a decoupled microservices architecture:

- **The Gate (MCP Server)**  
  FastMCP implementation mapping AI intent to the engine.

- **The Strike Engine (FastAPI)**  
  Asynchronous backend managing the TaskRunner.

- **The Vault (Docker)**  
  Hardened container containing offensive binaries.

- **The Eye (Selenium)**  
  Standalone Chrome sidecar for headless DOM interaction.

---

## 📥 Installation & Setup

### 1. Launch the Infrastructure

```bash
cd docker
docker compose up -d --build
```

### 2. Connect to Claude

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kinetic": {
      "command": "python3",
      "args": ["/path/to/kinetic/mcp/server.py"],
      "env": {
        "KINETIC_ENGINE_URL": "http://localhost:8000"
      }
    }
  }
}
```

---

## 🧪 Current Toolset (v0.2.5)

| Category | Tools | Purpose |
|----------|------|--------|
| Recon | Subfinder, Amass, Nmap | Infrastructure Mapping |
| Web | Nuclei, Ffuf, Arjun | Vulnerability Scanning & Parameter Discovery |
| SAST | Semgrep, Gitleaks | Source Auditing & Secret Detection |
| Dynamic | Selenium, Curl | DOM Analysis & Payload Verification |
| System | Git, Workspace | Ephemeral Repository Cloning |

---

## ⚠️ Ethical Disclosure

WellQ / Kinetic is intended for **authorized security testing only**.  
Unauthorized access or misuse is illegal.  

The developers assume **no liability** for misuse of this software.

---

## 🧠 About

Developed by **WellQ.io**
