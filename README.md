<!-- BlackRoad SEO Enhanced -->

# ulackroad vuln scanner

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad OS](https://img.shields.io/badge/Org-BlackRoad-OS-2979ff?style=for-the-badge)](https://github.com/BlackRoad-OS)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad vuln scanner** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


[![CI](https://github.com/BlackRoad-OS/blackroad-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-OS/blackroad-vuln-scanner/actions/workflows/ci.yml)

> **BlackRoad Vulnerability Scanner** — production-quality Python tool for detecting CVEs in Python dependencies, security anti-patterns in Dockerfiles, and leaked secrets in `.env` files. Results are persisted to SQLite for historical trend analysis.

---

## Features

- 🔍 **Dependency scanning** — checks `requirements.txt` against 15 real CVEs
- 🐳 **Dockerfile scanning** — detects 11 security anti-patterns (`:latest`, curl-pipe, root user, embedded secrets, …)
- 🔑 **Env-file scanning** — finds 18 classes of leaked credentials (passwords, API keys, AWS keys, JWT secrets, …)
- 📊 **Multi-format reports** — `text`, `json`, `csv`
- 🗄️ **SQLite persistence** — full scan history, per-scan vulnerability drill-down, aggregate stats
- 🖥️ **CLI** — single-command interface with subcommands

---

## Installation

```bash
git clone https://github.com/BlackRoad-OS/blackroad-vuln-scanner.git
cd blackroad-vuln-scanner
pip install -r requirements.txt
```

---

## Usage

### Scan Python dependencies

```bash
# Text report (default)
python -m src.vuln_scanner deps requirements.txt

# JSON report
python -m src.vuln_scanner deps requirements.txt --format json

# CSV report
python -m src.vuln_scanner deps requirements.txt --format csv
```

### Scan a Dockerfile

```bash
python -m src.vuln_scanner docker Dockerfile
python -m src.vuln_scanner docker path/to/Dockerfile --format json
```

### Scan environment files

```bash
# Recursively scans all .env files under the given directory
python -m src.vuln_scanner env .
python -m src.vuln_scanner env /path/to/project --format csv
```

### View scan history

```bash
python -m src.vuln_scanner history
```

### View aggregate statistics

```bash
python -m src.vuln_scanner stats
```

### Use a custom database path

```bash
python -m src.vuln_scanner --db /var/lib/blackroad/vulns.db deps requirements.txt
```

---

## Python API

```python
from src.vuln_scanner import VulnerabilityScanner

scanner = VulnerabilityScanner(db_path="vulns.db")

# Scan dependencies
result = scanner.scan_dependencies("requirements.txt")
print(f"Found {result.total} vulnerabilities ({result.critical} critical)")

# Scan Dockerfile
result = scanner.scan_dockerfile("Dockerfile")
report = scanner.generate_report(result.vulnerabilities, format="json")

# Scan .env files
result = scanner.scan_env_files("/path/to/project")

# Historical data
history = scanner.get_scan_history(limit=10)
stats   = scanner.get_stats()

scanner.close()
```

---

## CVE Database

The built-in CVE database covers the following advisories:

| CVE | Package | Severity | Fix version |
|-----|---------|----------|-------------|
| CVE-2023-32681 | requests | HIGH | 2.31.0 |
| CVE-2023-44271 | pillow | HIGH | 10.0.1 |
| CVE-2023-30861 | flask | HIGH | 2.3.2 |
| CVE-2023-25577 | werkzeug | HIGH | 2.2.3 |
| CVE-2023-6395  | pyyaml | CRITICAL | 6.0.1 |
| CVE-2023-43804 | urllib3 | HIGH | 2.0.7 |
| CVE-2023-28370 | tornado | MEDIUM | 6.3.2 |
| CVE-2021-43818 | lxml | HIGH | 4.7.1 |
| CVE-2022-40897 | setuptools | HIGH | 65.5.1 |
| CVE-2024-23334 | aiohttp | HIGH | 3.9.2 |
| CVE-2023-29483 | dnspython | MEDIUM | 2.4.2 |
| CVE-2022-42969 | py | HIGH | 1.11.0 |
| CVE-2023-24816 | ipython | HIGH | 8.10.0 |
| CVE-2022-35737 | starlette | HIGH | 0.20.4 |
| CVE-2023-49083 | cryptography | CRITICAL | 41.0.0 |

---

## SQLite Schema

```sql
CREATE TABLE scans (
    scan_id   TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL,   -- 'dependency' | 'dockerfile' | 'env'
    target    TEXT NOT NULL,
    total     INTEGER DEFAULT 0,
    critical  INTEGER DEFAULT 0,
    high      INTEGER DEFAULT 0,
    medium    INTEGER DEFAULT 0,
    low       INTEGER DEFAULT 0
);

CREATE TABLE vulnerabilities (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(scan_id),
    cve              TEXT,
    severity         TEXT,   -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    description      TEXT,
    package          TEXT,
    version_affected TEXT,
    fix_version      TEXT,
    file_path        TEXT,
    line_number      INTEGER,
    source           TEXT,   -- 'dependency' | 'dockerfile' | 'env-file'
    created_at       TEXT NOT NULL
);
```

---

## Running Tests

```bash
pytest tests/ -v --tb=short
```

### With coverage

```bash
pip install pytest-cov
pytest tests/ -v --cov=src --cov-report=term-missing
```

---

## License

Proprietary — © BlackRoad OS, Inc. All rights reserved.
