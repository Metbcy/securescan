# 🛡️ SecureScan

AI-powered security scanning dashboard that orchestrates multiple open-source security tools and presents findings in a unified interface.

## Features

- **Multi-scanner orchestration** — 11 scanners across code, dependency, IaC, and baseline categories
- **AI-powered analysis** — Groq/Llama 3 enrichment for remediation suggestions and executive summaries
- **Risk scoring** — Aggregate 0-100 risk score with severity-weighted algorithm
- **Dashboard** — Clean, modern Next.js dashboard with charts and findings tables
- **CLI** — Full-featured command-line interface for scripting and CI/CD
- **Extensible** — Easy to add new scanners via the base scanner interface

## Architecture

```
┌─────────────────────────┐
│  Next.js Dashboard      │
│  (Charts, Tables, UI)   │
└──────────┬──────────────┘
           │ REST API
┌──────────┴──────────────┐
│  FastAPI Backend        │
│  ├── Scanner Modules    │
│  ├── AI Enrichment      │
│  └── SQLite Storage     │
└─────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 20+

### Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Install scanners
pip install semgrep bandit safety pip-licenses checkov

# Optional: Trivy (see https://trivy.dev)
# Optional: Node.js/npm (for npm-audit scanner)
```

### Windows Setup (PowerShell)

```powershell
cd backend
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -e .
pip install semgrep bandit safety pip-licenses checkov

# Optional: Trivy (see https://trivy.dev)
# Optional: Node.js/npm (for npm-audit scanner)

# Optional AI key
$env:SECURESCAN_GROQ_API_KEY="your-key-here"

# Start API
python -m src.cli serve --host 127.0.0.1 --port 8000
```

If you use Command Prompt instead of PowerShell, activate with:

```bat
venv\Scripts\activate.bat
```

### CLI Usage

```bash
# Check available scanners
securescan status

# Scan a project
securescan scan ./your-project

# Scan specific types only
securescan scan ./your-project --type code --type baseline

# Start the API server
securescan serve --port 8000

# View scan history
securescan history
```

### Dashboard Setup

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 — the dashboard connects to the backend API at http://localhost:8000.

Windows (PowerShell):

```powershell
cd frontend
npm install
$env:NEXT_PUBLIC_API_URL="http://127.0.0.1:8000"
npm run dev
```

### Docker

```bash
docker compose up
```

## Scanners

| Scanner | Type | What it finds |
|---------|------|--------------|
| **Semgrep** | Code (SAST) | SQL injection, XSS, hardcoded secrets, command injection |
| **Bandit** | Code (Python) | Python-specific security issues, insecure imports |
| **Secrets** | Code | Hardcoded credentials, API keys, tokens, private keys |
| **Git Hygiene** | Code | Sensitive files in repo, missing `.gitignore` protections |
| **Trivy** | Dependencies | Known CVEs in package manifests and lockfiles |
| **Safety** | Dependencies | Python dependency vulnerabilities from safety DB |
| **License Checker** | Dependencies | Copyleft/unknown license compliance risks |
| **npm Audit** | Dependencies | npm package advisories and transitive vulns |
| **Checkov** | IaC | Terraform, K8s, Docker, and cloud misconfigurations |
| **Dockerfile** | IaC | Insecure Docker patterns (`:latest`, root user, `curl \| sh`, secrets in `ENV`) |
| **Baseline** | System Config | SSH, firewall, password policy, kernel security checks |

## AI Enrichment

Set a Groq API key (free tier) to enable AI-powered features:

```bash
export SECURESCAN_GROQ_API_KEY=your-key-here
```

Windows PowerShell:

```powershell
$env:SECURESCAN_GROQ_API_KEY="your-key-here"
```

Features:
- Remediation suggestions for critical/high findings
- Executive summary generation
- Contextual risk analysis

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API info with links to docs and health |
| GET | `/health` | Simple health check |
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{id}` | Get scan details |
| GET | `/api/scans/{id}/findings` | Get scan findings |
| GET | `/api/scans/{id}/summary` | Get scan summary |
| POST | `/api/scans/{id}/cancel` | Cancel an active scan |
| GET | `/api/scans/compare` | Compare two scans (new, fixed, unchanged) |
| GET | `/api/dashboard/status` | Scanner availability |
| GET | `/api/dashboard/stats` | Aggregate statistics |
| GET | `/api/dashboard/trends` | Risk/findings trend data |
| GET | `/api/browse` | Filesystem directory picker data |
| POST | `/api/dashboard/install/{scanner}` | Install supported scanners |

## Running Tests

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

## Tech Stack

- **Backend**: Python, FastAPI, SQLite, asyncio
- **Frontend**: Next.js 15, Tailwind CSS, Recharts
- **AI**: Groq API (Llama 3)
- **Scanners**: 11 integrated scanners (code, dependency, IaC, baseline)

## License

MIT
