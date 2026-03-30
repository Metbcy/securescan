# 🛡️ SecureScan

AI-powered security scanning dashboard that orchestrates multiple open-source security tools and presents findings in a unified interface.

## Features

- **Multi-scanner orchestration** — Semgrep, Bandit, Trivy, Checkov, and custom baseline checks
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
pip install semgrep bandit

# Optional: Trivy (see https://trivy.dev)
# Optional: Checkov (pip install checkov)
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

### Docker

```bash
docker compose up
```

## Scanners

| Scanner | Type | What it finds |
|---------|------|--------------|
| **Semgrep** | Code (SAST) | SQL injection, XSS, hardcoded secrets, command injection |
| **Bandit** | Code (Python) | Python-specific security issues, insecure imports |
| **Trivy** | Dependencies | Known CVEs in packages (requirements.txt, package.json) |
| **Checkov** | IaC | Terraform, K8s, Docker misconfigurations |
| **Baseline** | System Config | SSH, firewall, password policy, kernel security checks |

## AI Enrichment

Set a Groq API key (free tier) to enable AI-powered features:

```bash
export SECURESCAN_GROQ_API_KEY=your-key-here
```

Features:
- Remediation suggestions for critical/high findings
- Executive summary generation
- Contextual risk analysis

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{id}` | Get scan details |
| GET | `/api/scans/{id}/findings` | Get scan findings |
| GET | `/api/scans/{id}/summary` | Get scan summary |
| GET | `/api/dashboard/status` | Scanner availability |
| GET | `/api/dashboard/stats` | Aggregate statistics |

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
- **Scanners**: Semgrep, Bandit, Trivy, Checkov

## License

MIT
