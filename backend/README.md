# SecureScan Backend

AI-powered security scanning dashboard.

## Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Install Scanners

```bash
pip install semgrep bandit
# For Trivy: see https://trivy.dev/latest/getting-started/installation/
```

## Usage

```bash
securescan status            # Check available scanners
securescan scan ./myproject  # Scan a project
securescan serve             # Start API server
securescan history           # View past scans
```

## API Endpoints

| Method | Endpoint                        | Description             |
|--------|---------------------------------|-------------------------|
| POST   | `/api/scans`                    | Start a new scan        |
| GET    | `/api/scans`                    | List all scans          |
| GET    | `/api/scans/{id}`               | Get scan details        |
| GET    | `/api/scans/{id}/findings`      | Get scan findings       |
| GET    | `/api/scans/{id}/summary`       | Get scan summary        |
| GET    | `/api/dashboard/status`         | Scanner availability    |
| GET    | `/api/dashboard/stats`          | Aggregate statistics    |
