from pathlib import Path

from pydantic_settings import BaseSettings

_PKG_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    database_path: str = "securescan.db"
    scanners_enabled: list[str] = ["semgrep", "bandit", "trivy"]
    groq_api_key: str | None = None
    scan_timeout: int = 300
    compliance_data_dir: str = str(_PKG_DIR / "data" / "compliance")
    report_template_dir: str = str(_PKG_DIR / "templates" / "reports")
    nmap_extra_args: str = ""
    zap_api_key: str | None = None
    zap_address: str = "http://localhost:8080"
    dast_timeout: int = 120

    model_config = {"env_prefix": "SECURESCAN_"}


settings = Settings()
