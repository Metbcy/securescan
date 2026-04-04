from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    database_path: str = "securescan.db"
    scanners_enabled: list[str] = ["semgrep", "bandit", "trivy"]
    groq_api_key: Optional[str] = None
    scan_timeout: int = 300
    compliance_data_dir: str = "data/compliance"
    report_template_dir: str = "templates/reports"
    nmap_extra_args: str = ""
    zap_api_key: Optional[str] = None
    zap_address: str = "http://localhost:8080"
    dast_timeout: int = 120

    model_config = {"env_prefix": "SECURESCAN_"}


settings = Settings()
