from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    database_path: str = "securescan.db"
    scanners_enabled: list[str] = ["semgrep", "bandit", "trivy"]
    groq_api_key: Optional[str] = None
    scan_timeout: int = 300

    model_config = {"env_prefix": "SECURESCAN_"}


settings = Settings()
