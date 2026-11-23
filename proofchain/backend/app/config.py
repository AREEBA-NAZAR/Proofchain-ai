from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(BACKEND_DIR / ".env"), extra="ignore")

    # SQLite by default so the prototype runs with zero setup; set
    # DATABASE_URL=postgresql+psycopg2://user:pass@host/db for PostgreSQL.
    database_url: str = f"sqlite:///{(DATA_DIR / 'proofchain.db').as_posix()}"

    rpc_url: str = "http://127.0.0.1:8545"
    # Written by `contracts/scripts/deploy.js`.
    deployment_file: str = str(REPO_DIR / "contracts" / "deployments" / "localhost.json")

    storage_dir: str = str(DATA_DIR / "objects")
    # e.g. http://127.0.0.1:5001 — when set, metadata is pinned to IPFS instead of local disk.
    ipfs_api_url: str | None = None

    public_app_url: str = "http://localhost:3000"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    max_upload_mb: int = 50
    # Per-process sliding-window limits. Place a shared limiter at the edge for
    # multi-worker or multi-instance deployments.
    api_rate_limit_per_minute: int = Field(default=120, ge=1)
    upload_rate_limit_per_minute: int = Field(default=20, ge=1)
    rate_limit_redis_url: str | None = None

    # Pretrained AI-image classifier, run with ONNX Runtime (see backend/ml/download_detector.py).
    detector_onnx: str = str(BACKEND_DIR / "models" / "detector.onnx")
    # Pretrained AI-text classifier: a folder holding model.onnx + tokenizer.json.
    text_detector_dir: str = str(BACKEND_DIR / "models" / "text-detector")
    # Optional self-trained TorchScript classifier (see backend/ml/train_detector.py).
    detector_weights: str = str(BACKEND_DIR / "models" / "detector.pt")


def get_settings() -> Settings:
    return Settings()
