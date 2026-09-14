"""Runtime configuration, read from environment variables.

A ``backend/.env`` file (gitignored) is loaded on import if present, so secrets
like ``GROQ_API_KEY`` never live in the codebase. Everything has a sensible
default so the service runs out of the box for local development.
"""
import os
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Populate os.environ from a simple KEY=VALUE .env file (no override)."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(_BACKEND_DIR / ".env")


class Settings:
    """Resolved application settings."""

    data_dir = Path(os.getenv("DATA_DIR", _BACKEND_DIR / "data"))
    dataset_dir = Path(os.getenv("DATASET_DIR", _REPO_ROOT / "Dataset"))
    groq_api_key = os.getenv("GROQ_API_KEY") or None
    cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")


settings = Settings()
