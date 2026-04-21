import logging
import os
from pathlib import Path

from fastapi import FastAPI


def load_env_file() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text().splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue

        key, value = entry.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_env_file()
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(message)s")

from api.routes import router as scans_router


app = FastAPI(title="SurfaceLab Orchestrator")
app.include_router(scans_router)
