from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from core.presets import PresetValidationError, parse_preset

from .config import AppConfig
from .database import Database
from .jobs import JobManager
from .routes_auth import router as auth_router
from .routes_datasets import router as datasets_router
from .routes_inventory import router as inventory_router
from .routes_operations import router as operations_router
from .security import SecretBox, ensure_secret


def create_app(config: AppConfig | None = None, start_worker: bool = True) -> FastAPI:
    config = config or AppConfig.from_environment()
    config.data_dir.mkdir(parents=True, exist_ok=True)
    (config.data_dir / "uploads").mkdir(exist_ok=True)

    db = Database(config.data_dir / "webapp.sqlite3")
    # Хеш от удалённой парольной авторизации больше не нужен.
    db.delete_setting("admin_password")
    secret_box = SecretBox(config.data_dir / "fernet.key")
    manager = JobManager(db, secret_box, config.project_dir, config.data_dir)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        _seed_presets(db, config.project_dir)
        if start_worker:
            manager.start()
        yield
        if start_worker:
            manager.stop()

    app = FastAPI(title="Netcraze WireGuard", lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=ensure_secret(config.data_dir / "session.key"),
        session_cookie="netcraze_session",
        max_age=config.session_minutes * 60,
        same_site="lax",
        https_only=config.secure_cookie,
    )
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    app.state.config = config
    app.state.db = db
    app.state.jobs = manager
    app.state.secret_box = secret_box
    app.include_router(auth_router)
    app.include_router(inventory_router)
    app.include_router(operations_router)
    app.include_router(datasets_router)
    return app


def _seed_presets(db: Database, project_dir) -> None:
    if db.list_presets():
        return
    for path in (project_dir / "preset-services-only.txt", project_dir / "preset-ru-direct.txt"):
        if not path.exists():
            continue
        try:
            parsed = parse_preset(path.read_text(encoding="utf-8"), path.stem)
            db.save_preset(parsed.name, parsed.content)
        except (PresetValidationError, sqlite3.IntegrityError):
            pass
