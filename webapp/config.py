from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppConfig:
    project_dir: Path
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    session_minutes: int = 60
    secure_cookie: bool = False

    @classmethod
    def from_environment(cls, project_dir: Path | None = None) -> "AppConfig":
        project = (project_dir or Path(__file__).resolve().parent.parent).resolve()
        data = Path(os.getenv("NETCRAZE_WEB_DATA", project / ".webdata")).resolve()
        return cls(
            project_dir=project,
            data_dir=data,
            host=os.getenv("NETCRAZE_WEB_HOST", "127.0.0.1"),
            port=int(os.getenv("NETCRAZE_WEB_PORT", "8765")),
            session_minutes=int(os.getenv("NETCRAZE_SESSION_MINUTES", "60")),
            secure_cookie=os.getenv("NETCRAZE_SECURE_COOKIE", "0") == "1",
        )
