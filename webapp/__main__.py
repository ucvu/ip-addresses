from __future__ import annotations

import uvicorn

from .app import create_app
from .config import AppConfig


def main() -> None:
    config = AppConfig.from_environment()
    uvicorn.run(create_app(config), host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
