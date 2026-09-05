from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .models import OperationEvent, OperationOptions, RouterCredentials, RouterTarget

EventSink = Callable[[OperationEvent], None]


class IsolatedCliExecutor:
    """Безопасный адаптер существующего CLI для веб-очереди.

    Каждый запуск получает отдельный каталог, поэтому генератор не удаляет и
    не перезаписывает файлы другого задания.
    """

    def __init__(self, project_dir: Path, job_dir: Path, emit: EventSink) -> None:
        self.project_dir = project_dir
        self.job_dir = job_dir
        self.emit = emit

    def prepare(self, preset_content: str | None, conf_source: Path | None) -> tuple[Path | None, Path | None]:
        self.job_dir.mkdir(parents=True, exist_ok=True)
        for filename in ("install_wireguard.py", "generate_geo_domains.py"):
            shutil.copy2(self.project_dir / filename, self.job_dir / filename)
        for filename in ("geosite.dat", "geoip.dat"):
            source = self.project_dir / filename
            if source.exists():
                destination = self.job_dir / filename
                try:
                    os.link(source, destination)
                except OSError:
                    shutil.copy2(source, destination)
        preset_path = None
        if preset_content is not None:
            preset_path = self.job_dir / "preset.txt"
            preset_path.write_text(preset_content, encoding="utf-8")
        conf_path = None
        if conf_source is not None:
            conf_path = self.job_dir / (conf_source.name if conf_source.suffix.lower() == ".conf" else "wireguard.conf")
            if conf_source.resolve() != conf_path.resolve():
                shutil.copy2(conf_source, conf_path)
        return preset_path, conf_path

    def run(
        self,
        target: RouterTarget,
        credentials: RouterCredentials,
        options: OperationOptions,
        preset_path: Path | None,
        generate_off: bool = False,
    ) -> int:
        command = [
            sys.executable,
            "-u",
            str(self.job_dir / "install_wireguard.py"),
            "--action",
            options.action,
            "--router",
            target.address,
        ]
        if options.action in {"install", "update"}:
            command.extend(["--preset", str(preset_path)])
            if options.online and not generate_off:
                command.append("--online")
            if options.generate_off or generate_off:
                command.append("--generate-off")
        if options.action == "endpoint":
            command.extend(["--endpoint", options.endpoint or ""])
        if options.vpn_off:
            command.append("--vpn-off")
        if options.action == "install":
            command.append("--keep-conf")

        environment = os.environ.copy()
        environment["ROUTER_USERNAME"] = credentials.username
        environment["ROUTER_PASSWORD"] = credentials.password
        # Windows выбирает системную кодовую страницу для перенаправленного
        # stdout дочернего Python. Фиксируем UTF-8 с обеих сторон pipe.
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONUNBUFFERED"] = "1"
        self.emit(OperationEvent("command", f"Запуск операции {options.action}.", router=target.name))
        process = subprocess.Popen(
            command,
            cwd=self.job_dir,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            message = line.rstrip()
            if message:
                self.emit(OperationEvent("router", message, router=target.name))
        return process.wait()
