from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import urllib.request
from pathlib import Path

from core.executor import IsolatedCliExecutor
from core.models import OperationEvent, OperationOptions, RouterCredentials, RouterTarget
from generate_geo_domains import GEOIP_URL, GEOSITE_URL

from .database import Database, utc_now
from .security import SecretBox


class JobManager:
    def __init__(self, db: Database, secrets: SecretBox, project_dir: Path, data_dir: Path) -> None:
        self.db = db
        self.secrets = secrets
        self.project_dir = project_dir
        self.data_dir = data_dir
        self.jobs_dir = data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.db.interrupt_running_jobs()
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, name="netcraze-job-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=3)

    def notify(self) -> None:
        self._wake.set()

    def request_cancel(self, job_id: int) -> None:
        job = self.db.get_job(job_id)
        if not job or job["status"] in {"success", "failed", "cancelled", "interrupted"}:
            return
        self.db.update_job(job_id, cancel_requested=1, awaiting_confirmation=0)
        self.db.add_event(job_id, "warning", "cancel", "Запрошена безопасная отмена задачи.")
        self.notify()

    def confirm_next(self, job_id: int) -> None:
        job = self.db.get_job(job_id)
        if job and job["status"] == "waiting":
            self.db.update_job(job_id, status="running", awaiting_confirmation=0)
            self.db.add_event(job_id, "info", "manual", "Продолжение подтверждено администратором.")
            self.notify()

    def retry_failed(
        self,
        job_id: int,
        target_ids: list[int] | None = None,
        iterations: int = 1,
    ) -> int:
        job = self.db.get_job(job_id)
        if not job:
            raise ValueError("Задача не найдена.")
        if job["type"] == "install":
            raise ValueError("Для повторной установки необходимо заново загрузить WireGuard-конфигурацию.")
        if not 1 <= iterations <= 20:
            raise ValueError("Количество прогонов должно быть от 1 до 20.")
        if job["status"] in {"interrupted", "cancelled"}:
            available_targets = self.db.get_job_targets(job_id)
        else:
            available_targets = self.db.get_job_targets(job_id, "failed")
        if not available_targets:
            raise ValueError("В задаче нет доступных для повторного запуска целей.")
        if target_ids is None:
            targets = available_targets
        else:
            selected_ids = set(target_ids)
            available_ids = {target["id"] for target in available_targets}
            if selected_ids - available_ids:
                raise ValueError("Выбраны недоступные для повторного запуска цели.")
            targets = [target for target in available_targets if target["id"] in selected_ids]
            if not targets:
                raise ValueError("Выберите хотя бы один роутер для повторного запуска.")

        options = json.loads(job["options_json"])
        options["retry_iterations"] = iterations
        new_id = self.db.create_job(job["type"], options, targets, bool(job["manual"]))
        self.db.add_event(
            new_id,
            "info",
            "queue",
            f"Новый проход задачи №{job_id}: роутеров {len(targets)}, прогонов {iterations}.",
        )
        self.notify()
        return new_id

    def _worker(self) -> None:
        while not self._stop.is_set():
            job = self.db.next_queued_job()
            if job is None:
                self._wake.wait(0.75)
                self._wake.clear()
                continue
            try:
                self._process_job(job)
            except Exception as exc:
                self._cleanup_job_files(job)
                self.db.add_event(job["id"], "error", "internal", f"Внутренняя ошибка: {exc}")
                self.db.update_job(
                    job["id"], status="failed", error=str(exc), finished_at=utc_now(), awaiting_confirmation=0
                )

    def _process_job(self, job) -> None:
        job_id = int(job["id"])
        if job["cancel_requested"]:
            self.db.update_job(job_id, status="cancelled", finished_at=utc_now())
            return
        self.db.update_job(job_id, status="running", started_at=utc_now())
        self.db.add_event(job_id, "info", "start", "Задача запущена.", percent=0)
        if job["type"] == "dataset_update":
            self._update_datasets(job_id)
            return

        options_data = json.loads(job["options_json"])
        options = OperationOptions(
            action=job["type"],
            preset_id=options_data.get("preset_id"),
            endpoint=options_data.get("endpoint"),
            online=bool(options_data.get("online")),
            generate_off=bool(options_data.get("generate_off")),
            vpn_off=bool(options_data.get("vpn_off")),
            manual=bool(job["manual"]),
            conf_name=options_data.get("conf_name"),
        )
        username = self.secrets.decrypt(self.db.get_setting("router_username"))
        password = self.secrets.decrypt(self.db.get_setting("router_password"))
        if not username or not password:
            raise RuntimeError("Сначала сохраните общие учётные данные роутеров в настройках.")
        credentials = RouterCredentials(username, password)

        preset_content = None
        if options.preset_id:
            preset = self.db.get_preset(options.preset_id)
            if not preset:
                raise RuntimeError("Выбранный пресет больше не существует.")
            preset_content = preset["content"]
        conf_source = Path(options_data["conf_path"]) if options_data.get("conf_path") else None
        if options.action == "install" and (not conf_source or not conf_source.exists()):
            raise RuntimeError("Загруженный WireGuard-конфиг не найден.")

        job_dir = self.jobs_dir / str(job_id)
        executor = IsolatedCliExecutor(
            self.project_dir,
            job_dir,
            lambda event: self._emit(job_id, event),
        )
        try:
            iterations = int(options_data.get("retry_iterations", 1))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Некорректное количество прогонов.") from exc
        if not 1 <= iterations <= 20:
            raise RuntimeError("Количество прогонов должно быть от 1 до 20.")

        failed = 0
        targets = self.db.get_job_targets(job_id)
        total_runs = max(len(targets) * iterations, 1)
        run_index = 0
        try:
            preset_path, _ = executor.prepare(preset_content, conf_source)
            for iteration in range(1, iterations + 1):
                iteration_failed = 0
                if iterations > 1:
                    self.db.add_event(
                        job_id,
                        "info",
                        "iteration",
                        f"Прогон {iteration} из {iterations}.",
                        percent=int(run_index / total_runs * 100),
                    )
                for index, row in enumerate(targets):
                    current = self.db.get_job(job_id)
                    if current["cancel_requested"]:
                        self._cancel_remaining(job_id, targets[index:])
                        self.db.update_job(job_id, status="cancelled", finished_at=utc_now())
                        self.db.add_event(
                            job_id,
                            "warning",
                            "finish",
                            "Задача отменена между безопасными этапами.",
                        )
                        return
                    if job["manual"]:
                        self.db.update_target(row["id"], "waiting")
                        self.db.update_job(job_id, status="waiting", awaiting_confirmation=1)
                        self.db.add_event(
                            job_id,
                            "warning",
                            "manual",
                            f"Ожидается подтверждение перед роутером {row['name']}.",
                            row["name"],
                        )
                        while not self._stop.is_set():
                            current = self.db.get_job(job_id)
                            if current["cancel_requested"] or not current["awaiting_confirmation"]:
                                break
                            self._wake.wait(0.5)
                            self._wake.clear()
                        if current["cancel_requested"]:
                            self._cancel_remaining(job_id, targets[index:])
                            self.db.update_job(
                                job_id,
                                status="cancelled",
                                finished_at=utc_now(),
                                awaiting_confirmation=0,
                            )
                            return

                    self.db.update_job(job_id, status="running", awaiting_confirmation=0)
                    self.db.update_target(row["id"], "running")
                    target = RouterTarget(row["router_id"], row["name"], row["address"])
                    percent = int(run_index / total_runs * 100)
                    suffix = f" (прогон {iteration}/{iterations})" if iterations > 1 else ""
                    self.db.add_event(
                        job_id,
                        "info",
                        "target",
                        f"Начинаю {row['name']}{suffix}.",
                        row["name"],
                        percent,
                    )
                    code = executor.run(
                        target,
                        credentials,
                        options,
                        preset_path,
                        generate_off=run_index > 0,
                    )
                    run_index += 1
                    if code == 0:
                        self.db.update_target(row["id"], "success")
                        self.db.add_event(
                            job_id,
                            "success",
                            "target",
                            f"{row['name']}{suffix}: успешно.",
                            row["name"],
                        )
                    else:
                        iteration_failed += 1
                        error = f"Процесс завершился с кодом {code}."
                        self.db.update_target(row["id"], "failed", error)
                        self.db.add_event(
                            job_id,
                            "error",
                            "target",
                            f"{row['name']}{suffix}: {error}",
                            row["name"],
                        )
                failed = iteration_failed
        finally:
            if conf_source:
                conf_source.unlink(missing_ok=True)
            shutil.rmtree(job_dir, ignore_errors=True)

        status = "failed" if failed else "success"
        error = f"Не выполнено целей: {failed}." if failed else None
        self.db.update_job(job_id, status=status, error=error, finished_at=utc_now())
        level = "error" if failed else "success"
        self.db.add_event(job_id, level, "finish", error or "Задача успешно завершена.", percent=100)

    def _update_datasets(self, job_id: int) -> None:
        try:
            for index, (url, name) in enumerate(((GEOSITE_URL, "geosite.dat"), (GEOIP_URL, "geoip.dat")), start=1):
                destination = self.project_dir / name
                temporary = self.data_dir / f"{name}.download"
                self.db.add_event(
                    job_id, "info", "download", f"Скачиваю {name}…", percent=(index - 1) * 45
                )
                urllib.request.urlretrieve(url, temporary)
                os.replace(temporary, destination)
                self.db.add_event(job_id, "success", "download", f"{name} обновлён.", percent=index * 45)
        except Exception:
            for name in ("geosite.dat.download", "geoip.dat.download"):
                (self.data_dir / name).unlink(missing_ok=True)
            raise
        self.db.update_job(job_id, status="success", finished_at=utc_now())
        self.db.add_event(job_id, "success", "finish", "Базы правил обновлены.", percent=100)

    def _cleanup_job_files(self, job) -> None:
        try:
            options = json.loads(job["options_json"])
            if options.get("conf_path"):
                Path(options["conf_path"]).unlink(missing_ok=True)
        except (ValueError, OSError, TypeError):
            pass
        shutil.rmtree(self.jobs_dir / str(job["id"]), ignore_errors=True)

    def _emit(self, job_id: int, event: OperationEvent) -> None:
        self.db.add_event(job_id, event.level, event.stage, event.message, event.router, event.percent)

    def _cancel_remaining(self, job_id: int, rows) -> None:
        for row in rows:
            if row["status"] in {"queued", "waiting"}:
                self.db.update_target(row["id"], "cancelled")
