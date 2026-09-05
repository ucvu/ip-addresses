from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self.migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def migrate(self) -> None:
        with self._write_lock, self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version < 1:
                connection.executescript(
                    """
                    CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE routers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        address TEXT NOT NULL UNIQUE,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE presets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        content TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE jobs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        options_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        finished_at TEXT,
                        cancel_requested INTEGER NOT NULL DEFAULT 0,
                        manual INTEGER NOT NULL DEFAULT 0,
                        awaiting_confirmation INTEGER NOT NULL DEFAULT 0,
                        error TEXT
                    );
                    CREATE TABLE job_targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        router_id INTEGER,
                        name TEXT NOT NULL,
                        address TEXT NOT NULL,
                        position INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'queued',
                        error TEXT
                    );
                    CREATE TABLE job_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        created_at TEXT NOT NULL,
                        level TEXT NOT NULL,
                        stage TEXT NOT NULL,
                        router TEXT,
                        message TEXT NOT NULL,
                        percent INTEGER
                    );
                    CREATE INDEX idx_jobs_status ON jobs(status, id);
                    CREATE INDEX idx_events_job ON job_events(job_id, id);
                    PRAGMA user_version = 1;
                    """
                )

    def get_setting(self, key: str) -> str | None:
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def delete_setting(self, key: str) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute("DELETE FROM settings WHERE key = ?", (key,))

    def list_routers(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM routers ORDER BY name COLLATE NOCASE").fetchall()

    def get_router(self, router_id: int) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()

    def save_router(self, name: str, address: str, router_id: int | None = None) -> int:
        now = utc_now()
        with self._write_lock, self.connect() as connection:
            if router_id is None:
                cursor = connection.execute(
                    "INSERT INTO routers(name, address, created_at, updated_at) VALUES(?, ?, ?, ?)",
                    (name, address, now, now),
                )
                return int(cursor.lastrowid)
            connection.execute(
                "UPDATE routers SET name = ?, address = ?, updated_at = ? WHERE id = ?",
                (name, address, now, router_id),
            )
            return router_id

    def import_routers(self, routers: list[tuple[str, str | None]]) -> tuple[int, int, int]:
        """Добавляет и обновляет роутеры одной транзакцией."""
        now = utc_now()
        created = updated = unchanged = 0
        with self._write_lock, self.connect() as connection:
            existing = {
                row["address"]: row
                for row in connection.execute("SELECT * FROM routers").fetchall()
            }
            for address, name in routers:
                current = existing.get(address)
                if current is None:
                    connection.execute(
                        "INSERT INTO routers(name, address, created_at, updated_at) VALUES(?, ?, ?, ?)",
                        (name or address, address, now, now),
                    )
                    created += 1
                elif name and name != current["name"]:
                    connection.execute(
                        "UPDATE routers SET name = ?, updated_at = ? WHERE id = ?",
                        (name, now, current["id"]),
                    )
                    updated += 1
                else:
                    unchanged += 1
        return created, updated, unchanged

    def delete_router(self, router_id: int) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute("DELETE FROM routers WHERE id = ?", (router_id,))

    def list_presets(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM presets ORDER BY name COLLATE NOCASE").fetchall()

    def get_preset(self, preset_id: int) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM presets WHERE id = ?", (preset_id,)).fetchone()

    def save_preset(self, name: str, content: str, preset_id: int | None = None) -> int:
        now = utc_now()
        with self._write_lock, self.connect() as connection:
            if preset_id is None:
                cursor = connection.execute(
                    "INSERT INTO presets(name, content, created_at, updated_at) VALUES(?, ?, ?, ?)",
                    (name, content, now, now),
                )
                return int(cursor.lastrowid)
            connection.execute(
                "UPDATE presets SET name = ?, content = ?, updated_at = ? WHERE id = ?",
                (name, content, now, preset_id),
            )
            return preset_id

    def delete_preset(self, preset_id: int) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute("DELETE FROM presets WHERE id = ?", (preset_id,))

    def create_job(self, job_type: str, options: dict[str, Any], targets: list[sqlite3.Row | dict[str, Any]], manual: bool = False) -> int:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO jobs(type, status, options_json, created_at, manual) VALUES(?, 'queued', ?, ?, ?)",
                (job_type, json.dumps(options, ensure_ascii=False), utc_now(), int(manual)),
            )
            job_id = int(cursor.lastrowid)
            for position, target in enumerate(targets, start=1):
                keys = set(target.keys())
                target_id = target["router_id"] if "router_id" in keys else (target["id"] if "id" in keys else None)
                connection.execute(
                    "INSERT INTO job_targets(job_id, router_id, name, address, position) VALUES(?, ?, ?, ?, ?)",
                    (job_id, target_id, target["name"], target["address"], position),
                )
            return job_id

    def list_jobs(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT j.*, COUNT(t.id) AS target_count, "
                "SUM(CASE WHEN t.status = 'failed' THEN 1 ELSE 0 END) AS failed_count "
                "FROM jobs j LEFT JOIN job_targets t ON t.job_id = j.id "
                "GROUP BY j.id ORDER BY j.id DESC LIMIT ?",
                (limit,),
            ).fetchall()

    def get_job(self, job_id: int) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()

    def get_job_targets(self, job_id: int, status: str | None = None) -> list[sqlite3.Row]:
        with self.connect() as connection:
            if status:
                return connection.execute(
                    "SELECT * FROM job_targets WHERE job_id = ? AND status = ? ORDER BY position",
                    (job_id, status),
                ).fetchall()
            return connection.execute(
                "SELECT * FROM job_targets WHERE job_id = ? ORDER BY position", (job_id,)
            ).fetchall()

    def next_queued_job(self) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()

    def update_job(self, job_id: int, **values: Any) -> None:
        if not values:
            return
        allowed = {"status", "started_at", "finished_at", "cancel_requested", "awaiting_confirmation", "error"}
        if not set(values) <= allowed:
            raise ValueError("Недопустимое поле задачи")
        assignments = ", ".join(f"{key} = ?" for key in values)
        with self._write_lock, self.connect() as connection:
            connection.execute(f"UPDATE jobs SET {assignments} WHERE id = ?", (*values.values(), job_id))

    def replace_job_options(self, job_id: int, options: dict[str, Any]) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET options_json = ? WHERE id = ?",
                (json.dumps(options, ensure_ascii=False), job_id),
            )

    def update_target(self, target_id: int, status: str, error: str | None = None) -> None:
        with self._write_lock, self.connect() as connection:
            connection.execute(
                "UPDATE job_targets SET status = ?, error = ? WHERE id = ?", (status, error, target_id)
            )

    def add_event(self, job_id: int, level: str, stage: str, message: str, router: str | None = None, percent: int | None = None) -> int:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO job_events(job_id, created_at, level, stage, router, message, percent) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (job_id, utc_now(), level, stage, router, message, percent),
            )
            return int(cursor.lastrowid)

    def get_events(self, job_id: int, after_id: int = 0) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM job_events WHERE job_id = ? AND id > ? ORDER BY id", (job_id, after_id)
            ).fetchall()

    def interrupt_running_jobs(self) -> int:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET status = 'interrupted', finished_at = ?, "
                "error = 'Приложение было перезапущено во время выполнения.' "
                "WHERE status IN ('running', 'waiting')",
                (utc_now(),),
            )
            connection.execute(
                "UPDATE job_targets SET status = 'interrupted' WHERE status = 'running'"
            )
            return cursor.rowcount
