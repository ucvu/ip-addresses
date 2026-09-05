import json

from webapp.database import Database


def test_database_crud_and_queue(tmp_path):
    db = Database(tmp_path / "app.sqlite3")
    router_id = db.save_router("Home", "192.168.1.1")
    preset_id = db.save_preset("Proxy", "mode: proxy\ngeosite:openai\n")
    router = db.get_router(router_id)
    job_id = db.create_job("update", {"preset_id": preset_id}, [router])
    assert db.next_queued_job()["id"] == job_id
    assert db.get_job_targets(job_id)[0]["address"] == "192.168.1.1"
    db.add_event(job_id, "info", "test", "hello")
    assert db.get_events(job_id)[0]["message"] == "hello"


def test_running_jobs_are_interrupted_after_restart(tmp_path):
    db = Database(tmp_path / "app.sqlite3")
    job_id = db.create_job("dataset_update", {}, [])
    db.update_job(job_id, status="running")
    assert db.interrupt_running_jobs() == 1
    assert db.get_job(job_id)["status"] == "interrupted"


def test_retry_preserves_router_identity(tmp_path):
    from webapp.jobs import JobManager
    from webapp.security import SecretBox

    db = Database(tmp_path / "app.sqlite3")
    router_id = db.save_router("Home", "192.168.1.1")
    job_id = db.create_job("update", {"preset_id": 1}, [db.get_router(router_id)])
    target = db.get_job_targets(job_id)[0]
    db.update_target(target["id"], "failed", "test")
    manager = JobManager(db, SecretBox(tmp_path / "key"), tmp_path, tmp_path)
    retry_id = manager.retry_failed(job_id)
    assert db.get_job_targets(retry_id)[0]["router_id"] == router_id


def test_worker_removes_conf_after_preflight_failure(tmp_path):
    import time
    from webapp.jobs import JobManager
    from webapp.security import SecretBox

    db = Database(tmp_path / "app.sqlite3")
    router_id = db.save_router("Home", "192.168.1.1")
    conf = tmp_path / "upload.conf"
    conf.write_text("[Interface]\nPrivateKey=x\n", encoding="utf-8")
    job_id = db.create_job(
        "install",
        {"preset_id": 999, "conf_path": str(conf)},
        [db.get_router(router_id)],
    )
    manager = JobManager(db, SecretBox(tmp_path / "key"), tmp_path, tmp_path)
    manager.start()
    deadline = time.time() + 3
    while db.get_job(job_id)["status"] not in {"failed", "success"} and time.time() < deadline:
        time.sleep(0.05)
    manager.stop()
    assert db.get_job(job_id)["status"] == "failed"
    assert not conf.exists()

def test_retry_can_select_targets_and_store_iteration_count(tmp_path):
    from webapp.jobs import JobManager
    from webapp.security import SecretBox

    db = Database(tmp_path / "app.sqlite3")
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
        db.save_router("Router C", "192.168.1.3"),
    ]
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id) for router_id in router_ids],
    )
    original_targets = db.get_job_targets(job_id)
    for target in original_targets:
        db.update_target(target["id"], "failed", "test")

    manager = JobManager(db, SecretBox(tmp_path / "key"), tmp_path, tmp_path)
    retry_id = manager.retry_failed(
        job_id,
        [original_targets[0]["id"], original_targets[2]["id"]],
        iterations=3,
    )

    retried = db.get_job_targets(retry_id)
    assert [target["router_id"] for target in retried] == [router_ids[0], router_ids[2]]
    assert len(db.get_job_targets(job_id)) == 3
    assert json.loads(db.get_job(retry_id)["options_json"])["retry_iterations"] == 3


def test_worker_runs_every_selected_router_on_every_iteration(tmp_path, monkeypatch):
    from webapp.jobs import JobManager
    from webapp.security import SecretBox

    calls = []

    class Executor:
        def __init__(self, project_dir, job_dir, emit):
            pass

        def prepare(self, preset_content, conf_source):
            return None, None

        def run(self, target, credentials, options, preset_path, generate_off=False):
            calls.append((target.id, generate_off))
            return 0

    monkeypatch.setattr("webapp.jobs.IsolatedCliExecutor", Executor)
    db = Database(tmp_path / "app.sqlite3")
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
    ]
    box = SecretBox(tmp_path / "key")
    db.set_setting("router_username", box.encrypt("admin"))
    db.set_setting("router_password", box.encrypt("password"))
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820", "retry_iterations": 3},
        [db.get_router(router_id) for router_id in router_ids],
    )
    manager = JobManager(db, box, tmp_path, tmp_path)

    manager._process_job(db.get_job(job_id))

    assert [router_id for router_id, _ in calls] == router_ids * 3
    assert [generate_off for _, generate_off in calls] == [False, True, True, True, True, True]
    assert db.get_job(job_id)["status"] == "success"
    assert all(target["status"] == "success" for target in db.get_job_targets(job_id))

def test_interrupted_job_can_restart_selected_original_targets(tmp_path):
    from webapp.jobs import JobManager
    from webapp.security import SecretBox

    db = Database(tmp_path / "app.sqlite3")
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
        db.save_router("Router C", "192.168.1.3"),
    ]
    job_id = db.create_job(
        "update",
        {"preset_id": 1},
        [db.get_router(router_id) for router_id in router_ids],
    )
    original = db.get_job_targets(job_id)
    db.update_target(original[0]["id"], "success")
    db.update_target(original[1]["id"], "interrupted")
    db.update_job(job_id, status="interrupted")
    manager = JobManager(db, SecretBox(tmp_path / "key"), tmp_path, tmp_path)

    retry_id = manager.retry_failed(
        job_id,
        [original[0]["id"], original[2]["id"]],
    )

    restarted = db.get_job_targets(retry_id)
    assert [target["router_id"] for target in restarted] == [router_ids[0], router_ids[2]]
    assert [target["status"] for target in db.get_job_targets(job_id)] == [
        "success",
        "interrupted",
        "queued",
    ]
