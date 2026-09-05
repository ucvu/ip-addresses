import json
import re

from fastapi.testclient import TestClient

from webapp.app import create_app
from webapp.config import AppConfig


def token(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_dashboard_and_router_crud_without_auth(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "preset-services-only.txt").write_text(
        "mode: proxy\ngeosite:openai\n", encoding="utf-8"
    )
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "Netcraze WireGuard" in dashboard.text
        routers = client.get("/routers")
        saved = client.post(
            "/routers",
            data={
                "csrf": token(routers.text),
                "name": "Home",
                "address": "192.168.1.1",
                "router_id": "",
            },
            follow_redirects=False,
        )
        assert saved.status_code == 303
        assert "192.168.1.1" in client.get("/routers").text


def test_post_without_csrf_is_rejected(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        response = client.post(
            "/routers",
            data={"name": "Home", "address": "192.168.1.1", "router_id": ""},
        )
        assert response.status_code == 422


def test_legacy_auth_pages_redirect_to_dashboard(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        assert client.get("/login", follow_redirects=False).headers["location"] == "/"
        assert client.get("/setup", follow_redirects=False).headers["location"] == "/"
        settings = client.get("/settings")
        assert "Пароль администратора" not in settings.text


def test_operation_without_router_shows_html_validation_error(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "preset-services-only.txt").write_text(
        "mode: proxy\ngeosite:openai\n", encoding="utf-8"
    )
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        operations = client.get("/operations")
        response = client.post(
            "/operations",
            data={"csrf": token(operations.text), "action": "update", "preset_id": "1"},
        )
        assert response.status_code == 400
        assert response.headers["content-type"].startswith("text/html")
        assert "Выберите хотя бы один существующий роутер" in response.text


def test_legacy_admin_hash_is_removed(tmp_path):
    from webapp.database import Database

    project = tmp_path / "project"
    project.mkdir()
    data_dir = tmp_path / "data"
    database = Database(data_dir / "webapp.sqlite3")
    database.set_setting("admin_password", "obsolete-hash")
    app = create_app(AppConfig(project_dir=project, data_dir=data_dir), start_worker=False)
    assert app.state.db.get_setting("admin_password") is None

def test_router_list_import_creates_and_updates_routers(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        page = client.get("/routers")
        response = client.post(
            "/routers/import",
            data={"csrf": token(page.text)},
            files={
                "router_file": (
                    "routers.txt",
                    "192.168.1.1 Дом\nrouter.example.com\n".encode("utf-8"),
                    "text/plain",
                )
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "добавлено 2" in response.text
        assert "Дом" in response.text
        assert "router.example.com" in response.text

        response = client.post(
            "/routers/import",
            data={"csrf": token(response.text)},
            files={
                "router_file": (
                    "routers.txt",
                    "192.168.1.1 Главный роутер\nrouter.example.com\n".encode("utf-8"),
                    "text/plain",
                )
            },
            follow_redirects=True,
        )
        assert "обновлено 1" in response.text
        assert "без изменений 1" in response.text
        assert "Главный роутер" in response.text


def test_invalid_router_list_is_not_partially_imported(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    with TestClient(app) as client:
        page = client.get("/routers")
        response = client.post(
            "/routers/import",
            data={"csrf": token(page.text)},
            files={
                "router_file": (
                    "routers.txt",
                    b"192.168.1.1 Home\nnot/a/router\n",
                    "text/plain",
                )
            },
            follow_redirects=True,
        )
        assert "Строка 2" in response.text
        assert app.state.db.list_routers() == []

def test_retry_form_selects_failed_routers_and_iterations(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
    ]
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id) for router_id in router_ids],
    )
    failed_targets = db.get_job_targets(job_id)
    for target in failed_targets:
        db.update_target(target["id"], "failed", "test")
    db.update_job(job_id, status="failed")

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        for target in failed_targets:
            assert f'name="target_ids" value="{target["id"]}" checked' in page.text
        assert 'name="iterations" value="1"' in page.text

        empty = client.post(
            f"/jobs/{job_id}/retry",
            data={"csrf": token(page.text), "iterations": "2"},
            follow_redirects=False,
        )
        assert empty.status_code == 303
        assert empty.headers["location"] == f"/jobs/{job_id}"
        assert len(db.list_jobs()) == 1

        selected = client.post(
            f"/jobs/{job_id}/retry",
            data={
                "csrf": token(page.text),
                "target_ids": str(failed_targets[1]["id"]),
                "iterations": "3",
            },
            follow_redirects=False,
        )
        assert selected.status_code == 303
        retry_id = int(selected.headers["location"].rsplit("/", 1)[1])
        retry_targets = db.get_job_targets(retry_id)
        assert len(retry_targets) == 1
        assert retry_targets[0]["router_id"] == router_ids[1]
        assert len(db.get_job_targets(job_id)) == 2
        assert json.loads(db.get_job(retry_id)["options_json"])["retry_iterations"] == 3

def test_operations_page_has_router_search_and_select_all(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    app.state.db.save_router("Home Router", "192.168.1.1")
    app.state.db.save_router("Office Router", "router.office.example")

    with TestClient(app) as client:
        response = client.get("/operations")

    assert response.status_code == 200
    assert 'id="router-search"' in response.text
    assert 'id="select-all-routers"' in response.text
    assert 'data-search="Home Router 192.168.1.1"' in response.text
    assert 'data-search="Office Router router.office.example"' in response.text
    assert "visibleRouterInputs()" in response.text
    assert "selectAll.disabled=action.value==='install'" in response.text

def test_interrupted_job_page_can_restart_selected_targets(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
    ]
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id) for router_id in router_ids],
    )
    targets = db.get_job_targets(job_id)
    db.update_target(targets[0]["id"], "success")
    db.update_target(targets[1]["id"], "interrupted")
    db.update_job(job_id, status="interrupted", error="restart")

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        assert "Начать проход заново" in page.text
        assert f'name="target_ids" value="{targets[0]["id"]}">' in page.text
        assert f'name="target_ids" value="{targets[0]["id"]}" checked' not in page.text
        assert f'name="target_ids" value="{targets[1]["id"]}" checked' in page.text
        assert 'id="retry-select-all"' in page.text
        assert 'id="retry-clear-all"' in page.text

        response = client.post(
            f"/jobs/{job_id}/retry",
            data={
                "csrf": token(page.text),
                "target_ids": str(targets[1]["id"]),
                "iterations": "1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    retry_id = int(response.headers["location"].rsplit("/", 1)[1])
    restarted = db.get_job_targets(retry_id)
    assert len(restarted) == 1
    assert restarted[0]["router_id"] == router_ids[1]
    assert len(db.get_job_targets(job_id)) == 2


def test_job_state_returns_current_router_statuses(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_id = db.save_router("Router A", "192.168.1.1")
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id)],
    )
    target = db.get_job_targets(job_id)[0]

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        assert f'data-target-id="{target["id"]}"' in page.text
        assert f"/jobs/{job_id}/state" in page.text

        db.update_target(target["id"], "running")
        db.update_job(job_id, status="running")
        state = client.get(f"/jobs/{job_id}/state")

    assert state.status_code == 200
    assert state.json()["status"] == "running"
    assert state.json()["targets"] == [
        {"id": target["id"], "status": "running", "error": None}
    ]

def test_cancelled_job_uses_same_restart_selection_as_interrupted(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_ids = [
        db.save_router("Router A", "192.168.1.1"),
        db.save_router("Router B", "192.168.1.2"),
    ]
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id) for router_id in router_ids],
    )
    targets = db.get_job_targets(job_id)
    db.update_target(targets[0]["id"], "success")
    db.update_target(targets[1]["id"], "cancelled")
    db.update_job(job_id, status="cancelled")

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        assert "Начать проход заново" in page.text
        assert f'name="target_ids" value="{targets[0]["id"]}">' in page.text
        assert f'name="target_ids" value="{targets[0]["id"]}" checked' not in page.text
        assert f'name="target_ids" value="{targets[1]["id"]}" checked' in page.text
        assert 'id="retry-select-all"' in page.text
        assert 'id="retry-clear-all"' in page.text

        response = client.post(
            f"/jobs/{job_id}/retry",
            data={
                "csrf": token(page.text),
                "target_ids": str(targets[1]["id"]),
                "iterations": "2",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    retry_id = int(response.headers["location"].rsplit("/", 1)[1])
    restarted = db.get_job_targets(retry_id)
    assert len(restarted) == 1
    assert restarted[0]["router_id"] == router_ids[1]
    assert json.loads(db.get_job(retry_id)["options_json"])["retry_iterations"] == 2
    assert [target["status"] for target in db.get_job_targets(job_id)] == [
        "success",
        "cancelled",
    ]

def test_job_actions_switch_from_cancel_to_retry_after_failure(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_id = db.save_router("Router A", "192.168.1.1")
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id)],
    )
    target = db.get_job_targets(job_id)[0]

    with TestClient(app) as client:
        running_page = client.get(f"/jobs/{job_id}")
        assert f'action="/jobs/{job_id}/cancel"' in running_page.text

        db.update_target(target["id"], "failed", "test")
        db.update_job(job_id, status="failed", error="test")
        actions = client.get(f"/jobs/{job_id}/actions")

    assert actions.status_code == 200
    assert f'action="/jobs/{job_id}/cancel"' not in actions.text
    assert f'action="/jobs/{job_id}/retry"' in actions.text
    assert "Повторить неудачные" in actions.text


def test_job_state_refreshes_expired_csrf_before_action(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    app = create_app(AppConfig(project_dir=project, data_dir=tmp_path / "data"), start_worker=False)
    db = app.state.db
    router_id = db.save_router("Router A", "192.168.1.1")
    job_id = db.create_job(
        "endpoint",
        {"endpoint": "vpn.example.com:51820"},
        [db.get_router(router_id)],
    )

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        stale_token = token(page.text)
        client.cookies.clear()
        state = client.get(f"/jobs/{job_id}/state")
        fresh_token = state.json()["csrf_token"]
        response = client.post(
            f"/jobs/{job_id}/cancel",
            data={"csrf": fresh_token},
            follow_redirects=False,
        )

    assert fresh_token != stale_token
    assert response.status_code == 303
    assert response.headers["location"] == f"/jobs/{job_id}"
