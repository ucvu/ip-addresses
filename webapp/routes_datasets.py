from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from generate_geo_domains import parse_geoip_list, parse_geosite_list

from .helpers import check_csrf, flash, guard, render

router = APIRouter()


@router.get("/datasets", response_class=HTMLResponse)
async def datasets_page(request: Request):
    denied = guard(request)
    if denied:
        return denied
    return render(
        request,
        "datasets.html",
        files=_dataset_info(request.app.state.config.project_dir),
        results=None,
    )


@router.post("/datasets/search", response_class=HTMLResponse)
async def search_datasets(request: Request, query: str = Form(...), csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    try:
        results = _search_categories(request.app.state.config.project_dir, query)
        error = None
    except (ValueError, OSError) as exc:
        results, error = [], str(exc)
    return render(
        request,
        "datasets.html",
        files=_dataset_info(request.app.state.config.project_dir),
        results=results,
        query=query,
        error=error,
        status_code=400 if error else 200,
    )


@router.post("/datasets/update")
async def update_datasets(request: Request, csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    db = request.app.state.db
    job_id = db.create_job("dataset_update", {}, [])
    db.add_event(job_id, "info", "queue", "Обновление баз добавлено в очередь.")
    request.app.state.jobs.notify()
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    box = request.app.state.secret_box
    username = box.decrypt(db.get_setting("router_username")) or ""
    return render(
        request,
        "settings.html",
        router_username=username,
        credentials_ready=bool(username and box.decrypt(db.get_setting("router_password"))),
        host=request.app.state.config.host,
        port=request.app.state.config.port,
    )


@router.post("/settings/credentials")
async def save_credentials(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    db = request.app.state.db
    box = request.app.state.secret_box
    if not username.strip() or not password:
        flash(request, "Логин и пароль не могут быть пустыми.", "error")
    else:
        db.set_setting("router_username", box.encrypt(username.strip()))
        db.set_setting("router_password", box.encrypt(password))
        flash(request, "Учётные данные роутеров сохранены в зашифрованном виде.", "success")
    return RedirectResponse("/settings", status_code=303)


def _dataset_info(project_dir: Path) -> list[dict[str, object]]:
    result = []
    for name in ("geosite.dat", "geoip.dat"):
        path = project_dir / name
        stat = path.stat() if path.exists() else None
        result.append(
            {
                "name": name,
                "exists": bool(stat),
                "size": stat.st_size if stat else 0,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%d.%m.%Y %H:%M") if stat else "—",
            }
        )
    return result


def _search_categories(project_dir: Path, query: str) -> list[dict[str, object]]:
    query = query.strip()
    if not query:
        raise ValueError("Введите часть названия категории.")
    geosite_path, geoip_path = project_dir / "geosite.dat", project_dir / "geoip.dat"
    if not geosite_path.exists() or not geoip_path.exists():
        raise ValueError("Сначала загрузите обе базы правил.")
    geosite = parse_geosite_list(geosite_path.read_bytes())
    geoip = parse_geoip_list(geoip_path.read_bytes())
    needle = query.upper()
    results = [
        {"source": "geosite", "name": name.lower(), "count": len(values)}
        for name, values in geosite.items()
        if needle in name
    ]
    results.extend(
        {"source": "geoip", "name": name.lower(), "count": len(values)}
        for name, values in geoip.items()
        if needle in name
    )
    return sorted(results, key=lambda item: (item["source"], item["name"]))[:200]
