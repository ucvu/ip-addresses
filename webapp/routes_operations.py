from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse

from core.presets import validate_endpoint

from .helpers import FINAL_STATUSES, check_csrf, flash, guard, render, templates
from .security import csrf_token

router = APIRouter()


@router.get("/operations", response_class=HTMLResponse)
async def operations_page(request: Request):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    return render(request, "operations.html", routers=db.list_routers(), presets=db.list_presets())


@router.post("/operations")
async def create_operation(
    request: Request,
    action: str = Form(...),
    router_ids: list[int] | None = Form(None),
    preset_id: str = Form(""),
    endpoint: str = Form(""),
    online: str = Form(""),
    generate_off: str = Form(""),
    vpn_off: str = Form(""),
    manual: str = Form(""),
    confirm_destructive: str = Form(""),
    conf_file: UploadFile | None = File(None),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    db = request.app.state.db
    config = request.app.state.config
    staged: Path | None = None
    try:
        if action not in {"install", "update", "endpoint"}:
            raise ValueError("Неизвестная операция.")
        targets = [db.get_router(router_id) for router_id in (router_ids or [])]
        if not targets or any(target is None for target in targets):
            raise ValueError("Выберите хотя бы один существующий роутер.")
        if action == "install" and len(targets) != 1:
            raise ValueError("Первичную установку можно запускать только для одного роутера.")
        options: dict[str, object] = {
            "online": bool(online),
            "generate_off": bool(generate_off),
            "vpn_off": bool(vpn_off),
        }
        if action in {"install", "update"}:
            if not confirm_destructive:
                raise ValueError("Подтвердите удаление существующих списков и DNS-маршрутов.")
            if not preset_id or not db.get_preset(int(preset_id)):
                raise ValueError("Выберите существующий пресет.")
            options["preset_id"] = int(preset_id)
        if action == "endpoint":
            options["endpoint"] = validate_endpoint(endpoint)
        if action == "install":
            if not conf_file or not conf_file.filename or Path(conf_file.filename).suffix.lower() != ".conf":
                raise ValueError("Для установки загрузите файл с расширением .conf.")
            payload = await conf_file.read(256 * 1024 + 1)
            if len(payload) > 256 * 1024:
                raise ValueError("WireGuard-конфигурация превышает 256 КБ.")
            staged = config.data_dir / "uploads" / f"{uuid4().hex}.conf"
            staged.write_bytes(payload)
            options["conf_path"] = str(staged)
            options["conf_name"] = Path(conf_file.filename).name
        job_id = db.create_job(action, options, targets, bool(manual))
        db.add_event(job_id, "info", "queue", "Задача добавлена в очередь.")
        request.app.state.jobs.notify()
    except (ValueError, TypeError) as exc:
        if staged:
            staged.unlink(missing_ok=True)
        return render(
            request,
            "operations.html",
            routers=db.list_routers(),
            presets=db.list_presets(),
            error=str(exc),
            status_code=400,
        )
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.get("/jobs", response_class=HTMLResponse)
async def jobs_page(request: Request):
    denied = guard(request)
    if denied:
        return denied
    return render(request, "jobs.html", jobs=request.app.state.db.list_jobs())


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail(request: Request, job_id: int):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        return PlainTextResponse("Задача не найдена.", status_code=404)
    targets = db.get_job_targets(job_id)
    retry_targets = targets if job["status"] in {"interrupted", "cancelled"} else [
        target for target in targets if target["status"] == "failed"
    ]
    return render(
        request,
        "job_detail.html",
        job=job,
        targets=targets,
        retry_targets=retry_targets,
        events=db.get_events(job_id),
        final_statuses=FINAL_STATUSES,
    )


@router.get("/jobs/{job_id}/state")
async def job_state(request: Request, job_id: int):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        return PlainTextResponse("Задача не найдена.", status_code=404)
    return {
        "status": job["status"],
        "error": job["error"],
        "csrf_token": csrf_token(request.session),
        "targets": [
            {
                "id": target["id"],
                "status": target["status"],
                "error": target["error"],
            }
            for target in db.get_job_targets(job_id)
        ],
    }


@router.get("/jobs/{job_id}/actions", response_class=HTMLResponse)
async def job_actions(request: Request, job_id: int):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        return PlainTextResponse("Задача не найдена.", status_code=404)
    targets = db.get_job_targets(job_id)
    retry_targets = targets if job["status"] in {"interrupted", "cancelled"} else [
        target for target in targets if target["status"] == "failed"
    ]
    return templates.TemplateResponse(
        request=request,
        name="_job_actions.html",
        context={
            "request": request,
            "job": job,
            "retry_targets": retry_targets,
            "final_statuses": FINAL_STATUSES,
            "csrf_token": csrf_token(request.session),
        },
    )


@router.get("/jobs/{job_id}/events")
async def job_events(request: Request, job_id: int):
    denied = guard(request)
    if denied:
        return PlainTextResponse("Требуется вход.", status_code=401)
    db = request.app.state.db
    if not db.get_job(job_id):
        return PlainTextResponse("Задача не найдена.", status_code=404)
    try:
        initial = int(request.headers.get("last-event-id", "0"))
    except ValueError:
        initial = 0

    async def stream():
        last_id = initial
        idle = 0
        while True:
            if await request.is_disconnected():
                return
            events = db.get_events(job_id, last_id)
            for event in events:
                last_id = event["id"]
                yield f"id: {last_id}\ndata: {json.dumps(dict(event), ensure_ascii=False)}\n\n"
            job = db.get_job(job_id)
            if job and job["status"] in FINAL_STATUSES and not events:
                yield f"event: done\ndata: {json.dumps({'status': job['status']})}\n\n"
                return
            idle += 1
            if idle % 15 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(request: Request, job_id: int, csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    request.app.state.jobs.request_cancel(job_id)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.post("/jobs/{job_id}/confirm")
async def confirm_job(request: Request, job_id: int, csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    request.app.state.jobs.confirm_next(job_id)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.post("/jobs/{job_id}/retry")
async def retry_job(
    request: Request,
    job_id: int,
    target_ids: list[int] | None = Form(None),
    iterations: int = Form(1),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    try:
        new_id = request.app.state.jobs.retry_failed(job_id, target_ids or [], iterations)
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)
    return RedirectResponse(f"/jobs/{new_id}", status_code=303)
