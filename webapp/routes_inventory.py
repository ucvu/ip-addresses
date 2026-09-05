from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from core.presets import PresetValidationError, parse_preset, validate_router_address
from core.routers import RouterImportError, parse_router_import

from .helpers import check_csrf, flash, guard, render

router = APIRouter()


@router.get("/routers", response_class=HTMLResponse)
async def routers_page(request: Request, edit: int | None = None):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    return render(
        request,
        "routers.html",
        routers=db.list_routers(),
        selected=db.get_router(edit) if edit else None,
    )


@router.post("/routers")
async def save_router(
    request: Request,
    name: str = Form(...),
    address: str = Form(...),
    router_id: str = Form(""),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    db = request.app.state.db
    try:
        normalized = validate_router_address(address)
        if not name.strip():
            raise ValueError("Название роутера не может быть пустым.")
        db.save_router(name.strip(), normalized, int(router_id) if router_id else None)
    except (ValueError, sqlite3.IntegrityError) as exc:
        error = "Такой адрес уже сохранён." if isinstance(exc, sqlite3.IntegrityError) else str(exc)
        return render(
            request,
            "routers.html",
            routers=db.list_routers(),
            selected={"id": router_id, "name": name, "address": address},
            error=error,
            status_code=400,
        )
    flash(request, "Роутер сохранён.", "success")
    return RedirectResponse("/routers", status_code=303)


@router.post("/routers/import")
async def import_routers(
    request: Request,
    router_file: UploadFile = File(...),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid

    db = request.app.state.db
    try:
        raw = await router_file.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise RouterImportError("Файл со списком роутеров превышает 256 КБ.")
        entries = parse_router_import(raw.decode("utf-8-sig"))
        created, updated, unchanged = db.import_routers(
            [(entry.address, entry.name) for entry in entries]
        )
    except UnicodeDecodeError:
        flash(request, "Не удалось импортировать роутеры: файл должен быть в UTF-8.", "error")
    except RouterImportError as exc:
        flash(request, f"Не удалось импортировать роутеры: {exc}", "error")
    except sqlite3.IntegrityError:
        flash(
            request,
            "Не удалось импортировать роутеры: адреса должны быть уникальными.",
            "error",
        )
    else:
        flash(
            request,
            f"Импорт завершён: добавлено {created}, обновлено {updated}, "
            f"без изменений {unchanged}.",
            "success",
        )
    return RedirectResponse("/routers", status_code=303)


@router.post("/routers/{router_id}/delete")
async def delete_router(request: Request, router_id: int, csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    request.app.state.db.delete_router(router_id)
    flash(request, "Роутер удалён.", "success")
    return RedirectResponse("/routers", status_code=303)


@router.get("/presets", response_class=HTMLResponse)
async def presets_page(request: Request, edit: int | None = None):
    denied = guard(request)
    if denied:
        return denied
    db = request.app.state.db
    return render(
        request,
        "presets.html",
        presets=db.list_presets(),
        selected=db.get_preset(edit) if edit else None,
    )


@router.post("/presets")
async def save_preset(
    request: Request,
    name: str = Form(...),
    content: str = Form(...),
    preset_id: str = Form(""),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    db = request.app.state.db
    try:
        parsed = parse_preset(content, name)
        db.save_preset(parsed.name, parsed.content, int(preset_id) if preset_id else None)
    except (PresetValidationError, sqlite3.IntegrityError) as exc:
        error = "Пресет с таким названием уже существует." if isinstance(exc, sqlite3.IntegrityError) else str(exc)
        return render(
            request,
            "presets.html",
            presets=db.list_presets(),
            selected={"id": preset_id, "name": name, "content": content},
            error=error,
            status_code=400,
        )
    flash(request, "Пресет сохранён и проверен.", "success")
    return RedirectResponse("/presets", status_code=303)


@router.post("/presets/import")
async def import_preset(
    request: Request,
    preset_file: UploadFile = File(...),
    csrf: str = Form(...),
):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    try:
        raw = await preset_file.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise PresetValidationError("Файл пресета превышает 256 КБ.")
        content = raw.decode("utf-8-sig")
        parsed = parse_preset(content, Path(preset_file.filename or "preset").stem)
        request.app.state.db.save_preset(parsed.name, parsed.content)
    except (UnicodeDecodeError, PresetValidationError, sqlite3.IntegrityError) as exc:
        flash(request, f"Не удалось импортировать пресет: {exc}", "error")
    else:
        flash(request, "Пресет импортирован.", "success")
    return RedirectResponse("/presets", status_code=303)


@router.get("/presets/{preset_id}/export")
async def export_preset(request: Request, preset_id: int):
    denied = guard(request)
    if denied:
        return denied
    preset = request.app.state.db.get_preset(preset_id)
    if not preset:
        return PlainTextResponse("Пресет не найден.", status_code=404)
    filename = quote(f"{preset['name']}.txt")
    return PlainTextResponse(
        preset["content"],
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"},
    )


@router.post("/presets/{preset_id}/delete")
async def delete_preset(request: Request, preset_id: int, csrf: str = Form(...)):
    denied = guard(request)
    if denied:
        return denied
    invalid = check_csrf(request, csrf)
    if invalid:
        return invalid
    request.app.state.db.delete_preset(preset_id)
    flash(request, "Пресет удалён.", "success")
    return RedirectResponse("/presets", status_code=303)
