from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .helpers import render

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    db = request.app.state.db
    box = request.app.state.secret_box
    credentials_ready = bool(
        box.decrypt(db.get_setting("router_username"))
        and box.decrypt(db.get_setting("router_password"))
    )
    return render(
        request,
        "dashboard.html",
        routers=db.list_routers(),
        presets=db.list_presets(),
        jobs=db.list_jobs(10),
        credentials_ready=credentials_ready,
    )


@router.get("/setup")
@router.get("/login")
async def legacy_auth_redirect():
    return RedirectResponse("/", status_code=303)
