from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.responses import PlainTextResponse
from fastapi.templating import Jinja2Templates

from .security import csrf_token, verify_csrf

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

STATUS_LABELS = {
    "queued": "В очереди",
    "running": "Выполняется",
    "waiting": "Ожидает подтверждения",
    "success": "Успешно",
    "failed": "Ошибка",
    "cancelled": "Отменено",
    "interrupted": "Прервано",
}
FINAL_STATUSES = {"success", "failed", "cancelled", "interrupted"}


def render(request: Request, name: str, status_code: int = 200, **context):
    context.update(
        request=request,
        csrf_token=csrf_token(request.session),
        flashes=request.session.pop("flashes", []),
        status_labels=STATUS_LABELS,
    )
    return templates.TemplateResponse(request=request, name=name, context=context, status_code=status_code)


def flash(request: Request, message: str, level: str = "info") -> None:
    items = request.session.setdefault("flashes", [])
    items.append({"message": message, "level": level})
    request.session["flashes"] = items[-5:]


def guard(request: Request):
    return None


def check_csrf(request: Request, supplied: str):
    if not verify_csrf(request.session, supplied):
        return PlainTextResponse("Недействительный CSRF-токен.", status_code=403)
    return None
