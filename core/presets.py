from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .models import Preset


class PresetValidationError(ValueError):
    """Ошибка формата пользовательского пресета."""


_ENDPOINT_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[^:\s]+):(\d{1,5})$")


def parse_preset(content: str, name: str = "Пресет") -> Preset:
    lines = content.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    first_meaningful = next((line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")), "")
    if not first_meaningful.lower().startswith("mode:"):
        raise PresetValidationError("Первая содержательная строка должна быть 'mode: direct' или 'mode: proxy'.")
    mode = first_meaningful.split(":", 1)[1].strip().lower()
    if mode not in {"direct", "proxy"}:
        raise PresetValidationError("Режим должен быть direct или proxy.")

    entries: list[str] = []
    mode_seen = False
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("mode:"):
            if mode_seen:
                raise PresetValidationError(f"Строка {number}: режим можно указать только один раз.")
            mode_seen = True
            continue
        source, separator, value = line.partition(":")
        if not separator or source.lower() not in {"geosite", "geoip", "domain"}:
            raise PresetValidationError(
                f"Строка {number}: ожидается geosite:name, geoip:name или domain:value."
            )
        if not value.strip():
            raise PresetValidationError(f"Строка {number}: значение после двоеточия не может быть пустым.")
        entries.append(f"{source.lower()}:{value.strip()}")
    if not entries:
        raise PresetValidationError("В пресете должна быть хотя бы одна запись.")

    normalized = "\n".join(lines).strip() + "\n"
    return Preset(name=name.strip() or "Пресет", mode=mode, entries=tuple(entries), content=normalized)


def validate_endpoint(value: str) -> str:
    value = value.strip()
    match = _ENDPOINT_RE.fullmatch(value)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise ValueError("Endpoint должен иметь вид host:port, например vpn.example.com:51820.")
    return value


def validate_router_address(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value or any(char.isspace() for char in value):
        raise ValueError("Укажите IP-адрес, имя хоста или полный URL роутера.")
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise ValueError("URL роутера должен содержать только http(s)://host[:port].")
        return value
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+(?::\d{1,5})?", value):
            raise ValueError("Некорректный адрес роутера.")
    return value
