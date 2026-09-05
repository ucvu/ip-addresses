from __future__ import annotations

from dataclasses import dataclass

from .presets import validate_router_address


class RouterImportError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RouterImportEntry:
    address: str
    name: str | None = None


def parse_router_import(content: str) -> tuple[RouterImportEntry, ...]:
    entries: dict[str, RouterImportEntry] = {}
    lines = content.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    for number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        try:
            address = validate_router_address(parts[0])
        except ValueError as exc:
            raise RouterImportError(f"Строка {number}: {exc}") from exc
        name = parts[1].strip() if len(parts) == 2 else None
        if name == "":
            name = None
        if name and len(name) > 120:
            raise RouterImportError(f"Строка {number}: название длиннее 120 символов.")
        previous = entries.get(address)
        if previous and name is None:
            continue
        entries[address] = RouterImportEntry(address=address, name=name)
    if not entries:
        raise RouterImportError("В файле нет ни одного адреса роутера.")
    return tuple(entries.values())
