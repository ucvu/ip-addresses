from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True, slots=True)
class RouterTarget:
    id: int | None
    name: str
    address: str


@dataclass(frozen=True, slots=True)
class RouterCredentials:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class Preset:
    name: str
    mode: Literal["direct", "proxy"]
    entries: tuple[str, ...]
    content: str


@dataclass(frozen=True, slots=True)
class OperationOptions:
    action: Literal["install", "update", "endpoint"]
    preset_id: int | None = None
    endpoint: str | None = None
    online: bool = False
    generate_off: bool = False
    vpn_off: bool = False
    manual: bool = False
    conf_name: str | None = None


@dataclass(frozen=True, slots=True)
class OperationEvent:
    stage: str
    message: str
    level: Literal["debug", "info", "warning", "error", "success"] = "info"
    router: str | None = None
    percent: int | None = None


@dataclass(frozen=True, slots=True)
class OperationResult:
    success: bool
    failed_targets: tuple[RouterTarget, ...] = field(default_factory=tuple)
    message: str = ""
