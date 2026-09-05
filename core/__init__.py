"""Общее ядро CLI и веб-интерфейса."""

from .models import (
    OperationEvent,
    OperationOptions,
    OperationResult,
    Preset,
    RouterCredentials,
    RouterTarget,
)
from .presets import PresetValidationError, parse_preset, validate_endpoint, validate_router_address
from .routers import RouterImportEntry, RouterImportError, parse_router_import

__all__ = [
    "OperationEvent",
    "OperationOptions",
    "OperationResult",
    "Preset",
    "PresetValidationError",
    "RouterCredentials",
    "RouterImportEntry",
    "RouterImportError",
    "RouterTarget",
    "parse_preset",
    "parse_router_import",
    "validate_endpoint",
    "validate_router_address",
]
