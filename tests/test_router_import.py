import pytest

from core.routers import RouterImportEntry, RouterImportError, parse_router_import


def test_parse_router_import_with_optional_and_multiword_names():
    content = """
    # Домашняя сеть
    192.168.1.1 Дом
    router.example.com
    https://router-2.example.com:8443 Дача и гости
    """

    assert parse_router_import(content) == (
        RouterImportEntry("192.168.1.1", "Дом"),
        RouterImportEntry("router.example.com"),
        RouterImportEntry("https://router-2.example.com:8443", "Дача и гости"),
    )


def test_parse_router_import_keeps_explicit_name_for_duplicate_address():
    assert parse_router_import("192.168.1.1 Дом\n192.168.1.1\n") == (
        RouterImportEntry("192.168.1.1", "Дом"),
    )


def test_parse_router_import_reports_invalid_line_number():
    with pytest.raises(RouterImportError, match="Строка 2"):
        parse_router_import("192.168.1.1 Дом\nnot/a/router\n")