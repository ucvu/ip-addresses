import pytest

from core.presets import PresetValidationError, parse_preset, validate_endpoint, validate_router_address


def test_parse_preset_preserves_comments_and_normalizes_entries():
    preset = parse_preset("# comment\nmode:proxy\n geosite:OpenAI \ndomain:example.com\n", "Test")
    assert preset.mode == "proxy"
    assert preset.entries == ("geosite:OpenAI", "domain:example.com")
    assert preset.content.endswith("\n")


@pytest.mark.parametrize("content", ["", "geosite:openai", "mode: other\ngeosite:x", "mode: proxy\nunknown:x"])
def test_invalid_presets(content):
    with pytest.raises(PresetValidationError):
        parse_preset(content)


@pytest.mark.parametrize("value", ["vpn.example.com:51820", "1.2.3.4:443", "[2001:db8::1]:53"])
def test_endpoint_validation(value):
    assert validate_endpoint(value) == value


@pytest.mark.parametrize("value", ["host", "192.168.1.1", "https://router.example.com:8443"])
def test_router_address_validation(value):
    assert validate_router_address(value) == value.rstrip("/")
