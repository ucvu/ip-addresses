from unittest.mock import Mock

import pytest

import install_wireguard as router


def test_add_dns_wait_save_wait_verify(monkeypatch):
    events = []
    servers = [{"address": "9.9.9.9", "interface": "Wireguard0"},
               {"address": "8.8.8.8"}]

    def rci(session, commands):
        command = commands[0]
        if "show" in command:
            events.append("read")
            return [{"show": {"sc": {"ip": {"name-server": list(servers)}}}}]
        if "ip" in command:
            events.append("add")
            assert command == {"ip": {"name-server": {"address": "9.9.9.9"}}}
            servers.append({"address": "9.9.9.9"})
        else:
            assert command == {"system": {"configuration": {"save": {}}}}
            events.append("save")

    monkeypatch.setattr(router, "rci", rci)
    monkeypatch.setattr(router.time, "sleep", lambda delay: events.append(("sleep", delay)))
    router.ensure_global_dns_server(Mock())
    assert events == ["read", "add", ("sleep", router.ACTION_DELAY),
                      "save", ("sleep", router.ACTION_DELAY), "read"]
    events.clear()
    router.ensure_global_dns_server(Mock())
    assert events == ["read"]
    assert {"address": "8.8.8.8"} in servers


@pytest.mark.parametrize("servers", [
    [{"address": "9.9.9.9"}],
    [{"address": "9.9.9.9", "interface": "", "domain": ""}],
    {"address": "9.9.9.9"},
])
def test_existing_global_dns_is_not_written(monkeypatch, servers):
    rci = Mock(return_value=[{"show": {"sc": {"ip": {"name-server": servers}}}}])
    sleep = Mock()
    monkeypatch.setattr(router, "rci", rci)
    monkeypatch.setattr(router.time, "sleep", sleep)
    router.ensure_global_dns_server(Mock())
    assert rci.call_count == 1
    sleep.assert_not_called()


@pytest.mark.parametrize("succeeds", [True, False])
def test_silently_dropped_dns_write_is_retried(monkeypatch, succeeds):
    writes = 0
    reads = 0

    def rci(session, commands):
        nonlocal writes, reads
        command = commands[0]
        if "show" in command:
            reads += 1
            # Последняя разрешённая попытка должна быть перечитана и проверена.
            servers = ([{"address": "9.9.9.9"}] if succeeds
                       and writes == router.VERIFY_ATTEMPTS else
                       [{"address": "9.9.9.9", "domain": "example.com"}])
            return [{"show": {"sc": {"ip": {"name-server": servers}}}}]
        if "ip" in command:
            writes += 1

    sleep = Mock()
    monkeypatch.setattr(router, "rci", rci)
    monkeypatch.setattr(router.time, "sleep", sleep)
    if succeeds:
        router.ensure_global_dns_server(Mock())
    else:
        with pytest.raises(SystemExit) as error:
            router.ensure_global_dns_server(Mock())
        assert error.value.code == 1
    assert writes == router.VERIFY_ATTEMPTS
    assert reads == router.VERIFY_ATTEMPTS + 1
    assert sleep.call_count == 2 * router.VERIFY_ATTEMPTS


@pytest.mark.parametrize("action", ["install", "update"])
def test_routing_setup_runs_dns_before_vpn_restore(monkeypatch, tmp_path, action):
    preset = tmp_path / "preset.txt"
    preset.write_text("mode: proxy\n", encoding="utf-8")
    args = router.argparse.Namespace(action=action, router="192.0.2.1",
                                    preset=str(preset), generate_off=True,
                                    vpn_off=False, keep_conf=True)
    events = []
    monkeypatch.setattr(router, "parse_args", lambda: args)
    monkeypatch.setattr(router, "SCRIPT_DIR", tmp_path)
    for name in ["validate_credentials", "login", "disable_vpn_if_up",
                 "delete_all_domain_lists_and_routes"]:
        monkeypatch.setattr(router, name, Mock())
    monkeypatch.setattr(router, "get_wireguard_interfaces", lambda session: ["Wireguard0"])
    monkeypatch.setattr(router, "ensure_wireguard_component", lambda session: session)
    monkeypatch.setattr(router, "find_wg_conf", lambda: tmp_path / "vpn.conf")
    monkeypatch.setattr(router, "ensure_wireguard_interface", lambda *args: "Wireguard0")
    monkeypatch.setattr(router, "find_wan_interface", lambda session: None)
    monkeypatch.setattr(router, "enable_vpn", lambda *args: events.append("vpn"))
    monkeypatch.setattr(router, "ensure_global_dns_server", lambda *args: events.append("dns"))
    router.main()
    assert events == ["dns", "vpn"]
