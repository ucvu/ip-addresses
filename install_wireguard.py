#!/usr/bin/env python3
"""
Настраивает WireGuard VPN на роутере Netcraze через веб RCI API
(тот же API, что использует веб-интерфейс).

Что делает:
  1. Устанавливает компонент "WireGuard VPN" (клиент), если он ещё
     не установлен (роутер перезагрузится).
  2. Проверяет ВСЕ существующие WireGuard-интерфейсы на роутере и выключает
     каждый включённый перед любыми другими действиями (возможен
     кратковременный разрыв соединения с роутером, скрипт дожидается
     восстановления).
  3. Импортирует WireGuard-конфиг (.conf рядом со скриптом) как отключённое
     подключение в разделе "Другие подключения" и помечает его как
     используемое для выхода в интернет.
  4. Удаляет ВСЕ существующие списки и правила в "Маршрутизация -> Маршруты
     DNS" и создаёт их заново из *.txt файлов рядом со скриптом (без
     указания шлюза, с автодобавлением маршрута). Интерфейс маршрута
     зависит от --mode: 'proxy' (по умолчанию) — созданное WireGuard-
     подключение, 'direct' — интерфейс "Ethernet-подключение". Заодно
     в "Приоритеты подключений" "Ethernet-подключение" перемещается
     в конец списка (--mode direct) либо в начало, если оно там ещё
     не первое (--mode proxy).
  5. Если передан --vpn-up — включает VPN-подключение в самом конце.
  6. Удаляет использованный .conf файл (кроме случая --update-only,
     где .conf вообще не используется), если не передан --keep-conf.

С флагом --update-only шаги 1-3 и 6 пропускаются: имя WireGuard-подключения
берётся с роутера (первое найденное), .conf файл рядом со скриптом
игнорируется, обновляются только списки и маршруты DNS (шаг 4).

Списков может быть любое количество — достаточно положить *.txt файл
рядом со скриптом (по одной записи на строку, строки с "#" игнорируются)
и запустить скрипт заново. Внимание: при каждом запуске все существующие
списки/маршруты на роутере удаляются и создаются заново из текущего
набора *.txt файлов.

Использование:
    python install_wireguard.py [--router IP] [--generate | --generate-offline]
                                [--vpn-up] [--update-only] [--keep-conf]
                                [--mode direct|proxy]

    --router IP        адрес роутера: IP (по умолчанию 192.168.88.57, используется HTTP)
                       или доменное имя (используется HTTPS); можно также
                       указать URL целиком со схемой (http:// или https://)
    --generate         перед настройкой запустить generate_geo_domains.py,
                       чтобы обновить *.txt файлы со списками
    --generate-offline то же самое, но с флагом --offline (без скачивания
                       geosite.dat/geoip.dat, используются уже имеющиеся)
    --vpn-up           включить VPN-подключение по завершении всех действий
                       (по умолчанию подключение остаётся выключенным)
    --update-only      только пересоздать списки и маршруты DNS на уже
                       настроенном подключении, ничего больше не менять
    --keep-conf        не удалять .conf файл после успешного выполнения
    --mode             direct — маршруты DNS через "Ethernet-подключение";
                       proxy (по умолчанию) — через WireGuard-подключение
"""

import argparse
import hashlib
import ipaddress
import subprocess
import sys
import time
from pathlib import Path

import requests

ROUTER_URL = "http://192.168.1.1"
USERNAME = "admin"
PASSWORD = "Admin123qw"
COMPONENT = "wireguard"  # клиент; "wireguard-server" сюда специально не входит

REBOOT_TIMEOUT = 180  # секунд ожидания возврата роутера в сеть после установки

SCRIPT_DIR = Path(__file__).resolve().parent
USE_FOR_INTERNET = True


def login(session: requests.Session) -> None:
    resp = session.get(f"{ROUTER_URL}/auth")
    if resp.status_code == 200:
        return  # сессия уже авторизована

    realm = resp.headers["X-NDM-Realm"]
    challenge = resp.headers["X-NDM-Challenge"]
    md5_hash = hashlib.md5(f"{USERNAME}:{realm}:{PASSWORD}".encode()).hexdigest()
    sha_hash = hashlib.sha256((challenge + md5_hash).encode()).hexdigest()

    resp = session.post(f"{ROUTER_URL}/auth", json={"login": USERNAME, "password": sha_hash})
    resp.raise_for_status()


def rci(session: requests.Session, commands: list) -> list:
    resp = session.post(f"{ROUTER_URL}/rci/", json=commands)
    resp.raise_for_status()
    return resp.json()


# ---- Установка компонента WireGuard ----------------------------------------

def is_component_installed(session: requests.Session, component: str, retries: int = 3) -> bool:
    # Сразу после логина роутер иногда отвечает на первый запрос неполным
    # JSON (без ключа "component") — поэтому пара попыток с паузой.
    for attempt in range(retries):
        resp = session.post(f"{ROUTER_URL}/rci/components/list", json={})
        resp.raise_for_status()
        try:
            return "installed" in resp.json()["component"][component]
        except (KeyError, ValueError):
            if attempt == retries - 1:
                raise
            time.sleep(1)


def queue_component_install(session: requests.Session, component: str) -> None:
    resp = session.post(
        f"{ROUTER_URL}/rci/",
        json=[{"components": {"install": [{"component": component}]}}],
    )
    resp.raise_for_status()


def commit_and_wait(session: requests.Session) -> None:
    resp = session.post(f"{ROUTER_URL}/rci/components/commit", json={"reason": "manual"})
    resp.raise_for_status()

    while True:
        time.sleep(2)
        try:
            resp = session.get(f"{ROUTER_URL}/rci/components/commit", timeout=5)
        except requests.exceptions.RequestException:
            break  # роутер перезагружается
        if resp.status_code != 200:
            break  # сессия сброшена — начался перезапуск сервисов/reboot
        data = resp.json()
        print(f"  прогресс: {data.get('progress', {})}")
        if not data.get("continued", False):
            break


def wait_for_router(timeout: int = REBOOT_TIMEOUT) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{ROUTER_URL}/auth", timeout=5)
            if resp.status_code in (200, 401):
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    raise TimeoutError("Роутер не вернулся в сеть после перезагрузки")


def verify_installed_with_retries(component: str, timeout: int = REBOOT_TIMEOUT) -> requests.Session | None:
    # /auth поднимается раньше, чем остальные службы (RCI/компоненты),
    # поэтому саму проверку установки тоже нужно повторять, а не делать один раз.
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            session = requests.Session()
            login(session)
            if is_component_installed(session, component):
                return session
        except (requests.exceptions.RequestException, KeyError, ValueError):
            pass  # роутер ещё поднимает службы, ответы могут быть неполными
        time.sleep(3)
    return None


def ensure_wireguard_component(session: requests.Session) -> requests.Session:
    if is_component_installed(session, COMPONENT):
        print(f"Компонент '{COMPONENT}' уже установлен.")
        return session

    print(f"Ставлю в очередь компонент '{COMPONENT}'...")
    queue_component_install(session, COMPONENT)

    print("Применяю изменения (роутер перезагрузится)...")
    commit_and_wait(session)

    print("Жду возврата роутера в сеть...")
    wait_for_router()

    print("Проверяю установку (роутер может ещё поднимать службы)...")
    new_session = verify_installed_with_retries(COMPONENT)
    if new_session is None:
        print(f"Не удалось подтвердить установку '{COMPONENT}'.", file=sys.stderr)
        sys.exit(1)

    print(f"Готово: '{COMPONENT}' успешно установлен.")
    return new_session


# ---- Общие хелперы ----------------------------------------------------------

def next_free_id(existing_ids, prefix: str) -> str:
    n = 0
    while f"{prefix}{n}" in existing_ids:
        n += 1
    return f"{prefix}{n}"


def cidr_to_addr_mask(cidr: str):
    iface = ipaddress.ip_interface(cidr)
    return str(iface.ip), str(iface.network.netmask)


# ---- WireGuard-подключение ---------------------------------------------------

def find_wg_conf() -> Path:
    conf_files = sorted(SCRIPT_DIR.glob("*.conf"))
    if not conf_files:
        print(f"Не найден файл конфигурации (*.conf) в {SCRIPT_DIR}", file=sys.stderr)
        sys.exit(1)
    if len(conf_files) > 1:
        names = ", ".join(p.name for p in conf_files)
        print(f"Найдено несколько файлов конфигурации (*.conf): {names}. "
              f"Оставьте рядом со скриптом только один.", file=sys.stderr)
        sys.exit(1)
    return conf_files[0]


def parse_wg_conf(path: Path):
    interface_cfg = {}
    peers = []
    current = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[Interface]":
            current = interface_cfg
            continue
        if line == "[Peer]":
            current = {}
            peers.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        current[key.strip()] = value.strip()
    return interface_cfg, peers


def get_existing_interfaces(session: requests.Session) -> dict:
    data = rci(session, [{"show": {"interface": {}}}])[0]["show"]["interface"]
    return {ifname: info.get("description", "") for ifname, info in data.items()}


def build_interface_commands(description, ifname, interface_cfg, peers, use_for_internet):
    cmds = [{"interface": {"description": description, "name": ifname}}]

    if use_for_internet:
        cmds.append({"interface": {"ip": {"global": {"auto": True}}, "name": ifname}})

    addr_v4 = addr_v6 = None
    for part in interface_cfg.get("Address", "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            addr_v6 = part
        else:
            addr_v4 = part

    if addr_v4:
        ip, mask = cidr_to_addr_mask(addr_v4)
        cmds.append({"interface": {"ip": {"address": [{"no": True}, {"address": ip, "mask": mask}]}, "name": ifname}})

    listen_port = interface_cfg.get("ListenPort")
    if listen_port:
        cmds.append({"interface": {"wireguard": {"listen-port": {"port": int(listen_port)}}, "name": ifname}})
    else:
        cmds.append({"interface": {"wireguard": {"listen-port": {"no": True}}, "name": ifname}})

    cmds.append({"interface": {"schedule": {"no": True}, "name": ifname}})

    mtu = interface_cfg.get("MTU")
    if mtu:
        cmds.append({"interface": {"ip": {"mtu": mtu}, "name": ifname}})

    cmds.append({"interface": {"ip": {"tcp": {"adjust-mss": {"pmtu": True}}}, "name": ifname}})

    dns_entries = [d.strip() for d in interface_cfg.get("DNS", "").split(",") if d.strip()]
    if dns_entries:
        ns_list = [{"no": True}] + [{"name-server": d, "port": ""} for d in dns_entries]
        cmds.append({"interface": {"ip": {"name-server": ns_list}, "name": ifname}})

    peer_objs = []
    for peer in peers:
        allow_ips = []
        for cidr in peer.get("AllowedIPs", "").split(","):
            cidr = cidr.strip()
            if not cidr:
                continue
            if ":" in cidr:
                print(f"  предупреждение: IPv6 AllowedIPs ({cidr}) не поддержан скриптом, пропущен")
                continue
            ip, mask = cidr_to_addr_mask(cidr)
            allow_ips.append({"address": ip, "mask": mask})

        peer_obj = {
            "key": peer["PublicKey"],
            "allow-ips": [{"no": True}] + allow_ips,
            "comment": "",
            "connect": {},
        }
        if peer.get("PersistentKeepalive"):
            peer_obj["keepalive-interval"] = {"interval": int(peer["PersistentKeepalive"])}
        if peer.get("PresharedKey"):
            peer_obj["preshared-key"] = peer["PresharedKey"]
        if peer.get("Endpoint"):
            peer_obj["endpoint"] = {"address": peer["Endpoint"]}
        peer_objs.append(peer_obj)

    if peer_objs:
        cmds.append({"interface": {"wireguard": {"peer": peer_objs}, "name": ifname}})

    if interface_cfg.get("PrivateKey"):
        cmds.append({"interface": {"wireguard": {"private-key": interface_cfg["PrivateKey"]}, "name": ifname}})

    if addr_v6:
        cmds.append({"interface": {"ipv6": {"address": [{"no": True}, {"block": addr_v6}]}, "name": ifname}})

    cmds.append({"system": {"configuration": {"save": {}}}})
    return cmds


def find_interface_by_description(session: requests.Session, description: str) -> str | None:
    existing = get_existing_interfaces(session)
    for ifname, desc in existing.items():
        if ifname.startswith("Wireguard") and desc == description:
            return ifname
    return None


def get_wireguard_interfaces(session: requests.Session) -> list:
    return [ifname for ifname in get_existing_interfaces(session) if ifname.startswith("Wireguard")]


def find_any_interface_by_description(session: requests.Session, description: str) -> str | None:
    existing = get_existing_interfaces(session)
    for ifname, desc in existing.items():
        if desc == description:
            return ifname
    return None


def get_global_interface_settings(session: requests.Session) -> dict:
    # "ip global" — участие интерфейса в политике приоритетов подключений;
    # поле "order" задаёт позицию (0 — самый высокий приоритет).
    data = rci(session, [{"show": {"sc": {"interface": {}}}}])[0]["show"]["sc"]["interface"]
    settings = {}
    for ifname, info in data.items():
        global_settings = info.get("ip", {}).get("global")
        if global_settings and "order" in global_settings:
            settings[ifname] = global_settings
    return settings


def move_interface_to_bottom(session: requests.Session, ifname: str) -> None:
    settings = get_global_interface_settings(session)
    if ifname not in settings:
        return  # интерфейс не участвует в приоритетах подключений

    others = sorted((name for name in settings if name != ifname), key=lambda name: settings[name]["order"])
    new_order = others + [ifname]

    rci(session, [
        {"interface": {"ip": {"global": {"enabled": settings[name].get("enabled", True), "order": position}}, "name": name}}
        for position, name in enumerate(new_order)
    ] + [{"system": {"configuration": {"save": {}}}}])
    print(f"'{ifname}' перемещён в конец списка приоритетов подключений.")


def move_interface_to_top(session: requests.Session, ifname: str) -> None:
    settings = get_global_interface_settings(session)
    if ifname not in settings:
        return  # интерфейс не участвует в приоритетах подключений
    if settings[ifname]["order"] == 0:
        return  # уже первый

    others = sorted((name for name in settings if name != ifname), key=lambda name: settings[name]["order"])
    new_order = [ifname] + others

    rci(session, [
        {"interface": {"ip": {"global": {"enabled": settings[name].get("enabled", True), "order": position}}, "name": name}}
        for position, name in enumerate(new_order)
    ] + [{"system": {"configuration": {"save": {}}}}])
    print(f"'{ifname}' перемещён в начало списка приоритетов подключений.")


def ensure_wireguard_interface(session: requests.Session, description: str, conf_path: Path, use_for_internet: bool) -> str:
    existing_ifname = find_interface_by_description(session, description)
    if existing_ifname:
        print(f"Подключение '{description}' уже существует ({existing_ifname}), импорт пропущен.")
        return existing_ifname

    ifname = next_free_id(get_existing_interfaces(session).keys(), "Wireguard")
    interface_cfg, peers = parse_wg_conf(conf_path)
    rci(session, build_interface_commands(description, ifname, interface_cfg, peers, use_for_internet))
    print(f"Подключение '{description}' создано как {ifname} (VPN не включён, выход в интернет: {use_for_internet}).")
    return ifname


def get_interface_state(session: requests.Session, ifname: str) -> dict | None:
    data = rci(session, [{"show": {"interface": {}}}])[0]["show"]["interface"]
    return data.get(ifname)


def set_interface_up(session: requests.Session, ifname: str, up: bool) -> None:
    rci(session, [
        {"interface": {"name": ifname, "up": up}},
        {"system": {"configuration": {"save": {}}}},
    ])


def disable_vpn_if_up(session: requests.Session, ifname: str) -> None:
    info = get_interface_state(session, ifname)
    if info is None or info.get("state") != "up":
        return

    print(f"WireGuard-подключение {ifname} сейчас включено — выключаю перед настройкой "
          f"(возможен кратковременный разрыв соединения с роутером)...")
    set_interface_up(session, ifname, False)

    print("Жду восстановления соединения с роутером...")
    wait_for_router()
    login(session)


# ---- Списки доменов/IP и маршруты DNS --------------------------------------

def get_existing_domain_lists(session: requests.Session) -> dict:
    data = rci(session, [{"show": {"sc": {"object-group": {"fqdn": {}}}}}])[0]["show"]["sc"]["object-group"]["fqdn"]
    return {group_id: info.get("description", "") for group_id, info in data.items()}


def read_list_entries(path: Path) -> list:
    entries = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def get_existing_routes(session: requests.Session) -> list:
    data = rci(session, [{"show": {"sc": {"dns-proxy": {"route": {}}}}}])[0]["show"]["sc"]["dns-proxy"]["route"]
    return data or []


def delete_all_domain_lists_and_routes(session: requests.Session) -> None:
    routes = get_existing_routes(session)
    route_indexes = [r["index"] for r in routes if "index" in r]
    if route_indexes:
        rci(session, [
            {"dns-proxy": {"route": [{"index": idx, "no": True} for idx in route_indexes]}},
            {"system": {"configuration": {"save": {}}}},
        ])
        print(f"Удалено маршрутов: {len(route_indexes)}")

    existing = get_existing_domain_lists(session)
    if existing:
        rci(session, [
            {"object-group": {"fqdn": [{"name": group_id, "no": True} for group_id in existing]}},
            {"system": {"configuration": {"save": {}}}},
        ])
        print(f"Удалено списков: {len(existing)}")


def create_domain_list(session: requests.Session, name: str, entries: list) -> str:
    existing = get_existing_domain_lists(session)
    group_id = next_free_id(existing.keys(), "domain-list")

    rci(session, [{"object-group": {"fqdn": {group_id: {
        "description": name,
        "include": [{"address": e} for e in entries],
    }}}}])
    print(f"Список '{name}' сохранён как {group_id} ({len(entries)} записей).")
    return group_id


def create_dns_route(session: requests.Session, group_id: str, interface_name: str, auto: bool = True) -> None:
    rci(session, [
        {"dns-proxy": {"route": {
            "group": group_id,
            "gateway": "",
            "auto": auto,
            "reject": False,
            "interface": interface_name,
            "disable": False,
        }}},
        {"system": {"configuration": {"save": {}}}},
    ])
    print(f"Маршрут '{group_id}' -> {interface_name} настроен (авто: {auto}).")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--router", metavar="ADDR",
                         help="IP, доменное имя или полный URL роутера (по умолчанию 192.168.1.1)")
    parser.add_argument("--generate", action="store_true",
                         help="перед настройкой запустить generate_geo_domains.py для обновления *.txt списков")
    parser.add_argument("--generate-offline", action="store_true",
                         help="то же, что --generate, но с флагом --offline (без скачивания geosite.dat/geoip.dat)")
    parser.add_argument("--vpn-up", action="store_true",
                         help="включить VPN-подключение по завершении настройки")
    parser.add_argument("--update-only", action="store_true",
                         help="только пересоздать списки и маршруты DNS; имя WireGuard-подключения "
                              "берётся с роутера (первое найденное), .conf файл игнорируется")
    parser.add_argument("--keep-conf", action="store_true",
                         help="не удалять .conf файл после успешного выполнения")
    parser.add_argument("--mode", choices=["direct", "proxy"], default="proxy",
                         help="интерфейс для маршрутов DNS: 'direct' — Ethernet-подключение, "
                              "'proxy' — WireGuard-подключение (по умолчанию)")
    args = parser.parse_args()
    if args.generate and args.generate_offline:
        parser.error("--generate и --generate-offline нельзя использовать одновременно")
    return args


def run_generator(offline: bool = False) -> None:
    script = SCRIPT_DIR / "generate_geo_domains.py"
    cmd = [sys.executable, str(script)]
    if offline:
        cmd.append("--offline")
    print(f"Запускаю {script.name}{' --offline' if offline else ''}...")
    subprocess.run(cmd, cwd=SCRIPT_DIR, check=True)


def main() -> None:
    global ROUTER_URL
    args = parse_args()
    if args.router:
        if "://" in args.router:
            ROUTER_URL = args.router.rstrip("/")
        else:
            try:
                ipaddress.ip_address(args.router)
                scheme = "http"  # локальный IP роутера — обычный HTTP без TLS
            except ValueError:
                scheme = "https"  # доменное имя (например, облачный доступ) — почти всегда HTTPS,
                                   # а POST на HTTP при редиректе на HTTPS теряет метод/тело запроса
            ROUTER_URL = f"{scheme}://{args.router}"

    if args.generate:
        run_generator()
    elif args.generate_offline:
        run_generator(offline=True)

    session = requests.Session()
    login(session)

    conf_path = None
    if args.update_only:
        wg_interfaces = get_wireguard_interfaces(session)
        if not wg_interfaces:
            print("На роутере нет ни одного WireGuard-подключения.", file=sys.stderr)
            sys.exit(1)
        ifname = wg_interfaces[0]
        print(f"--update-only: использую существующее подключение {ifname}, .conf файл игнорируется.")
    else:
        session = ensure_wireguard_component(session)

        for wg_ifname in get_wireguard_interfaces(session):
            disable_vpn_if_up(session, wg_ifname)

        conf_path = find_wg_conf()
        connection_name = conf_path.stem

        ifname = ensure_wireguard_interface(session, connection_name, conf_path, USE_FOR_INTERNET)

    if args.mode == "direct":
        route_ifname = find_any_interface_by_description(session, "Ethernet-подключение")
        if route_ifname is None:
            print("Не найден интерфейс 'Ethernet-подключение' на роутере.", file=sys.stderr)
            sys.exit(1)
        print(f"Режим direct: маршруты DNS будут указывать на {route_ifname} (Ethernet-подключение).")
        move_interface_to_bottom(session, route_ifname)
    else:
        route_ifname = ifname
        eth_ifname = find_any_interface_by_description(session, "Ethernet-подключение")
        if eth_ifname is None:
            print("Интерфейс 'Ethernet-подключение' не найден, проверку приоритета пропускаю.")
        else:
            move_interface_to_top(session, eth_ifname)

    print("Удаляю существующие списки и маршруты DNS...")
    delete_all_domain_lists_and_routes(session)

    list_files = sorted(p for p in SCRIPT_DIR.glob("*.txt") if not p.stem.startswith("_"))
    if not list_files:
        print("Файлы списков (*.txt) рядом со скриптом не найдены.")
    else:
        for path in list_files:
            entries = read_list_entries(path)
            if not entries:
                continue
            group_id = create_domain_list(session, path.stem, entries)
            create_dns_route(session, group_id, route_ifname, auto=True)

    if args.vpn_up:
        print(f"Включаю VPN-подключение {ifname}...")
        set_interface_up(session, ifname, True)

    if conf_path is not None and not args.keep_conf:
        conf_path.unlink()
        print(f"Файл {conf_path.name} удалён.")

    print("Готово.")


if __name__ == "__main__":
    main()
