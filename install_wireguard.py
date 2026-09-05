#!/usr/bin/env python3
"""
Настраивает WireGuard VPN на роутере Netcraze через веб RCI API
(тот же API, что использует веб-интерфейс).

Что делает при --action install:
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
     DNS" и создаёт их заново из файлов geosite_domains_*.txt и
     geoip_ips_*.txt рядом со скриптом (без указания шлюза,
     с автодобавлением маршрута). Интерфейс маршрута зависит от режима
     в файле пресета: 'proxy' — созданное WireGuard-подключение,
     'direct' — интерфейс "Ethernet-подключение". Заодно в "Приоритеты
     подключений" "Ethernet-подключение" перемещается в конец списка
     (режим direct) либо в начало, если оно там ещё не первое (proxy).
  5. Включает VPN-подключение в самом конце (по умолчанию); с ключом
     --vpn-off подключение, наоборот, остаётся выключенным.
  6. Удаляет использованный .conf файл, если не передан --keep-conf.

При --action update выполняются только шаги 2, 4 и 5: имя WireGuard-
подключения берётся с роутера (первое найденное), .conf файл рядом
со скриптом игнорируется и не удаляется.

При --action endpoint меняется только адрес сервера WireGuard (endpoint
всех пиров подключения) на значение из ключа --endpoint. Сначала текущий
адрес читается с роутера: если он уже нужный, скрипт ничего не делает
и не трогает VPN. Иначе VPN выключается, адрес меняется, результат
перечитывается с роутера для проверки, затем подключение включается
обратно (если не передан --vpn-off). Списки и маршруты DNS при этом
не трогаются, --preset не нужен.

Перед настройкой роутера списки geosite_domains_*.txt / geoip_ips_*.txt
генерируются заново через generate_geo_domains.py по файлу пресета
(отключается ключом --generate-off). Если geosite.dat/geoip.dat рядом
со скриптом отсутствуют, они скачиваются; если уже есть — берутся готовые,
а для повторного скачивания нужен ключ --online (или удалить .dat файлы).

Формат файла пресета: первая строка 'mode: direct' или 'mode: proxy'
(пробел после двоеточия необязателен), дальше по одной записи на строку:
  geosite:name  — все домены сервиса из geosite.dat
  geoip:name    — все IP-подсети сервиса из geoip.dat
  domain:значение — домен добавляется в список доменов, а IP/CIDR — в список IP
Например:

    mode: proxy
    geosite:anthropic
    geosite:youtube
    geoip:telegram
    domain:amd.com
    domain:intel.com

Использование:
    python install_wireguard.py --action {install|update} --preset FILE --router ADDR
                                [--online] [--generate-off] [--vpn-off] [--keep-conf]
    python install_wireguard.py --action endpoint --endpoint ADDR:PORT --router ADDR
                                [--vpn-off]

    --action           install — полная установка WireGuard;
                       update — только обновление списков и маршрутов DNS;
                       endpoint — только смена адреса сервера WireGuard
    --preset FILE      файл пресета: режим маршрутизации + список сервисов
                       (обязателен для install и update)
    --endpoint A:PORT  новый адрес сервера WireGuard, например
                       vpn.example.com:51820 (обязателен для endpoint)
    --router ADDR      адрес роутера: IP (используется HTTP) или доменное имя
                       (используется HTTPS); можно также указать URL целиком
                       со схемой (http:// или https://)
    --online           заново скачать geosite.dat/geoip.dat, даже если они уже
                       лежат рядом со скриптом
    --generate-off     не генерировать списки, использовать уже имеющиеся
                       geosite_domains_*.txt / geoip_ips_*.txt
    --vpn-off          оставить VPN-подключение выключенным по завершении
                       всех действий (по умолчанию оно включается)
    --keep-conf        не удалять .conf файл после успешного выполнения
"""

import argparse
import hashlib
import ipaddress
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

ROUTER_URL = ""  # задаётся в main() из обязательного ключа --router
USERNAME = os.getenv("ROUTER_USERNAME")
PASSWORD = os.getenv("ROUTER_PASSWORD")
COMPONENT = "wireguard"  # клиент; "wireguard-server" сюда специально не входит

REBOOT_TIMEOUT = 180  # секунд ожидания возврата роутера в сеть после установки
HTTP_TIMEOUT = (15, 60)  # (соединение, ответ) в секундах — чтобы запрос не висел вечно;
                         # на соединение с запасом: TLS-хендшейк через прокси небыстрый
VPN_DOWN_DELAY = 10  # секунд паузы после выключения VPN: роутер отвечает раньше,
                     # чем перестраивает маршрутизацию, и проверять сразу бесполезно
VPN_DOWN_TIMEOUT = 300  # секунд на попытки достучаться до роутера после выключения VPN
ACTION_DELAY = 1  # секунд паузы между RCI-командами при создании списков/маршрутов:
                  # роутер иногда молча игнорирует команду, если они идут слишком часто подряд
VERIFY_ATTEMPTS = 3  # попыток проверить и досоздать недостающие списки/маршруты

USE_FOR_INTERNET = True


def validate_credentials() -> None:
    missing = []
    if not USERNAME:
        missing.append("ROUTER_USERNAME")
    if not PASSWORD:
        missing.append("ROUTER_PASSWORD")
    if missing:
        names = ", ".join(missing)
        print(f"Не заданы переменные {names}. Скопируйте .env.example в .env "
              "и укажите данные доступа к роутеру.", file=sys.stderr)
        sys.exit(1)


def login(session: requests.Session) -> None:
    resp = session.get(f"{ROUTER_URL}/auth", timeout=HTTP_TIMEOUT)
    if resp.status_code == 200:
        return  # сессия уже авторизована

    realm = resp.headers["X-NDM-Realm"]
    challenge = resp.headers["X-NDM-Challenge"]
    md5_hash = hashlib.md5(f"{USERNAME}:{realm}:{PASSWORD}".encode()).hexdigest()
    sha_hash = hashlib.sha256((challenge + md5_hash).encode()).hexdigest()

    resp = session.post(f"{ROUTER_URL}/auth", json={"login": USERNAME, "password": sha_hash},
                        timeout=HTTP_TIMEOUT)
    resp.raise_for_status()


def rci(session: requests.Session, commands: list) -> list:
    resp = session.post(f"{ROUTER_URL}/rci/", json=commands, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# ---- Установка компонента WireGuard ----------------------------------------

def is_component_installed(session: requests.Session, component: str, retries: int = 3) -> bool:
    # Сразу после логина роутер иногда отвечает на первый запрос неполным
    # JSON (без ключа "component") — поэтому пара попыток с паузой.
    for attempt in range(retries):
        resp = session.post(f"{ROUTER_URL}/rci/components/list", json={}, timeout=HTTP_TIMEOUT)
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
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()


def commit_and_wait(session: requests.Session) -> None:
    resp = session.post(f"{ROUTER_URL}/rci/components/commit", json={"reason": "manual"},
                        timeout=HTTP_TIMEOUT)
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
            resp = requests.get(f"{ROUTER_URL}/auth", timeout=HTTP_TIMEOUT)
            if resp.status_code in (200, 401):
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    raise TimeoutError("Роутер не вернулся в сеть после перезагрузки")


def reconnect(session: requests.Session, timeout: int = REBOOT_TIMEOUT) -> None:
    # После разрыва (выключение VPN, смена приоритетов подключений) роутер может
    # то отвечать, то нет, поэтому логин нужно повторять, а не делать один раз:
    # ответивший /auth ещё не значит, что связь уже стабильна.
    deadline = time.time() + timeout
    while True:
        try:
            login(session)
            return
        except requests.exceptions.RequestException:
            if time.time() >= deadline:
                raise
            time.sleep(3)


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


def find_wan_interface(session: requests.Session) -> str | None:
    # "Ethernet-подключение" в веб-интерфейсе — это локализованный лейбл для
    # интерфейса с системной ролью "interface-name": "ISP"; поле "description"
    # при этом может быть произвольным ("Broadband connection" и т.п.) и не
    # годится для поиска.
    data = rci(session, [{"show": {"interface": {}}}])[0]["show"]["interface"]
    for ifname, info in data.items():
        if info.get("interface-name") == "ISP":
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


def disable_vpn_if_up(session: requests.Session, ifname: str, attempts: int = 3) -> None:
    attempt = 0
    while True:
        info = get_interface_state(session, ifname)
        if info is None or info.get("state") != "up":
            return
        if attempt >= attempts:
            print(f"Не удалось выключить {ifname}: подключение всё ещё активно.", file=sys.stderr)
            sys.exit(1)
        attempt += 1

        print(f"WireGuard-подключение {ifname} сейчас включено — выключаю перед настройкой "
              f"(возможен кратковременный разрыв соединения с роутером)...")
        try:
            set_interface_up(session, ifname, False)
        except requests.exceptions.RequestException:
            # Роутер часто закрывает соединение прямо в момент выключения туннеля,
            # не ответив на запрос. Команда при этом обычно уже применена, поэтому
            # не падаем, а проверяем состояние интерфейса после восстановления связи.
            print("Соединение оборвано в момент выключения VPN, проверю состояние после восстановления...")

        print(f"Жду восстановления соединения с роутером ({VPN_DOWN_DELAY} с паузы, "
              f"затем опрос до {VPN_DOWN_TIMEOUT // 60} мин)...")
        time.sleep(VPN_DOWN_DELAY)
        reconnect(session, timeout=VPN_DOWN_TIMEOUT)
        print("Соединение с роутером восстановлено.")


def enable_vpn(session: requests.Session, ifname: str) -> None:
    print(f"Включаю VPN-подключение {ifname}...")
    try:
        set_interface_up(session, ifname, True)
    except requests.exceptions.RequestException:
        # Включение туннеля так же рвёт текущее соединение с роутером;
        # это последнее действие скрипта, команда уже отправлена.
        print("Соединение с роутером оборвано в момент включения VPN (команда отправлена).")


# ---- Адрес сервера WireGuard (endpoint пира) --------------------------------

def endpoint_to_str(endpoint) -> str:
    # Роутер может отдавать endpoint как строкой, так и объектом
    # {"address": ..., "port": ...} — приводим к виду "host:port".
    if isinstance(endpoint, dict):
        address = str(endpoint.get("address", "")).strip()
        port = endpoint.get("port")
        if port and ":" not in address:
            return f"{address}:{port}"
        return address
    return str(endpoint or "").strip()


def get_wireguard_peers(session: requests.Session, ifname: str) -> list:
    # Возвращает [{"key": <публичный ключ>, "endpoint": "host:port"}, ...].
    data = rci(session, [{"show": {"sc": {"interface": {}}}}])[0]["show"]["sc"]["interface"]
    peers = data.get(ifname, {}).get("wireguard", {}).get("peer", [])

    if isinstance(peers, dict):
        # вариант ответа, где публичный ключ пира — имя поля
        items = [{"key": key, **(value if isinstance(value, dict) else {})}
                 for key, value in peers.items()]
    else:
        items = [peer for peer in peers if isinstance(peer, dict)]

    return [{"key": peer["key"], "endpoint": endpoint_to_str(peer.get("endpoint"))}
            for peer in items if peer.get("key")]


def set_peer_endpoint(session: requests.Session, ifname: str, peer_key: str, endpoint: str) -> None:
    rci(session, [
        {"interface": {"wireguard": {"peer": {"key": peer_key, "endpoint": {"address": endpoint}}},
                       "name": ifname}},
        {"system": {"configuration": {"save": {}}}},
    ])


def change_wireguard_endpoint(session: requests.Session, ifname: str, endpoint: str) -> None:
    peers = get_wireguard_peers(session, ifname)
    if not peers:
        print(f"У подключения {ifname} не найдено ни одного пира WireGuard.", file=sys.stderr)
        sys.exit(1)

    for peer in peers:
        if peer["endpoint"] == endpoint:
            print(f"Пир {peer['key'][:12]}...: адрес уже {endpoint}, пропускаю.")
            continue
        print(f"Пир {peer['key'][:12]}...: {peer['endpoint'] or '(адрес не задан)'} -> {endpoint}")
        set_peer_endpoint(session, ifname, peer["key"], endpoint)
        time.sleep(ACTION_DELAY)

    # Проверяем по данным с роутера, а не по факту успешного ответа на команду.
    stale = [peer for peer in get_wireguard_peers(session, ifname) if peer["endpoint"] != endpoint]
    if stale:
        keys = ", ".join(peer["key"][:12] + "..." for peer in stale)
        print(f"Адрес сервера не применился у пиров: {keys}", file=sys.stderr)
        sys.exit(1)
    print(f"Адрес сервера WireGuard на {ifname} изменён на {endpoint} (пиров: {len(peers)}).")


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


def read_preset_mode(path: Path) -> str:
    # Сам список сервисов отсюда не читаем — файл пресета целиком уходит
    # в generate_geo_domains.py, который сам пропускает строку с режимом.
    if not path.exists():
        print(f"Файл пресета не найден: {path}", file=sys.stderr)
        sys.exit(1)

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        print(f"Файл пресета {path} пуст.", file=sys.stderr)
        sys.exit(1)

    first = lines[0].strip()
    if not first.lower().startswith("mode:"):
        print(f"Первая строка файла пресета должна быть 'mode: direct' или 'mode: proxy', "
              f"получено: '{first}'", file=sys.stderr)
        sys.exit(1)

    mode = first.split(":", 1)[1].strip().lower()
    if mode not in ("direct", "proxy"):
        print(f"Некорректный режим в пресете: '{mode}' (ожидается direct или proxy)", file=sys.stderr)
        sys.exit(1)
    return mode


def get_existing_routes(session: requests.Session) -> list:
    data = rci(session, [{"show": {"sc": {"dns-proxy": {"route": {}}}}}])[0]["show"]["sc"]["dns-proxy"]["route"]
    return data or []


def delete_all_domain_lists_and_routes(session: requests.Session, attempts: int = 3) -> None:
    # Смена приоритетов подключений перед этим шагом может ненадолго оборвать связь
    # с роутером. Повторять безопасно: список удаляемого перечитывается заново,
    # так что уже удалённое просто не попадёт в следующую попытку.
    for attempt in range(attempts):
        try:
            delete_all_domain_lists_and_routes_once(session)
            return
        except requests.exceptions.RequestException:
            if attempt == attempts - 1:
                raise
            print("Соединение с роутером потеряно, жду восстановления и повторяю удаление...")
            reconnect(session)


def delete_all_domain_lists_and_routes_once(session: requests.Session) -> None:
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


def ensure_lists_and_routes(session: requests.Session, lists_to_create: dict, route_ifname: str) -> None:
    # Роутер иногда молча не применяет команду создания списка или маршрута,
    # хотя RCI отвечает успехом — поэтому после каждого шага пауза, а по итогу
    # состояние перепроверяется по данным с самого роутера и недостающее
    # досоздаётся, а не просто предполагается по выводу команд.
    # +1 итерация сверх VERIFY_ATTEMPTS — только для перепроверки результата
    # последней попытки досоздания, без ещё одной попытки досоздания.
    for attempt in range(1, VERIFY_ATTEMPTS + 2):
        existing_lists = get_existing_domain_lists(session)  # group_id -> description
        name_to_gid = {desc: gid for gid, desc in existing_lists.items()}
        routed_groups = {r.get("group"): r for r in get_existing_routes(session)}

        def is_missing(name: str) -> bool:
            gid = name_to_gid.get(name)
            if gid is None:
                return True
            route = routed_groups.get(gid)
            return route is None or route.get("interface") != route_ifname or route.get("disable", False)

        pending = [name for name in lists_to_create if is_missing(name)]
        if not pending:
            if attempt > 1:
                print("Все списки и маршруты на месте.")
            return
        if attempt > VERIFY_ATTEMPTS:
            break

        if attempt > 1:
            print(f"Не хватает списков/маршрутов ({len(pending)}): {', '.join(pending)} — "
                  f"повторяю (попытка {attempt}/{VERIFY_ATTEMPTS})...")

        for name in pending:
            gid = name_to_gid.get(name)
            if gid is None:
                gid = create_domain_list(session, name, lists_to_create[name])
                time.sleep(ACTION_DELAY)
            create_dns_route(session, gid, route_ifname, auto=True)
            time.sleep(ACTION_DELAY)

    print(f"Не удалось создать списки/маршруты после {VERIFY_ATTEMPTS} попыток: "
          f"{', '.join(pending)}", file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--action", choices=["install", "update", "endpoint"], required=True,
                         help="install — полная установка WireGuard; "
                              "update — только обновление списков и маршрутов DNS; "
                              "endpoint — только смена адреса сервера WireGuard")
    parser.add_argument("--preset", metavar="FILE",
                         help="файл пресета: первая строка 'mode: direct' или 'mode: proxy', "
                              "остальные строки — сервисы geosite:.../geoip:... "
                              "(обязателен для --action install и update)")
    parser.add_argument("--endpoint", metavar="ADDR:PORT",
                         help="новый адрес сервера WireGuard, например vpn.example.com:51820 "
                              "(обязателен для --action endpoint)")
    parser.add_argument("--router", metavar="ADDR", required=True,
                         help="IP, доменное имя или полный URL роутера")
    parser.add_argument("--online", action="store_true",
                         help="заново скачать geosite.dat/geoip.dat, даже если они уже есть")
    parser.add_argument("--generate-off", action="store_true",
                         help="не генерировать списки, использовать уже имеющиеся "
                              "geosite_domains_*.txt / geoip_ips_*.txt")
    parser.add_argument("--vpn-off", action="store_true",
                         help="оставить VPN-подключение выключенным по завершении настройки "
                              "(по умолчанию оно включается)")
    parser.add_argument("--keep-conf", action="store_true",
                         help="не удалять .conf файл после успешного выполнения "
                              "(только для --action install)")
    args = parser.parse_args()
    if args.online and args.generate_off:
        parser.error("--online бессмысленен вместе с --generate-off: генерация не запускается")

    if args.action == "endpoint":
        if not args.endpoint:
            parser.error("--action endpoint требует ключ --endpoint")
        host, sep, port = args.endpoint.rpartition(":")
        if not sep or not host or not port.isdigit():
            parser.error("--endpoint должен быть в виде адрес:порт, например vpn.example.com:51820")
    else:
        if not args.preset:
            parser.error(f"--action {args.action} требует ключ --preset")
        if args.endpoint:
            parser.error("--endpoint используется только с --action endpoint")
    return args


def dat_files_present() -> bool:
    return (SCRIPT_DIR / "geosite.dat").exists() and (SCRIPT_DIR / "geoip.dat").exists()


def run_generator(preset: Path, offline: bool) -> None:
    script = SCRIPT_DIR / "generate_geo_domains.py"
    cmd = [sys.executable, str(script), "--preset", str(preset)]
    if offline:
        cmd.append("--offline")
    print(f"Запускаю: {' '.join(cmd[1:])}")
    subprocess.run(cmd, cwd=SCRIPT_DIR, check=True)


def main() -> None:
    global ROUTER_URL
    args = parse_args()
    validate_credentials()
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

    if args.action == "endpoint":
        session = requests.Session()
        login(session)

        wg_interfaces = get_wireguard_interfaces(session)
        if not wg_interfaces:
            print("На роутере нет ни одного WireGuard-подключения.", file=sys.stderr)
            sys.exit(1)

        ifname = wg_interfaces[0]

        # Проверяем ДО выключения VPN: если адрес уже нужный, незачем ронять
        # туннель и ждать восстановления связи ради ничего.
        peers = get_wireguard_peers(session, ifname)
        if not peers:
            print(f"У подключения {ifname} не найдено ни одного пира WireGuard.", file=sys.stderr)
            sys.exit(1)
        if all(peer["endpoint"] == args.endpoint for peer in peers):
            print(f"Адрес сервера WireGuard на {ifname} уже {args.endpoint} "
                  f"(пиров: {len(peers)}) — менять нечего, VPN не трогаю.")
            print("Готово.")
            return

        for wg_ifname in wg_interfaces:
            disable_vpn_if_up(session, wg_ifname)

        change_wireguard_endpoint(session, ifname, args.endpoint)

        if args.vpn_off:
            print(f"VPN-подключение {ifname} оставлено выключенным (--vpn-off).")
        else:
            enable_vpn(session, ifname)

        print("Готово.")
        return

    preset_path = Path(args.preset)
    mode = read_preset_mode(preset_path)
    print(f"Пресет '{args.preset}': режим {mode}.")

    if args.generate_off:
        print("Генерация списков пропущена (--generate-off).")
    else:
        if dat_files_present() and not args.online:
            offline = True
        else:
            offline = False
            if not dat_files_present():
                print("Файлы geosite.dat/geoip.dat рядом со скриптом не найдены — скачиваю.")
        run_generator(preset_path, offline=offline)

    session = requests.Session()
    login(session)

    conf_path = None
    if args.action == "update":
        wg_interfaces = get_wireguard_interfaces(session)
        if not wg_interfaces:
            print("На роутере нет ни одного WireGuard-подключения.", file=sys.stderr)
            sys.exit(1)

        for wg_ifname in wg_interfaces:
            disable_vpn_if_up(session, wg_ifname)

        ifname = wg_interfaces[0]
        print(f"--action update: использую существующее подключение {ifname}, .conf файл игнорируется.")
    else:
        session = ensure_wireguard_component(session)

        for wg_ifname in get_wireguard_interfaces(session):
            disable_vpn_if_up(session, wg_ifname)

        conf_path = find_wg_conf()
        connection_name = conf_path.stem

        ifname = ensure_wireguard_interface(session, connection_name, conf_path, USE_FOR_INTERNET)

    if mode == "direct":
        route_ifname = find_wan_interface(session)
        if route_ifname is None:
            print("Не найден WAN-интерфейс (Ethernet-подключение) на роутере.", file=sys.stderr)
            sys.exit(1)
        print(f"Режим direct: маршруты DNS будут указывать на {route_ifname} (Ethernet-подключение).")
        move_interface_to_bottom(session, route_ifname)
    else:
        route_ifname = ifname
        eth_ifname = find_wan_interface(session)
        if eth_ifname is None:
            print("WAN-интерфейс (Ethernet-подключение) не найден, проверку приоритета пропускаю.")
        else:
            move_interface_to_top(session, eth_ifname)

    print("Удаляю существующие списки и маршруты DNS...")
    delete_all_domain_lists_and_routes(session)

    list_files = sorted(list(SCRIPT_DIR.glob("geosite_domains_*.txt")) + list(SCRIPT_DIR.glob("geoip_ips_*.txt")))
    if not list_files:
        print("Файлы списков (geosite_domains_*.txt, geoip_ips_*.txt) рядом со скриптом не найдены.")
    else:
        lists_to_create = {path.stem: read_list_entries(path) for path in list_files}
        lists_to_create = {name: entries for name, entries in lists_to_create.items() if entries}
        ensure_lists_and_routes(session, lists_to_create, route_ifname)

    if args.vpn_off:
        print(f"VPN-подключение {ifname} оставлено выключенным (--vpn-off).")
    else:
        enable_vpn(session, ifname)

    if conf_path is not None and not args.keep_conf:
        conf_path.unlink()
        print(f"Файл {conf_path.name} удалён.")

    print("Готово.")


if __name__ == "__main__":
    main()
