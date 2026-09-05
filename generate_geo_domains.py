"""
Скачивает geosite.dat и geoip.dat (v2ray-rules-dat) и выгружает домены
и IP-подсети выбранных сервисов в текстовые файлы
(без protobuf-библиотек, только stdlib).

Список сервисов задаётся файлом пресета (--preset), по одной записи
на строку:
  geosite:name  — все домены сервиса из geosite.dat
  geoip:name    — все IP-подсети сервиса из geoip.dat
  domain:значение — домен попадает в geosite_domains_*.txt, а IP/CIDR — в geoip_ips_*.txt
Первая строка вида 'mode: direct'/'mode: proxy' (её использует
install_wireguard.py) пропускается, так что один и тот же файл годится
обоим скриптам.

Прочие настройки — ниже в блоке CONFIG.
"""

import argparse
import glob
import ipaddress
import os
import sys
import urllib.request

# ---------------- CONFIG ----------------

GEOSITE_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
GEOSITE_FILE = "geosite.dat"

GEOIP_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOIP_FILE = "geoip.dat"

OUTPUT_PREFIX_DOMAINS = "geosite_domains"
OUTPUT_PREFIX_IPS = "geoip_ips"
MAX_LINES_PER_FILE = 299

INCLUDE_IPV6 = False

# -----------------------------------------


def download_file(url, dest):
    print(f"Скачиваю {url} -> {dest}")
    urllib.request.urlretrieve(url, dest)


def require_offline_file(dest):
    if not os.path.exists(dest):
        sys.exit(f"Ошибка: файл {dest} не найден. Запустите без --offline, чтобы его скачать.")


def read_varint(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_domain(data):
    # Domain { type=1 varint; value=2 string; attribute=3 repeated }
    pos = 0
    value = None
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            chunk = data[pos:pos + length]
            pos += length
            if field_no == 2:
                value = chunk.decode("utf-8", errors="replace")
        else:
            raise ValueError(f"unexpected wire type {wire_type} in Domain")
    return value


def parse_geosite(data, pos, length):
    # GeoSite { country_code=1 string; domain=2 repeated Domain }
    end = pos + length
    country_code = None
    domains = []
    while pos < end:
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 2:
            flen, pos = read_varint(data, pos)
            chunk = data[pos:pos + flen]
            pos += flen
            if field_no == 1:
                country_code = chunk.decode("utf-8", errors="replace")
            elif field_no == 2:
                domains.append(parse_domain(chunk))
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        else:
            raise ValueError(f"unexpected wire type {wire_type} in GeoSite")
    return country_code, domains, pos


def parse_geosite_list(data):
    pos = 0
    entries = {}
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if field_no == 1 and wire_type == 2:
            length, pos = read_varint(data, pos)
            country_code, domains, pos = parse_geosite(data, pos, length)
            entries[country_code] = domains
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            pos += length
        else:
            raise ValueError(f"unexpected top-level wire type {wire_type}")
    return entries


def parse_cidr(data):
    # CIDR { ip=1 bytes; prefix=2 varint }
    pos = 0
    ip_bytes = None
    prefix = None
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            v, pos = read_varint(data, pos)
            if field_no == 2:
                prefix = v
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            chunk = data[pos:pos + length]
            pos += length
            if field_no == 1:
                ip_bytes = chunk
        else:
            raise ValueError(f"unexpected wire type {wire_type} in CIDR")
    return f"{ipaddress.ip_address(ip_bytes)}/{prefix}"


def parse_geoip(data, pos, length):
    # GeoIP { country_code=1 string; cidr=2 repeated CIDR; ... }
    end = pos + length
    country_code = None
    cidrs = []
    while pos < end:
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 2:
            flen, pos = read_varint(data, pos)
            chunk = data[pos:pos + flen]
            pos += flen
            if field_no == 1:
                country_code = chunk.decode("utf-8", errors="replace")
            elif field_no == 2:
                cidrs.append(parse_cidr(chunk))
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        else:
            raise ValueError(f"unexpected wire type {wire_type} in GeoIP")
    return country_code, cidrs, pos


def parse_geoip_list(data):
    pos = 0
    entries = {}
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if field_no == 1 and wire_type == 2:
            length, pos = read_varint(data, pos)
            country_code, cidrs, pos = parse_geoip(data, pos, length)
            entries[country_code] = cidrs
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            pos += length
        else:
            raise ValueError(f"unexpected top-level wire type {wire_type}")
    return entries


def header_for(service):
    return "# " + "-".join(word.capitalize() for word in service.split("-"))


def parse_service_entry(entry):
    source, sep, name = entry.partition(":")
    if not sep:
        sys.exit(f"Ошибка: '{entry}' не в формате 'geosite:name', 'geoip:name' или 'domain:имя'")
    source = source.strip().lower()
    if source not in ("geosite", "geoip", "domain"):
        sys.exit(f"Ошибка: неизвестный источник '{source}' в '{entry}', "
                 f"ожидается geosite, geoip или domain")
    return source, name.strip()


def is_ip_or_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def build_custom_domain_blocks(services):
    # Валидные IP/CIDR из domain: обрабатываются отдельно как IP-списки.
    domains = [name for source, name in map(parse_service_entry, services)
               if source == "domain" and not is_ip_or_cidr(name)]
    if not domains:
        return []
    print(f"Отдельных доменов из пресета (domain:): {len(domains)}")
    return [("# Custom", domains)]


def build_custom_ip_blocks(services):
    addresses = [name for source, name in map(parse_service_entry, services)
                 if source == "domain" and is_ip_or_cidr(name)]
    if not addresses:
        return []
    print(f"Отдельных IP-подсетей из пресета (domain:): {len(addresses)}")
    return [("# Custom IP", addresses)]


def build_blocks(entries, services, source_key, source_name):
    blocks = []
    for entry in services:
        source, service = parse_service_entry(entry)
        if source != source_key:
            continue
        values = entries.get(service.upper())
        if values is None:
            continue
        print(f"Сервис '{source}:{service}' найден в {source_name} ({len(values)} записей)")
        blocks.append((header_for(service), values))
    return blocks


def pack_into_files(blocks, max_lines):
    files = []
    current = []
    for header, domains in blocks:
        block = [header] + domains + [""]
        pos = 0
        while pos < len(block):
            space = max_lines - len(current)
            if space <= 0:
                files.append(current)
                current = []
                space = max_lines
            take = block[pos:pos + space]
            current.extend(take)
            pos += len(take)
            if pos < len(block):
                files.append(current)
                current = []
                block = [header + " (continued)"] + block[pos:]
                pos = 0
    if current:
        files.append(current)
    return files


def search_services(text, domain_entries, ip_entries):
    needle = text.upper()
    domain_matches = sorted(code for code in domain_entries if needle in code)
    ip_matches = sorted(code for code in ip_entries if needle in code)

    for code in domain_matches:
        print(f"geosite:{code.lower()} ({len(domain_entries[code])} domains)")
    for code in ip_matches:
        print(f"geoip:{code.lower()} ({len(ip_entries[code])} cidrs)")


def clear_old_files(prefix):
    for path in glob.glob(f"{prefix}_*.txt"):
        os.remove(path)


def write_files(files, prefix):
    clear_old_files(prefix)
    written = []
    for i, lines in enumerate(files, start=1):
        while lines and lines[-1] == "":
            lines = lines[:-1]
        path = f"{prefix}_{i}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        written.append(path)
        print(f"Записан {path} ({len(lines)} строк)")
    return written


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true",
                         help="использовать уже скачанные geosite.dat/geoip.dat вместо новой загрузки")
    parser.add_argument("--search", metavar="TEXT",
                         help="искать сервисы по подстроке вместо генерации файлов (требует --offline)")
    parser.add_argument("--pull", action="store_true",
                         help="только скачать geosite.dat/geoip.dat, без генерации файлов")
    parser.add_argument("--preset", metavar="PATH",
                         help="файл пресета со списком сервисов (geosite:.../geoip:..., "
                              "по одному в строке; строка 'mode: ...' пропускается)")
    args = parser.parse_args()
    if args.search and not args.offline:
        parser.error("--search можно использовать только вместе с --offline")
    if args.pull and (args.offline or args.search):
        parser.error("--pull нельзя сочетать с --offline или --search")
    if not args.preset and not (args.pull or args.search):
        parser.error("--preset обязателен: список сервисов берётся из файла пресета")
    return args


def read_preset_services(path):
    services = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 'mode: direct'/'mode: proxy' — строка для install_wireguard.py, не сервис
            if not line or line.startswith("#") or line.lower().startswith("mode:"):
                continue
            services.append(line)
    return services


def main():
    args = parse_args()

    if args.pull:
        download_file(GEOSITE_URL, GEOSITE_FILE)
        download_file(GEOIP_URL, GEOIP_FILE)
        print("Загрузка файлов завершена")
        return

    if args.offline:
        require_offline_file(GEOSITE_FILE)
        require_offline_file(GEOIP_FILE)
    else:
        download_file(GEOSITE_URL, GEOSITE_FILE)
        download_file(GEOIP_URL, GEOIP_FILE)
        print("Загрузка файлов завершена")

    print("Начинаю парсинг файлов")

    with open(GEOSITE_FILE, "rb") as f:
        geosite_data = f.read()
    domain_entries = parse_geosite_list(geosite_data)

    with open(GEOIP_FILE, "rb") as f:
        geoip_data = f.read()
    ip_entries = parse_geoip_list(geoip_data)

    if args.search:
        search_services(args.search, domain_entries, ip_entries)
        return

    services = read_preset_services(args.preset)
    if not services:
        sys.exit(f"Ошибка: в файле пресета {args.preset} нет ни одного сервиса")

    domain_blocks = (build_custom_domain_blocks(services)
                     + build_blocks(domain_entries, services, "geosite", GEOSITE_FILE))
    domain_files = pack_into_files(domain_blocks, MAX_LINES_PER_FILE)
    write_files(domain_files, OUTPUT_PREFIX_DOMAINS)

    if not INCLUDE_IPV6:
        ip_entries = {code: [cidr for cidr in cidrs if ":" not in cidr] for code, cidrs in ip_entries.items()}
    ip_blocks = (build_custom_ip_blocks(services)
                 + build_blocks(ip_entries, services, "geoip", GEOIP_FILE))
    ip_files = pack_into_files(ip_blocks, MAX_LINES_PER_FILE)
    write_files(ip_files, OUTPUT_PREFIX_IPS)


if __name__ == "__main__":
    main()
