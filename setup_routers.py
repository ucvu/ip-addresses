#!/usr/bin/env python3
"""
Прогоняет install_wireguard.py по списку роутеров из файла
(по умолчанию routers.txt рядом со скриптом, по одному адресу на строку,
строки с "#" игнорируются).

Доступны только два действия — update (по умолчанию) и endpoint; --action
install через этот скрипт недоступен, чтобы пакетный прогон по множеству
роутеров не запустил первичную установку не на том роутере. Все остальные
ключи пробрасываются в install_wireguard.py как есть:
    python setup_routers.py --preset preset.txt
    python setup_routers.py --action endpoint --endpoint vpn.example.com:51820

Отличие от одиночного запуска install_wireguard.py (только для update):
списки генерируются лишь на первом роутере, все последующие вызовы получают
--generate-off (файлы geosite_domains_*.txt / geoip_ips_*.txt уже готовы,
пересобирать их для каждого роутера незачем). Если --generate-off передан
явно, генерации не будет вообще. При --action endpoint генерации нет в любом
случае — списки при смене адреса сервера не трогаются.

Ошибка на одном роутере не прерывает работу: скрипт идёт дальше, а в конце
печатает итог и завершается с ненулевым кодом, если что-то не удалось.
Недоступные и не настроившиеся роутеры дописываются в update_failed.txt сразу
по ходу прогона (файл сбрасывается в начале запуска, так что при удачном
прогоне его не остаётся); его можно сразу передать как --routers, чтобы
повторить только их.

С ключом --manual перед каждым роутером скрипт спрашивает подтверждение
и ждёт Enter.

Использование:
    python setup_routers.py [--routers FILE] [--manual] [--action {update|endpoint}]
                            [ключи install_wireguard.py...]
"""

import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
INSTALL_SCRIPT = SCRIPT_DIR / "install_wireguard.py"
FAILED_FILE = "update_failed.txt"


def read_routers(path: Path) -> list:
    if not path.exists():
        print(f"Файл со списком роутеров не найден: {path}", file=sys.stderr)
        sys.exit(1)

    routers = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            routers.append(line)

    if not routers:
        print(f"В файле {path} нет ни одного адреса роутера.", file=sys.stderr)
        sys.exit(1)
    return routers


def write_failed(failed: list) -> None:
    # Файл переписывается сразу после каждой неудачи, чтобы результат не потерялся,
    # если прогон прервать. Формат тот же, что у routers.txt, поэтому повторить
    # только неудачные можно так:
    #     python setup_routers.py --routers update_failed.txt ...
    path = SCRIPT_DIR / FAILED_FILE
    if not failed:
        path.unlink(missing_ok=True)
        return
    path.write_text("\n".join(failed) + "\n", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("--routers", metavar="FILE", default="routers.txt",
                         help="файл со списком адресов роутеров (по умолчанию routers.txt "
                              "рядом со скриптом); остальные ключи уходят в install_wireguard.py")
    parser.add_argument("--manual", action="store_true",
                         help="спрашивать подтверждение (Enter) перед каждым роутером")
    parser.add_argument("--action", choices=["update", "endpoint"], default="update",
                         help="update — обновление списков и маршрутов DNS (по умолчанию); "
                              "endpoint — смена адреса сервера WireGuard; "
                              "install через этот скрипт недоступен")
    args, passthrough = parser.parse_known_args()
    if any(arg == "--router" or arg.startswith("--router=") for arg in passthrough):
        parser.error("--router указывать не нужно: адреса берутся из файла со списком")
    return args, passthrough


def main() -> None:
    args, passthrough = parse_args()
    routers = read_routers(SCRIPT_DIR / args.routers)
    total = len(routers)
    print(f"Роутеров в списке: {total}")

    failed = []
    write_failed(failed)  # сбрасываем результат прошлого запуска
    for number, router in enumerate(routers, start=1):
        cmd = [sys.executable, str(INSTALL_SCRIPT), "--router", router, "--action", args.action] + passthrough
        if args.action == "update" and number > 1 and "--generate-off" not in passthrough:
            cmd.append("--generate-off")  # списки уже сгенерированы на первом роутере

        print(f"\n=== [{number}/{total}] {router} ===")
        if args.manual:
            input("Продолжаем? (Enter — начать, Ctrl+C — прервать) ")
        print(f"Запускаю: {' '.join(cmd[1:])}")
        result = subprocess.run(cmd, cwd=SCRIPT_DIR)
        if result.returncode != 0:
            failed.append(router)
            write_failed(failed)
            print(f"!!! {router}: ошибка (код {result.returncode}), записан в {FAILED_FILE}, "
                  f"перехожу к следующему роутеру.", file=sys.stderr)

    print(f"\nИтог: успешно {total - len(failed)} из {total}.")
    if failed:
        print(f"Не настроены ({len(failed)}), записаны в {FAILED_FILE}: " + ", ".join(failed),
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
