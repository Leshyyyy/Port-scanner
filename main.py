import asyncio
import logging
import os
import sys
import uuid
import json
from pathlib import Path
import yaml
from dotenv import load_dotenv

from utils import cron_manager
from utils.target_manager import TargetManager
from utils.scanner import Scanner
from utils.state_comparator import compare_states
from database.db_manager import DBManager
from config.logger_config import setup_logger
from bot.notifier import send_vk_notification, format_vk_message

setup_logger(level=logging.INFO)
logger = logging.getLogger("main")

async def main():
    BASE_DIR = Path(__file__).resolve().parent
    os.chdir(BASE_DIR)
    load_dotenv()
    db_path = os.getenv("DB_PATH", "database/scanner_back.db")
    vk_token = os.getenv("VK_BOT_TOKEN")
    vk_admin_id = os.getenv("VK_ADMIN_ID")

    config_path = Path("config/config.yaml")
    if not config_path.exists():
        logger.error(f"Конфиг {config_path} не найден!")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    logger.info("Синхронизация CRON")
    schedule_cfg = config.get("schedule", {})
    cron_line = cron_manager.build_cron_line(
        minute=str(schedule_cfg.get("minute", "0")),
        hour=str(schedule_cfg.get("hour", "*/2")),
        day=str(schedule_cfg.get("day", "*")),
        month=str(schedule_cfg.get("month", "*")),
        weekday=str(schedule_cfg.get("weekday", "*")),
        command=f"{sys.executable} {os.path.abspath(__file__)}"
    )
    cron_manager.sync_schedule(cron_line)

    logger.info("Подключение к БД")
    db = DBManager(db_path=db_path)
    await db.connect()

    scan_id = str(uuid.uuid4())

    try:
        logger.info("Подготовка целей")
        scanner_cfg = config.get("scanner", {})
        raw_targets = scanner_cfg.get("targets", [])
        ports = str(scanner_cfg.get("ports", "1-65535"))

        target_mgr = TargetManager()
        valid_targets = await target_mgr.prepare_targets(raw_targets)

        if not valid_targets:
            logger.warning("Нет валидных целей для сканирования. Завершение работы.")
            return
        logger.debug("цели для сканирования: %s, порты: %s",valid_targets,ports)
        await db.create_scan(scan_id=scan_id, targets=valid_targets)

        logger.info(f"Запуск сканирования ({len(valid_targets)} целей)")
        rate = scanner_cfg.get("rate", 1000)
        interface = scanner_cfg.get("interface", None)
        wait_time = scanner_cfg.get("wait_time", 20)

        scanner = Scanner(rate, interface, wait_time)
        logger.debug("Параметры сканирования: число пакетов в сек. = %s, сетевой интерфейс = %s, время ожидания = %s",
                     rate, interface, wait_time)
        hosts = await scanner.scan(targets=valid_targets, ports=ports)
        logger.info(f"Сканирование завершено. Найдено хостов с открытыми портами: {len(hosts)}")

        if not hosts:
            logger.info("Открытых портов не найдено.")
            await db.finish_scan(scan_id=scan_id, status="completed")
            return

        ips = [host["ip"] for host in hosts]
        previous_states = await db.get_previous_states(ips=ips)

        logger.info("Сравнение и запись результатов")
        diff = compare_states(
            scan_id=uuid.UUID(scan_id),
            previous_states=previous_states,
            hosts=hosts
        )

        await db.save_scan_results(scan_id=scan_id, hosts=hosts)
        await db.apply_scan_diff(scan_id=scan_id, diff=diff)

        await db.finish_scan(scan_id=scan_id, status="completed")

        logger.info("Отправка уведомлений")
        if vk_token and vk_admin_id:
            unnotified_events = await db.get_unnotified_events(limit=50)
            if unnotified_events:
                notified_ids = []
                for event in unnotified_events:
                    ip, port = event["ip"], event["port"]
                    e_type = event["event_type"]
                    detail = event["detail"]

                    msg = format_vk_message(event)

                    success = await send_vk_notification(vk_token, vk_admin_id, msg)
                    if success:
                        notified_ids.append(event["id"])
                    await asyncio.sleep(0.3)

                if notified_ids:
                    await db.mark_events_notified(event_ids=notified_ids)
        else:
            logger.info("Токен ВК не настроен, пропускаем отправку.")

    except Exception as e:
        logger.exception("Фатальная ошибка при сканировании:")
        await db.finish_scan(scan_id=scan_id, status="failed")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())