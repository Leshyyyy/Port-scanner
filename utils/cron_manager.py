import subprocess
import logging

logger=logging.getLogger(__name__)

MARKER = "# scanner-worker-don't-delete"

def get_current_crontab() -> str:
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""

def set_crontab(content: str) -> None:
    #subprocess.run(["crontab", "-"], input=content, text=True, check=True)
    pass

def build_cron_line(minute: str, hour: str, day: str, month: str, weekday: str, command: str) -> str:
    return f"{minute} {hour} {day} {month} {weekday} {command} {MARKER}"

def sync_schedule(cron_line: str) -> None:
    current = get_current_crontab()
    lines = [l for l in current.splitlines() if MARKER not in l]
    if cron_line.strip() not in current:
        logger.info("Расписание изменилось (или задачи не было) — обновляем crontab")
    else:
        logger.info("Расписание уже соответствует конфигу — ничего не делаем")
        return

    lines.append(cron_line)
    set_crontab("\n".join(lines) + "\n")