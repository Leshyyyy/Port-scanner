import json
from datetime import datetime, timezone
import aiosqlite
from database.migration_run import apply_migrations
import logging


logger = logging.getLogger(__name__)

class DBManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._conn.execute("PRAGMA journal_mode = WAL")
        await apply_migrations(self._conn)
        await self._conn.commit()
        logger.info("БД подключена, миграции применены")


    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            logger.info("Соединение с БД закрыто")



    async def create_scan(self, scan_id: str, targets: list[str]) -> None:
        logger.debug("Начало создания сканирования %s для %d целей", scan_id, len(targets))
        try:
            await self._conn.execute(
                "INSERT INTO scans (scan_id, status, targets, created_at) VALUES (?, 'running', ?, ?)",
                (scan_id, json.dumps(targets), datetime.now(timezone.utc).isoformat())
            )
            await self._conn.commit()
            logger.info("Сканирование %s успешно создано и сохранено в БД", scan_id)
        except Exception:
            logger.exception("Ошибка при создании сканирования %s в БД", scan_id)


    async def finish_scan(self, scan_id: str, status: str) -> None:
        logger.debug("Завершение сканирования %s со статусом '%s'", scan_id, status)
        try:
            await self._conn.execute(
            "UPDATE scans SET status=?, finished_at=? WHERE scan_id=?",
            (status, datetime.now(timezone.utc).isoformat(), scan_id)
            )
            await self._conn.commit()
            logger.info("Сканирование %s завершено со статусом '%s'",scan_id,status)
        except Exception:
            logger.exception("Ошибка при завершении сканирования %s",scan_id)

    async def get_previous_states(self, ips: list[str]) -> dict[tuple[str, int], aiosqlite.Row]:
        if not ips:
            logger.debug("Запрос предыдущих состояний для пустого списка IP")
            return {}
        place = ",".join("?" for _ in ips)
        cursor = await self._conn.execute(
            f"SELECT * FROM port_states WHERE ip IN ({place})",
            ips
        )
        rows = await cursor.fetchall()
        logger.debug("Получено %d записей предыдущих состояний для %d IP", len(rows), len(ips))
        return {(r["ip"], r["port"]): r for r in rows}


    async def save_scan_results(self, scan_id: str, hosts: list[dict]) -> None:
        logger.debug("Сохранение результатов сканирования %s",scan_id)
        try:
            for host in hosts:
                cursor = await self._conn.execute(
                    "INSERT INTO scan_hosts (scan_id, ip) VALUES (?, ?)",
                    (scan_id, host["ip"])
                )
                scan_host_id = cursor.lastrowid
                for port in host["ports"]:
                    await self._conn.execute(
                        """INSERT INTO scan_ports
                           (scan_host_id, port, state, service, banner, exploits)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (scan_host_id, port["port"], port["state"],
                         port.get("service"), port.get("banner"),
                         json.dumps(port.get("exploits", [])))
                    )
            await self._conn.commit()
            logger.info("Результаты сканирования %s успешно сохранены",scan_id)
        except Exception:
            await self._conn.rollback()
            logger.exception("Ошибка при сохранении результатов %s, выполнен откат транзакции", scan_id)
            raise

    async def apply_scan_diff(self, scan_id: str, diff: dict) -> None:
        logger.debug("Применение различий сканирований")
        try:
            now = datetime.now(timezone.utc).isoformat()

            for state in diff["new_states"]:
                await self._conn.execute(
                    """INSERT INTO port_states (ip, port, service, banner, exploits, status, last_scan_id, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
                       ON CONFLICT (ip, port) DO UPDATE SET
                           service=excluded.service,
                           banner=excluded.banner,
                           exploits=excluded.exploits,
                           status='open',
                           last_seen_at=excluded.last_seen_at,
                           last_scan_id=excluded.last_scan_id""",
                    (state["ip"], state["port"], state["service"], state["banner"],
                     json.dumps(state["exploits"]), scan_id, now)
                )

            for ip, ports in diff["closed_ports"].items():
                place = ",".join("?" for _ in ports)
                await self._conn.execute(
                    f"""UPDATE port_states SET status='closed', last_seen_at=?
                        WHERE ip=? AND port IN ({place})""",
                    [now, ip, *ports]
                )

            if diff["events"]:
                await self._conn.executemany(
                    """INSERT INTO events (scan_id, ip, port, event_type, detail, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    [(scan_id, e["ip"], e["port"], e["event_type"],
                      json.dumps(e["detail"]) if e["detail"] is not None else None, now)
                     for e in diff["events"]]
                )

            await self._conn.commit()
            logger.info("Различия сканирований успешно применены")
        except Exception:
            await self._conn.rollback()
            logger.exception("Ошибка в применении различий сканирования")
            raise


    async def get_unnotified_events(self, limit: int = 100) -> list[aiosqlite.Row]:
        cursor = await self._conn.execute(
            "SELECT * FROM events WHERE notified=0 ORDER BY created_at LIMIT ?",
            (limit,)
        )
        rows= await cursor.fetchall()
        if rows:
            logger.info("получено %d неоповещенных событий",len(rows))
        return rows

    async def mark_events_notified(self, event_ids: list[int]) -> None:
        if not event_ids:
            return
        place = ",".join("?" for _ in event_ids)
        await self._conn.execute(
            f"UPDATE events SET notified=1 WHERE id IN ({place})",
            event_ids
        )
        logger.info("%d событий отмечены оповещенными",len(event_ids))
        await self._conn.commit()