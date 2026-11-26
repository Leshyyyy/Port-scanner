from pathlib import Path
import aiosqlite

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

async def apply_migrations(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               filename   TEXT PRIMARY KEY,
               applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    await conn.commit()

    cursor = await conn.execute("SELECT filename FROM schema_migrations")
    applied = {row[0] for row in await cursor.fetchall()}

    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for path in migration_files:
        if path.name in applied:
            continue

        sql = path.read_text(encoding="utf-8")
        try:
            await conn.executescript(sql)
            await conn.execute(
                "INSERT INTO schema_migrations (filename) VALUES (?)", (path.name,)
            )
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise