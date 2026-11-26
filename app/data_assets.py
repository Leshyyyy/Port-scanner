import streamlit as st
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime
import json
import logging

DB_PATH = Path(__file__).parents[1] / "database/scanner.db"


@st.cache_data(ttl=30)
def get_latest_scan_summary() -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

        return dict(row) if row else {}
    except Exception:
        logging.exception("Ошибка в получении результатов последнего сканирования")
        return {}
    finally:
        conn.close()


@st.cache_data(ttl=30)
def get_events_for_scan(scan_id: str) -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql_query(
            "SELECT * FROM events WHERE scan_id = ? ORDER BY created_at DESC",
            conn, params=(scan_id,)
        )
    finally:
        conn.close()


@st.cache_data(ttl=60)
def get_all_port_states() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql_query("SELECT * FROM port_states ORDER BY ip, port", conn)
    finally:
        conn.close()


def format_timestamp(ts_str: str) -> str:
    if not ts_str or str(ts_str).lower() in ["none", "nan", ""]:
        return "—"
    try:
        dt_utc = datetime.fromisoformat(ts_str)
        local_tz = datetime.now().astimezone().tzinfo
        dt_local = dt_utc.astimezone(local_tz)

        return dt_local.strftime("%d.%m.%Y в %H:%M:%S")
    except Exception:
        return str(ts_str)


def clean_text(val) -> str:
    if pd.isna(val) or val is None:
        return ""
    s = str(val).strip()
    if s.lower() in ["none", "nan", "null", "none none", "gws none"]:
        s = s.replace("None", "").replace("nan", "").strip()
    return s


def format_port_label(port, service, banner) -> str:
    try:
        port_str = str(int(float(port)))
    except (ValueError, TypeError):
        port_str = str(port)

    s_clean = clean_text(service)
    b_clean = clean_text(banner)
    service_part = s_clean if s_clean else ""
    if service_part and b_clean:
        return f"{port_str}/{service_part} — {b_clean}"
    elif service_part:
        return f"{port_str}/{service_part}"
    elif b_clean:
        return f"{port_str} — {b_clean}"
    else:
        return f"{port_str}"


def parse_event_detail(detail_raw) -> str:
    if not detail_raw or pd.isna(detail_raw):
        return ""
    try:
        data = json.loads(detail_raw) if isinstance(detail_raw, str) else detail_raw
        if isinstance(data, dict):
            parts = []
            for k, v in data.items():
                v_clean = clean_text(v)
                if v_clean:
                    parts.append(f"**{k}**: {v_clean}")
            return ", ".join(parts)
        return str(data)
    except Exception:
        return str(detail_raw)