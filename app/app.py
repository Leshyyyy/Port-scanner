import streamlit as st
import yaml
import json
import pandas as pd
from pathlib import Path
from datetime import datetime

from data_assets import *

CONFIG_PATH = Path(__file__).parents[1] / "config/config.yaml"

with open(CONFIG_PATH, encoding="utf-8") as f:
    config = yaml.safe_load(f)

st.set_page_config(page_title="Port Scanner Dashboard", layout="wide")


st.title("🛡️ Дашборд Сканера Портов")

summary = get_latest_scan_summary()

with st.container(border=True):
    col1, col2 = st.columns(2)

    if summary:
        status = summary.get("status", "unknown").lower()
        finished_at = format_timestamp(summary.get("finished_at"))

        with col1:
            st.markdown("##### 📌 Статус сканирования")
            if status == "completed":
                st.success("### ✅ УСПЕШНО")
            elif status == "running":
                st.info("### 🔄 В ПРОЦЕССЕ")
            else:
                st.error(f"### ❌ {status.upper()}")

        with col2:
            st.markdown("##### ⏱️ Последняя проверка")
            st.info(f"### {finished_at}")

    else:
        st.warning("⚠️ Сканирования ещё не проводились")

st.write("")

if summary:
    with st.container(border=True):
        st.subheader("🔔 События сканирования")

        if summary and summary.get("scan_id"):
            events_df = get_events_for_scan(summary["scan_id"])

            if events_df.empty:
                st.success("Изменений не обнаружено (все порты без изменений)")
            else:
                for ip, group in events_df.groupby("ip"):
                    st.markdown(f"##### 🖥️ Хост: `{ip}`")

                    for _, event in group.iterrows():
                        col_badge, col_event = st.columns([1, 14])

                        with col_badge:
                            if not event.get("notified", 1):
                                st.badge("NEW")

                        with col_event:
                            e_type = str(event["event_type"])
                            detail_text = parse_event_detail(event.get("detail"))

                            port_val = event.get("port")
                            port_str = ""
                            if pd.notna(port_val) and str(port_val).lower() != "nan":
                                try:
                                    port_str = f":{int(float(port_val))}"
                                except Exception:
                                    port_str = f":{port_val}"

                            msg = f"**{e_type.upper()}** {event['ip']}{port_str} — {detail_text}"

                            if "host" in e_type.lower():
                                st.success(msg, icon="🖥️")
                            elif "closed" in e_type.lower():
                                st.info(msg, icon="🔒️")
                            else:
                                st.warning(msg, icon="⚠️")
        else:
            st.info("Нет данных о событиях")

    st.divider()

    st.subheader("🌐 Открытые порты и уязвимости")
    port_states = get_all_port_states()
    if port_states.empty:
        st.info("Пока нет данных о сохранённых портах")
    else:
        search = st.text_input("🔍 Поиск по IP хоста")
        if search:
            port_states = port_states[port_states["ip"].str.contains(search, case=False, na=False)]

        for ip, group in port_states.groupby("ip"):
            with st.expander(f"🖥️ **{ip}** — открыто портов: {len(group)}"):
                for _, port_row in group.iterrows():
                    exploits = []
                    if port_row.get("exploits"):
                        try:
                            exploits = json.loads(port_row["exploits"])
                        except Exception:
                            exploits = []

                    label = format_port_label(
                        port_row["port"],
                        port_row.get("service"),
                        port_row.get("banner")
                    )

                    if exploits:
                        c_msg, c_pop = st.columns([12, 1])
                        with c_msg:
                            st.warning(f"⚠️ **{label}** (Найдено уязвимостей: {len(exploits)})")
                        with c_pop:
                            with st.popover("⚠️"):
                                st.markdown(f"### ⚠️ Уязвимости порта {port_row['port']}")
                                for e in exploits:
                                    cve = e.get("cve", "CVE N/A")
                                    title = e.get("title", "Без названия")
                                    url = e.get("url")
                                    st.write(f"• **{cve}** — {title}")
                                    if url:
                                        st.markdown(f"  [Ссылка на источник]({url})")
                    else:
                        st.success(f"✅ {label}")