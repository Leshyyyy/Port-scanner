import logging
from vkbottle import API, VKAPIError
import json

logger = logging.getLogger(__name__)


EVENT_MAP = {
    "new_open_port": ("🚨", "Обнаружен открытый порт"),
    "new_host": ("🖥️", "Найден новый хост"),
    "closed_port": ("🔒️", "Порт был закрыт"),
    "new_exploit": ("⚠️", "Найдена уязвимость!"),
}
def format_vk_message(event: dict) -> str:
    if not isinstance(event, dict):
        event = dict(event)
    e_type = str(event.get("event_type", "")).lower()
    ip = event.get("ip", "")
    port = event.get("port")
    detail_raw = event.get("detail")
    icon, title = EVENT_MAP.get(e_type, ("🔔", e_type.upper()))
    port_str = f":{port}" if port else ""

    lines = [
        f"{icon} {title}",
        "",
        f"📍 Хост: {ip}{port_str}"
    ]

    if detail_raw:
        try:
            detail = json.loads(detail_raw) if isinstance(detail_raw, str) else detail_raw
            if isinstance(detail, dict):
                key_map = {"service": "🛠️ Сервис", "banner": "🏷️ Баннер", "cve": "⚠️ CVE"}
                for k, v in detail.items():
                    if v and str(v).lower() not in ["none", "nan"]:
                        label = key_map.get(k, f"• {k.capitalize()}")
                        lines.append(f"{label}: {v}")
            else:
                lines.append(f"📄 Детали: {detail_raw}")
        except Exception:
            lines.append(f"📄 Детали: {detail_raw}")

    return "\n".join(lines)

async def send_vk_notification(vk_token: str, user_id: str, message: str) -> bool:
    api = API(token=vk_token)
    try:
        await api.messages.send(
            user_id=int(user_id),
            message=message,
            random_id=0
        )
        return True
    except VKAPIError as e:
        logger.error(f"Ошибка VK API: {e}")
        return False
    except Exception as e:
        logger.error(f"Исключение при отправке VK: {e}")
        return False
    finally:
        await api.http_client.close()