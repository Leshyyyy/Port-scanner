from pydantic import BaseModel, Field,field_validator
import re
import ipaddress
from typing import List, Optional

asn_pattern = re.compile(r"^(AS)\d+$")
port_pattern = re.compile(r"^(\d+(-\d+)?)(,(\d+(-\d+)?))*$")

class ScanRequest(BaseModel):
    targets: list[str] = Field(..., description="Список ip адресов и их диапазонов и ASN")
    ports: Optional[str] = Field(default="1-65535", description="диапазон портов для сканирования или их перечисление")
    vk_id: str = Field(..., description="Значение VK ID пользователя для верификации и отправки уведомлений")
    hash: str = Field(...,description="HMAC SHA 256 хэш")

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, targets: list[str]) -> list[str]:
        validated=[]
        for target in targets:
            target=target.strip()
            try:
                ipaddress.ip_address(target)
                validated.append(target)
                continue
            except ValueError:
                pass
            try:
                ipaddress.ip_network(target,strict=False)
                validated.append(target)
                continue
            except ValueError:
                pass
            if asn_pattern.match(target):
                validated.append(target)
                continue
            raise ValueError("Некорректный формат целей для сканирования")
        return validated

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: str) -> str:
        if not ports:
            return "1-65535"
        ports=ports.replace(" ","")
        if not port_pattern.match(ports):
            raise ValueError("Некорректны формат портов цели для сканирования")
        for part in ports.split(","):
            if "-" in part:
                start, end = part.split("-")
                start_d, end_d=int(start), int(end)
                if not(1<=start_d<=65535 and 1<=end_d<=65535):
                    raise ValueError("Порты не принадлежат допустимому диапазону 1-65535")
                if start_d>end_d:
                    raise ValueError("Начало диапазона не может быть больше его конца")
            else:
                port=int(part)
                if not(1<=port<=65535):
                    raise ValueError("Порт не принадлежит допустимому диапазону 1-65535")
        return ports

