from typing import Annotated
from pydantic import BaseModel, Field,field_validator
import re
import ipaddress

asn_pattern = re.compile(r"^(AS)\d+$")
cve_pattern = re.compile(r"^CVE-\d{4}-\d+$")

class ASNTarget(BaseModel):
    asn: str = Field(...,description="Номер ASN")

    @field_validator("asn")
    @classmethod
    def validate_asn(cls, value: str) -> str:
        value = value.strip().upper()
        if not asn_pattern.match(value):
            raise ValueError("Данные не соответствуют формату ASN")
        return value

class ResolveCidr(BaseModel):
    cidr: str = Field(..., description="CIDR диапазон полученный при проверке ASN")

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"Некорректный CIDR, полученный от whois: {value}")
        return value


class ScanTarget(BaseModel):
    target: str = Field(..., description="Цель для masscan")

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        value = value.strip()
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            pass
        raise ValueError(f"Цель не является валидным IP/CIDR: {value}")


class MasscanResultEntry(BaseModel):
    ip: str = Field(..., description="ip цели для nmap")
    port: int= Field(...,ge=1, le=65535, description="Порт для nmap")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"Некорректный IP в результатах masscan: {value}")
        return value


class CVEQuery(BaseModel):
    cve: str = Field(..., description="CVE номер для поиска в exploit db")

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, value: str) -> str:
        if not cve_pattern.match(value):
            raise ValueError(f"Некорректный формат CVE: {value}")
        return value
