import asyncio
import tempfile
import subprocess
import re
import json
import xml.etree.ElementTree as ET
from models.scan_models import *
from pydantic import ValidationError
import psutil
import logging

logger=logging.getLogger(__name__)

def _detect_default_interface() -> str:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, stat in stats.items():
        if not stat.isup or name.lower() in ("lo", "loopback"):
            continue

        if name in addrs and any(a.family.name == "AF_INET" for a in addrs[name]):
            return name

    raise RuntimeError("Не удалось автоматически определить активный сетевой интерфейс. Укажите его вручную")

class Scanner:
    def __init__(self, rate: int = 1000, interface: str | None = None, wait_time: int = 20):
        self.rate = rate
        self.e = interface if interface else _detect_default_interface()
        self.wait_time = wait_time

    async def _run_masscan(self, targets: list[str] , ports: str) -> dict:
        with tempfile.NamedTemporaryFile(mode="w+",delete=True) as temp_targets, \
            tempfile.NamedTemporaryFile(mode="r+",delete=True) as temp_masscan_results:
            for target in targets:
                try:
                    valid_target = ScanTarget(target=target).target
                except ValidationError:
                    continue

                temp_targets.write(f"{valid_target}\n")
            temp_targets.flush()

            masscan_process = await asyncio.create_subprocess_exec("masscan","-iL", temp_targets.name,
                "-p", ports, "--rate", str(self.rate), "-e", self.e, "--wait", str(self.wait_time), "-oJ", temp_masscan_results.name,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr=await masscan_process.communicate()
            temp_masscan_results.seek(0)
            try:
                data=json.load(temp_masscan_results)
            except Exception:
                data=[]
                logger.exception("Ошибка при выполнении masscan")

        masscan_results={}
        for entry in data:
            ip = entry.get("ip")
            port= entry.get("ports",[{}])[0].get("port")
            if ip and port:
                try:
                    validated = MasscanResultEntry(ip=ip, port=port)
                except ValidationError:
                    continue
                if validated.ip not in masscan_results:
                    masscan_results[validated.ip]=[]
                masscan_results[validated.ip].append(validated.port)
        return masscan_results


    async def _run_nmap(self, masscan_results: dict) -> list:
        results=[]
        for ip, ports in masscan_results.items():
            port_str=",".join(map(str,ports))
            nmap_process= await asyncio.create_subprocess_exec( "nmap", "-sV", "-p", port_str,"--script",
                "vulners", "-oX", "-", ip, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            nmap_xml_out, _ = await nmap_process.communicate()
            host_data = {"ip": ip, "ports": []}
            try:
                data=ET.fromstring(nmap_xml_out)
                for port_element in data.findall(".//port"):
                    port_id=port_element.get("portid")
                    state_element = port_element.find(".//state")
                    port_state = state_element.get("state") if state_element is not None else "closed"
                    if port_state not in ("open", "closed"):
                        port_state = "closed"

                    service_element=port_element.find(".//service")
                    name=service_element.get("name") if service_element is not None else "unknown"
                    product=service_element.get("product") if service_element is not None else ""
                    version=service_element.get("version") if service_element is not None else ""

                    cves=[]
                    for script in port_element.findall(".//script[@id='vulners']"):
                        script_out=script.get("output", "")
                        found_cves=re.findall(r"CVE-\d{4}-\d+",script_out)
                        cves.extend(found_cves)
                    cves = sorted(set(cves))
                    exploits=[]
                    if cves:
                        tasks= [self._exploitdb_scan(cve) for cve in cves]
                        exploitdb_results= await asyncio.gather(*tasks)
                        seen_cves = set()
                        for r in exploitdb_results:
                            for exploit in r:
                                if exploit["cve"] not in seen_cves:
                                    seen_cves.add(exploit["cve"])
                                    exploits.append(exploit)

                        exploits.sort(key=lambda e: e["title"] is None)

                    host_data["ports"].append({
                        "port": int(port_id),
                        "state": port_state,
                        "service": name,
                        "banner": f"{product} {version}".strip(),
                        "exploits": exploits[:10]
                    })
            except Exception:
                logger.exception("Ошибка при выполнении nmap сканирования")

            results.append(host_data)
        return results

    async def _exploitdb_scan(self, query:str) ->list:
        if not query or len(query)<3:
            print("no query")
            return []
        try:
            query = CVEQuery(cve=query).cve
            logger.debug("query=",query)
        except ValidationError:
            return []
        try:
            exploitdb_scan_process=await asyncio.create_subprocess_exec("searchsploit", "-j", query,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            exploitdb_scan_out, _ = await exploitdb_scan_process.communicate()
            logger.debug("Exploit_scan_out=", exploitdb_scan_out)
            if not exploitdb_scan_out:
                return [{
                    "title": None,
                    "cve": query,
                    "url": None,
                    "platform": None,
                    "type": None
                }]
            data=json.loads(exploitdb_scan_out.decode(errors="ignore"))
            exploits=data.get("RESULTS_EXPLOIT",[])

            if not exploits:
                return [{
                    "title": None,
                    "cve": query,
                    "url": None,
                    "platform": None,
                    "type": None
                }]
            results=[]
            for exploit in exploits:
                path = exploit.get("Path", "")
                exploit_id = ""
                if path:
                    filename = path.split("/")[-1]
                    exploit_id = filename.split(".")[0]

                url = f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id.isdigit() else ""

                results.append({
                    "title": exploit.get("Title"),
                    "cve": query,
                    "url": url,
                    "platform": exploit.get("Platform"),
                    "type": exploit.get("Type")
                })
                logger.debug("results=",results)
            return results

        except Exception:
            logger.exception("Ошибка при использовании searchsploit")
            return [{
                "title": None,
                "cve": query,
                "url": None,
                "platform": None,
                "type": None
            }]


    async def scan(self,targets: list[str], ports: str):
        masscan_results= await self._run_masscan(targets, ports)
        if not masscan_results:
            return []

        final_results = await self._run_nmap(masscan_results)
        return final_results