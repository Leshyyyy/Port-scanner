import json
from uuid import UUID
import aiosqlite

def compare_states(scan_id: UUID, previous_states:dict[tuple[str, int], aiosqlite.Row], hosts: list[dict],) -> dict:
    new_states = []
    closed_ports = {}
    events = []

    for host in hosts:
        ip = host["ip"]
        seen_ports = set()

        is_new_host = not any(key[0] == ip for key in previous_states)
        if is_new_host:
            events.append({"ip": ip, "port": None, "event_type": "new_host", "detail": None})

        for port in host["ports"]:
            port_num = port["port"]
            seen_ports.add(port_num)
            prev = previous_states.get((ip, port_num))

            if prev is None:
                events.append({
                    "ip": ip, "port": port_num, "event_type": "new_open_port",
                    "detail": {"service": port.get("service"), "banner": port.get("banner")}
                })
            elif prev["banner"] != port.get("banner") or prev["service"] != port.get("service"):
                events.append({
                    "ip": ip, "port": port_num, "event_type": "service_changed",
                    "detail": {"old_banner": prev["banner"], "new_banner": port.get("banner")}
                })

            old_exploits = json.loads(prev["exploits"]) if prev else []
            old_cves = {e["cve"] for e in old_exploits}
            for exploit in port.get("exploits", []):
                if exploit["cve"] not in old_cves:
                    events.append({
                        "ip": ip, "port": port_num, "event_type": "new_exploit", "detail": exploit
                    })

            new_states.append({
                "ip": ip,
                "port": port_num,
                "service": port.get("service"),
                "banner": port.get("banner"),
                "exploits": port.get("exploits", []),
            })

        closed = [
            key[1] for key, rec in previous_states.items()
            if key[0] == ip and rec["status"] == "open" and key[1] not in seen_ports
        ]
        if closed:
            closed_ports[ip] = closed
            for port_num in closed:
                events.append({"ip": ip, "port": port_num, "event_type": "port_closed", "detail": None})

    return {"new_states": new_states, "closed_ports": closed_ports, "events": events}