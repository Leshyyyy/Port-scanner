import asyncio
from pydantic import ValidationError

from models.scan_models import *

class TargetManager:
    def __init__(self):
        pass

    async def _resolve_asn(self, asn: str)-> list:
        try:
            asn=ASNTarget(asn=asn).asn
        except ValidationError:
            return []

        resolve_process = await asyncio.create_subprocess_exec("whois", "-i", "origin", asn,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        process_out, _=await resolve_process.communicate()
        text=process_out.decode(errors="ignore")
        cidrs=[]
        for line in text.splitlines():
            if line.lower().startswith("route:"):
                parts=line.split()
                if  len(parts) >=2:
                    try:
                        cidrs.append(ResolveCidr(cidr=parts[1]).cidr)
                    except ValidationError:
                        pass
        return cidrs

    async def prepare_targets(self, targets:list) ->list:
        valid_targets=[]
        for target in targets:
            target=str(target).strip()
            if target.lower().startswith("as"):
                resolved_cidrs = await self._resolve_asn(target)
                valid_targets.extend(resolved_cidrs)
            else:
                valid_targets.append(target)
        targets=[]
        for target in valid_targets:
            try:
                targets.append(ScanTarget(target=target).target)
            except ValidationError:
                pass

        return list(set(targets))