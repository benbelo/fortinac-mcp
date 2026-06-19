"""Network scanning utilities for rogue host diagnostics."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import json
import re
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    os_guess: str = ""
    mac_vendor: str = ""
    services: dict[int, str] = field(default_factory=dict)
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "open_ports": self.open_ports,
            "os_guess": self.os_guess,
            "mac_vendor": self.mac_vendor,
            "services": self.services,
        }


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


async def nmap_scan(ip: str, ports: str = "1-1024", os_detect: bool = False) -> ScanResult:
    """Run nmap against a target IP. Requires nmap installed."""
    if not _nmap_available():
        return ScanResult(ip=ip, raw="nmap not installed")

    cmd = ["nmap", "-sV", "-p", ports, "--open", "-oX", "-", ip]
    if os_detect:
        cmd.insert(1, "-O")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    xml_output = stdout.decode()

    result = ScanResult(ip=ip, raw=xml_output)

    for m in re.finditer(r'<port protocol="tcp" portid="(\d+)".*?<state state="open"', xml_output, re.DOTALL):
        port = int(m.group(1))
        result.open_ports.append(port)

    for m in re.finditer(r'<port protocol="tcp" portid="(\d+)".*?<service name="([^"]*)"', xml_output, re.DOTALL):
        port = int(m.group(1))
        service = m.group(2)
        result.services[port] = service

    os_match = re.search(r'<osmatch name="([^"]*)"', xml_output)
    if os_match:
        result.os_guess = os_match.group(1)

    vendor_match = re.search(r'<address addr="[^"]*" addrtype="mac" vendor="([^"]*)"', xml_output)
    if vendor_match:
        result.mac_vendor = vendor_match.group(1)

    return result


OUI_DB: dict[str, str] = {}


def lookup_oui(mac: str) -> str:
    """Lookup vendor from MAC OUI prefix. Uses nmap's oui db if available."""
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]

    if not OUI_DB:
        oui_path = "/opt/homebrew/share/nmap/nmap-mac-prefixes"
        try:
            with open(oui_path) as f:
                for line in f:
                    if line and not line.startswith("#"):
                        parts = line.strip().split(" ", 1)
                        if len(parts) == 2:
                            OUI_DB[parts[0]] = parts[1]
        except FileNotFoundError:
            pass

    return OUI_DB.get(prefix, "Unknown")
