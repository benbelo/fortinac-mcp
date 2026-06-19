"""FortiNAC REST API client for version 7.6."""

from __future__ import annotations

import xml.etree.ElementTree as ET
import httpx


class FortiNACClient:
    """Thin wrapper around the FortiNAC REST API v2."""

    def __init__(self, base_url: str, token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=f"{self.base_url}/api/v2",
            headers={"Authorization": f"Bearer {token}"},
            verify=verify_ssl,
            timeout=30.0,
        )

    async def _get(self, path: str, params: dict | None = None) -> dict:
        r = await self._client.get(path, params=params)
        r.raise_for_status()
        return r.json()

    async def _post(self, path: str, json: dict | None = None) -> dict:
        r = await self._client.post(path, json=json)
        r.raise_for_status()
        return r.json()

    # --- Hosts ---

    async def list_hosts(self, filter_str: str | None = None) -> list[dict]:
        params = {}
        if filter_str:
            params["filter"] = filter_str
        data = await self._get("/host", params=params)
        return data.get("results", data.get("result", []))

    async def get_host(self, host_id: int) -> dict:
        return await self._get(f"/host/{host_id}")

    async def get_host_by_mac(self, mac: str) -> dict:
        return await self._get(f"/host/by-mac/{mac}")

    async def get_host_by_ip(self, ip: str) -> dict:
        return await self._get(f"/host/by-ip/{ip}")

    async def get_host_count(self) -> int:
        data = await self._get("/host/count")
        return data.get("total", data.get("result", 0))

    async def trigger_host_scan(self, host_id: int) -> dict:
        return await self._post(f"/host/trigger-scan", json={"id": host_id})

    async def set_host_role(self, host_id: int, role: str) -> dict:
        return await self._post("/host/set-role", json={"id": host_id, "role": role})

    # --- Adapters ---

    async def list_adapters(self, filter_str: str | None = None) -> list[dict]:
        params = {}
        if filter_str:
            params["filter"] = filter_str
        data = await self._get("/adapter", params=params)
        return data.get("results", data.get("result", []))

    async def get_adapter(self, adapter_id: int) -> dict:
        return await self._get(f"/adapter/{adapter_id}")

    async def get_adapter_port(self, adapter_id: int) -> dict:
        return await self._get(f"/adapter/{adapter_id}/get-port")

    async def reprofile_rogues(self) -> dict:
        return await self._post("/adapter/reprofile-rogues")

    # --- Device Profiler ---

    async def get_profiler_settings(self) -> dict:
        return await self._get("/settings/device/device-profiler")

    async def export_profiler_rules_xml(self) -> str:
        r = await self._client.get("/DeviceProfiler/Rule/export")
        r.raise_for_status()
        return r.text

    async def export_profiler_rules(self) -> list[dict]:
        xml_text = await self.export_profiler_rules_xml()
        return _parse_profiler_rules_xml(xml_text)

    # --- Ports ---

    async def get_hosts_on_port(self, port_id: int) -> list[dict]:
        data = await self._get("/host/connected-to-port", params={"portId": port_id})
        return data.get("results", data.get("result", []))

    async def close(self):
        await self._client.aclose()


def _parse_profiler_rules_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    rules = []
    for rule_el in root.findall(".//DpcRule"):
        rule: dict = {
            "name": rule_el.findtext("name", ""),
            "type": rule_el.findtext("type", ""),
            "enabled": rule_el.findtext("enabled", "false") == "true",
            "role": rule_el.findtext("role", ""),
            "rank": int(rule_el.findtext("rank", "0")),
            "registerAutomatically": rule_el.findtext("registerAutomatically", "false") == "true",
            "methods": [],
        }
        methods_el = rule_el.find("methods")
        if methods_el is None:
            rules.append(rule)
            continue

        for method_el in methods_el:
            method = _parse_method(method_el)
            if method:
                rule["methods"].append(method)

        rules.append(rule)
    return rules


def _parse_method(el: ET.Element) -> dict | None:
    enabled = el.findtext("enabled", "false") == "true"
    if not enabled:
        return None

    tag = el.tag
    method_type_name = el.findtext("methodType/shortName", el.findtext("methodType/name", tag))

    if tag == "ouiMethodData":
        values = []
        for f in el.findall(".//filter"):
            val = f.findtext("value", "")
            if val:
                values.append(val)
        return {"type": "VENDOR_OUI", "name": method_type_name, "values": values}

    if tag == "dhcpMethodData":
        filters = []
        for f in el.findall(".//filter"):
            vendor_class = f.findtext("vendorClass", "")
            if vendor_class:
                filters.append(vendor_class)
        return {"type": "DHCP_FINGERPRINT", "name": method_type_name, "values": filters}

    if tag == "tcpPortsMethodData":
        ports_str = el.findtext("ports", "")
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
        return {"type": "TCP_PORTS", "name": method_type_name, "ports": ports}

    if tag == "ipRangeMethodData":
        ranges = []
        for r in el.findall(".//range"):
            start = r.findtext("startIP", "")
            end = r.findtext("endIP", "")
            if start and end:
                ranges.append({"start": start, "end": end})
        return {"type": "IP_RANGE", "name": method_type_name, "ranges": ranges}

    if tag == "fortiGuardMethodData":
        filters = []
        for f in el.findall(".//filter"):
            param_list = f.findtext("parameterList", "")
            if param_list:
                filters.append(param_list)
        return {"type": "FORTIGUARD", "name": method_type_name, "filters": filters}

    if tag == "snmpMethodData":
        oid = el.findtext("oid", "")
        value = el.findtext("value", "")
        return {"type": "SNMP_OID", "name": method_type_name, "oid": oid, "value": value}

    if tag == "locationMethodData":
        values = []
        for f in el.findall(".//filter"):
            val = f.findtext("value", "")
            if val:
                values.append(val)
        return {"type": "LOCATION", "name": method_type_name, "values": values}

    return {"type": tag, "name": method_type_name, "raw": ET.tostring(el, encoding="unicode")}
