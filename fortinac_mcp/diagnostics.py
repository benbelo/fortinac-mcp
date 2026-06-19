"""Intelligent diagnostics engine for rogue hosts.

Cross-references each rogue host against profiling rules to determine
which conditions fail and suggest remediation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from .client import FortiNACClient
from .scanner import nmap_scan, lookup_oui, ScanResult


@dataclass
class ConditionCheck:
    name: str
    expected: str
    actual: str
    passed: bool
    detail: str = ""


@dataclass
class RogueDiagnostic:
    host_id: int
    mac: str
    ip: str
    vendor: str
    vendor_api: str
    location: str
    host_name: str
    host_type: str
    candidate_profiles: list[str] = field(default_factory=list)
    checks: list[ConditionCheck] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    scan: ScanResult | None = None

    def summary(self) -> str:
        lines = [
            f"Device: {self.mac} ({self.ip or 'no IP'})",
            f"  Host: {self.host_name} | Type: {self.host_type}",
            f"  Vendor OUI: {self.vendor} | API vendor: {self.vendor_api}",
            f"  Location: {self.location or 'unknown'}",
        ]
        if self.scan and self.scan.open_ports:
            ports_str = ", ".join(
                f"{p}/{self.scan.services.get(p, '?')}" for p in self.scan.open_ports[:10]
            )
            lines.append(f"  Open ports: {ports_str}")

        if self.candidate_profiles:
            lines.append(f"  Candidate profiles: {', '.join(self.candidate_profiles)}")

        passed = [c for c in self.checks if c.passed]
        failed = [c for c in self.checks if not c.passed]

        if passed:
            lines.append("  Passed:")
            for c in passed:
                lines.append(f"    + {c.name}: {c.actual}")
        if failed:
            lines.append("  Failed:")
            for c in failed:
                lines.append(f"    - {c.name}: {c.actual} (expected: {c.expected})")
                if c.detail:
                    lines.append(f"      > {c.detail}")

        if self.suggestions:
            lines.append("  Suggestions:")
            for s in self.suggestions:
                lines.append(f"    > {s}")

        return "\n".join(lines)


def _extract_host_data(host: dict) -> dict:
    """Normalize host + adapter data into a flat dict for diagnosis."""
    adapters = host.get("adapterObjects", [])
    ip = host.get("ip")
    location = ""
    vendor_api = ""
    for a in adapters:
        if isinstance(a, dict):
            if not ip:
                ip = a.get("ipaddress")
                if not ip:
                    ips = a.get("ips", [])
                    if ips:
                        ip = ips[0]
            if not location:
                location = a.get("location", "")
            if not vendor_api:
                vendor_api = a.get("vendorName", "")
    return {
        "id": host.get("id", 0),
        "mac": host.get("primaryMac", ""),
        "ip": ip,
        "hostName": host.get("hostName", ""),
        "typeLabel": host.get("typeLabel", ""),
        "location": location,
        "vendorApi": vendor_api,
        "connected": host.get("connected", False),
    }


def _ip_in_range(ip_str: str, start: str, end: str) -> bool:
    try:
        ip = int(ipaddress.ip_address(ip_str))
        return int(ipaddress.ip_address(start)) <= ip <= int(ipaddress.ip_address(end))
    except ValueError:
        return False


def _check_vendor_oui(method: dict, vendor_oui: str, vendor_api: str) -> ConditionCheck:
    expected_vendors = method.get("values", [])
    expected_str = " | ".join(expected_vendors)
    vendor_oui = vendor_oui or ""
    vendor_api = vendor_api or ""
    matched = any(
        exp.lower() in vendor_oui.lower() or exp.lower() in vendor_api.lower()
        for exp in expected_vendors
    )
    actual = f"{vendor_oui}" + (f" (API: {vendor_api})" if vendor_api else "")
    return ConditionCheck(
        name="Vendor OUI",
        expected=expected_str,
        actual=actual,
        passed=matched,
    )


def _check_tcp_ports(method: dict, scan: ScanResult | None) -> list[ConditionCheck]:
    expected_ports = method.get("ports", [])
    if not expected_ports:
        return []
    if not scan:
        return [ConditionCheck(
            name="TCP Ports",
            expected=", ".join(str(p) for p in expected_ports),
            actual="scan not run",
            passed=False,
            detail="nmap not available or no IP",
        )]
    checks = []
    for port in expected_ports:
        is_open = port in scan.open_ports
        svc = scan.services.get(port, "")
        checks.append(ConditionCheck(
            name=f"TCP Port {port}",
            expected="open",
            actual=f"open ({svc})" if is_open else "closed/filtered",
            passed=is_open,
        ))
    return checks


def _check_dhcp(method: dict, host_data: dict) -> ConditionCheck:
    expected = method.get("values", [])
    expected_str = " | ".join(expected)
    return ConditionCheck(
        name="DHCP Fingerprint",
        expected=expected_str,
        actual="no DHCP data available via API",
        passed=False,
        detail="Device may use static IP, or DHCP data not exposed in host object",
    )


def _check_ip_range(method: dict, ip: str | None) -> ConditionCheck:
    ranges = method.get("ranges", [])
    range_strs = [f"{r['start']}-{r['end']}" for r in ranges]
    expected_str = ", ".join(range_strs)
    if not ip:
        return ConditionCheck(
            name="IP Range",
            expected=expected_str,
            actual="no IP assigned",
            passed=False,
            detail="Device has no IP — offline or static without DHCP",
        )
    matched = any(_ip_in_range(ip, r["start"], r["end"]) for r in ranges)
    return ConditionCheck(
        name="IP Range",
        expected=expected_str,
        actual=ip,
        passed=matched,
    )


def _check_fortiguard(method: dict, vendor_oui: str, vendor_api: str, host_type: str) -> ConditionCheck:
    filters = method.get("filters", [])
    expected_str = " | ".join(filters)
    vendor_oui = vendor_oui or ""
    vendor_api = vendor_api or ""
    matched = any(
        vendor_oui.lower() in f.lower() or vendor_api.lower() in f.lower()
        for f in filters
    ) if (vendor_oui or vendor_api) else False
    return ConditionCheck(
        name="FortiGuard IoT ID",
        expected=expected_str,
        actual=f"vendor={vendor_api or vendor_oui}, type={host_type}",
        passed=matched,
        detail="" if matched else "FortiGuard matching is server-side; this is a best-effort check based on vendor name",
    )


async def diagnose_rogue(
    client: FortiNACClient,
    host: dict,
    rules: list[dict],
    run_nmap: bool = True,
    nmap_ports: str = "1-1024",
) -> RogueDiagnostic:
    data = _extract_host_data(host)
    mac = data["mac"]
    ip = data["ip"]
    vendor_oui = lookup_oui(mac) if mac else "Unknown"

    diag = RogueDiagnostic(
        host_id=data["id"],
        mac=mac,
        ip=ip or "",
        vendor=vendor_oui,
        vendor_api=data["vendorApi"],
        location=data["location"],
        host_name=data["hostName"],
        host_type=data["typeLabel"],
    )

    scan = None
    if run_nmap and ip:
        scan = await nmap_scan(ip, ports=nmap_ports)
        diag.scan = scan

    for rule in rules:
        if not rule.get("enabled", False):
            continue

        rule_name = rule["name"]
        rule_checks: list[ConditionCheck] = []

        for method in rule.get("methods", []):
            mtype = method.get("type", "")

            if mtype == "VENDOR_OUI":
                rule_checks.append(_check_vendor_oui(method, vendor_oui, data["vendorApi"]))
            elif mtype == "TCP_PORTS":
                rule_checks.extend(_check_tcp_ports(method, scan))
            elif mtype == "DHCP_FINGERPRINT":
                rule_checks.append(_check_dhcp(method, data))
            elif mtype == "IP_RANGE":
                rule_checks.append(_check_ip_range(method, ip))
            elif mtype == "FORTIGUARD":
                rule_checks.append(_check_fortiguard(method, vendor_oui, data["vendorApi"], data["typeLabel"]))
            elif mtype == "SNMP_OID":
                rule_checks.append(ConditionCheck(
                    name=f"SNMP OID {method.get('oid', '?')}",
                    expected=method.get("value", "?"),
                    actual="not testable via API",
                    passed=False,
                    detail="SNMP check is server-side only",
                ))
            elif mtype == "LOCATION":
                expected_locs = method.get("values", [])
                actual_loc = data["location"]
                matched = any(e.lower() in actual_loc.lower() for e in expected_locs) if actual_loc else False
                rule_checks.append(ConditionCheck(
                    name="Location",
                    expected=" | ".join(expected_locs),
                    actual=actual_loc or "unknown",
                    passed=matched,
                ))

        if not rule_checks:
            continue

        passed = [c for c in rule_checks if c.passed]
        failed = [c for c in rule_checks if not c.passed]

        if not failed:
            diag.candidate_profiles.append(f"{rule_name} [ALL MATCH]")
        elif passed:
            diag.candidate_profiles.append(
                f"{rule_name} [{len(passed)}/{len(rule_checks)} match, failing: {', '.join(c.name for c in failed)}]"
            )

        for c in rule_checks:
            c.name = f"[{rule_name}] {c.name}"
        diag.checks.extend(rule_checks)

    _generate_suggestions(diag)
    return diag


def _generate_suggestions(diag: RogueDiagnostic):
    failed = [c for c in diag.checks if not c.passed]
    passed = [c for c in diag.checks if c.passed]

    if not diag.checks:
        diag.suggestions.append(
            "No profiling rule has any condition matching this device. "
            "Consider creating a new rule based on its vendor OUI."
        )
        return

    if not diag.ip:
        diag.suggestions.append(
            "Device has no IP. It is offline or using a static IP without DHCP. "
            "IP Range and TCP Port checks cannot be evaluated. "
            "Enable L3 polling or reconnect the device."
        )

    # Count failures by type across all rules
    fail_types: dict[str, int] = {}
    for c in failed:
        # Strip rule name prefix
        short = c.name.split("] ", 1)[-1] if "] " in c.name else c.name
        base = short.split(" ")[0] if short.startswith("TCP") else short
        fail_types[base] = fail_types.get(base, 0) + 1

    vendor_matches = [c for c in passed if "Vendor" in c.name]
    if vendor_matches and len(fail_types) <= 2:
        diag.suggestions.append(
            f"Vendor OUI matches at least one rule. Only {len(fail_types)} other condition type(s) failing. "
            "This device is close to being classified."
        )

    if "IP" in fail_types and diag.ip:
        diag.suggestions.append(
            f"IP {diag.ip} is outside the expected ranges. "
            "Either the device is on the wrong VLAN or the profiling rule range needs updating."
        )

    port_failures = [c for c in failed if "TCP Port" in c.name]
    if port_failures:
        ports = [c.name.split("Port ")[-1] for c in port_failures if "Port " in c.name]
        diag.suggestions.append(
            f"Expected TCP ports {', '.join(ports)} are closed. "
            "Verify the device services are running, or adjust the rule if this device type doesn't use those ports."
        )
