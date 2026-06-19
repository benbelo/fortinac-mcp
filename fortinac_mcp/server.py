"""FortiNAC MCP Server — rogue host diagnostics tools."""

from __future__ import annotations

import json
import os
from mcp.server.fastmcp import FastMCP
from .client import FortiNACClient
from .scanner import nmap_scan, lookup_oui, _nmap_available
from .diagnostics import diagnose_rogue, _extract_host_data

mcp = FastMCP(
    "FortiNAC",
    instructions="FortiNAC rogue host diagnostics and management",
)


def _get_client() -> FortiNACClient:
    url = os.environ.get("FORTINAC_URL")
    token = os.environ.get("FORTINAC_TOKEN")
    verify = os.environ.get("FORTINAC_VERIFY_SSL", "false").lower() == "true"
    if not url or not token:
        raise ValueError(
            "Set FORTINAC_URL and FORTINAC_TOKEN environment variables. "
            "Example: FORTINAC_URL=https://fortinac.local FORTINAC_TOKEN=your-api-token"
        )
    return FortiNACClient(url, token, verify_ssl=verify)


@mcp.tool()
async def list_rogues(limit: int = 50, connected_only: bool = False) -> str:
    """List rogue (unregistered) hosts on FortiNAC.

    Args:
        limit: Max number of rogues to return (default 50).
        connected_only: Only show currently connected rogues (default False).
    """
    client = _get_client()
    try:
        hosts = await client.list_hosts(filter_str="role==NAC-Default|role==null")
        if connected_only:
            hosts = [h for h in hosts if h.get("connected")]
        rogues = hosts[:limit]

        if not rogues:
            return "No rogue hosts found."

        lines = [f"Found {len(rogues)} rogue hosts:\n"]
        for h in rogues:
            data = _extract_host_data(h)
            vendor = lookup_oui(data["mac"]) if data["mac"] else "?"
            status = "ONLINE" if h.get("connected") else "offline"
            lines.append(
                f"  {data['mac']} | {data['ip'] or 'no IP'} | {vendor} "
                f"| {data['hostName']} | {data['typeLabel']} | {status} "
                f"| {data['location'] or '-'}"
            )

        return "\n".join(lines)
    finally:
        await client.close()


@mcp.tool()
async def diagnose_rogues(
    limit: int = 10,
    connected_only: bool = True,
    run_nmap: bool = True,
    nmap_ports: str = "1-1024",
) -> str:
    """Run intelligent diagnostics on rogue hosts.

    For each rogue, cross-references against all profiling rules and checks
    every condition (vendor OUI, TCP ports via nmap, DHCP fingerprint,
    IP range, FortiGuard IoT ID) to identify exactly which conditions
    are failing and why.

    Args:
        limit: Max number of rogues to diagnose (default 10).
        connected_only: Only diagnose connected rogues (default True).
        run_nmap: Whether to run nmap scans (default True).
        nmap_ports: Port range for nmap scanning (default "1-1024").
    """
    client = _get_client()
    try:
        hosts = await client.list_hosts(filter_str="role==NAC-Default|role==null")
        if connected_only:
            hosts = [h for h in hosts if h.get("connected")]
        rogues = hosts[:limit]

        if not rogues:
            return "No rogue hosts found" + (" (connected)" if connected_only else "") + "."

        rules = await client.export_profiler_rules()
        enabled_rules = [r for r in rules if r.get("enabled")]

        if not enabled_rules:
            return (
                f"Found {len(rogues)} rogues but no enabled profiling rules. "
                "Check API permissions or FortiNAC profiling configuration."
            )

        nmap_status = "enabled" if run_nmap and _nmap_available() else "disabled"
        lines = [
            f"Diagnosing {len(rogues)} rogue hosts against {len(enabled_rules)} enabled profiling rules",
            f"Nmap scanning: {nmap_status} (ports: {nmap_ports})",
            "=" * 60,
        ]

        for host in rogues:
            diag = await diagnose_rogue(
                client, host, enabled_rules,
                run_nmap=run_nmap and _nmap_available(),
                nmap_ports=nmap_ports,
            )
            lines.append(diag.summary())
            lines.append("-" * 60)

        lines.append(f"\nDiagnosed {len(rogues)} rogue hosts.")
        return "\n".join(lines)
    finally:
        await client.close()


@mcp.tool()
async def diagnose_host(mac: str, run_nmap: bool = True, nmap_ports: str = "1-1024") -> str:
    """Run diagnostics on a single host by MAC address.

    Args:
        mac: MAC address of the device (e.g. "AA:BB:CC:DD:EE:FF").
        run_nmap: Whether to run an nmap scan (default True).
        nmap_ports: Port range for nmap scanning (default "1-1024").
    """
    client = _get_client()
    try:
        host_data = await client.get_host_by_mac(mac)
        if not host_data:
            return f"Host {mac} not found in FortiNAC."

        if isinstance(host_data, dict) and "results" in host_data:
            results = host_data["results"]
            if not results:
                return f"Host {mac} not found in FortiNAC."
            host_data = results[0]

        rules = await client.export_profiler_rules()
        enabled_rules = [r for r in rules if r.get("enabled")]

        diag = await diagnose_rogue(
            client, host_data, enabled_rules,
            run_nmap=run_nmap and _nmap_available(),
            nmap_ports=nmap_ports,
        )
        return diag.summary()
    finally:
        await client.close()


@mcp.tool()
async def scan_host(ip: str, ports: str = "1-1024", os_detect: bool = False) -> str:
    """Run an nmap scan on a specific IP address.

    Args:
        ip: Target IP address.
        ports: Port range to scan (default "1-1024").
        os_detect: Enable OS detection (requires root/sudo, default False).
    """
    if not _nmap_available():
        return "nmap is not installed. Install with: brew install nmap"

    result = await nmap_scan(ip, ports=ports, os_detect=os_detect)

    lines = [f"Scan results for {ip}:"]
    if result.mac_vendor:
        lines.append(f"  Vendor: {result.mac_vendor}")
    if result.os_guess:
        lines.append(f"  OS: {result.os_guess}")

    if result.open_ports:
        lines.append(f"  Open ports ({len(result.open_ports)}):")
        for port in result.open_ports:
            svc = result.services.get(port, "")
            lines.append(f"    {port}/tcp -- {svc}" if svc else f"    {port}/tcp")
    else:
        lines.append("  No open ports found in range.")

    return "\n".join(lines)


@mcp.tool()
async def lookup_vendor(mac: str) -> str:
    """Look up the vendor/manufacturer for a MAC address.

    Args:
        mac: MAC address (e.g. "AA:BB:CC:DD:EE:FF").
    """
    vendor = lookup_oui(mac)
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return f"MAC: {mac}\nOUI Prefix: {prefix}\nVendor: {vendor}"


@mcp.tool()
async def get_profiling_rules() -> str:
    """Retrieve all device profiling rules from FortiNAC.

    Returns the rules with their conditions, methods, and classification settings.
    """
    client = _get_client()
    try:
        rules = await client.export_profiler_rules()
        return json.dumps(rules, indent=2, default=str)
    finally:
        await client.close()


@mcp.tool()
async def reprofile_all_rogues() -> str:
    """Trigger FortiNAC to re-evaluate all rogue hosts against profiling rules.

    This runs the built-in reprofile process on the FortiNAC server.
    """
    client = _get_client()
    try:
        result = await client.reprofile_rogues()
        return f"Reprofile triggered. Result: {json.dumps(result, default=str)}"
    finally:
        await client.close()


@mcp.tool()
async def get_host_details(mac: str) -> str:
    """Get full details of a host from FortiNAC by MAC address.

    Args:
        mac: MAC address (e.g. "AA:BB:CC:DD:EE:FF").
    """
    client = _get_client()
    try:
        host = await client.get_host_by_mac(mac)
        return json.dumps(host, indent=2, default=str)
    finally:
        await client.close()


@mcp.tool()
async def check_status() -> str:
    """Check FortiNAC connection and available capabilities."""
    issues = []
    caps = []

    url = os.environ.get("FORTINAC_URL", "")
    token = os.environ.get("FORTINAC_TOKEN", "")

    if not url:
        issues.append("FORTINAC_URL not set")
    if not token:
        issues.append("FORTINAC_TOKEN not set")

    if _nmap_available():
        caps.append("nmap: available")
    else:
        issues.append("nmap: NOT installed (brew install nmap)")

    if url and token:
        client = _get_client()
        try:
            count = await client.get_host_count()
            caps.append(f"FortiNAC API: connected ({count} hosts)")

            rules = await client.export_profiler_rules()
            enabled = [r for r in rules if r.get("enabled")]
            caps.append(f"Profiling rules: {len(enabled)} enabled / {len(rules)} total")
        except Exception as e:
            issues.append(f"FortiNAC API: {e}")
        finally:
            await client.close()

    lines = [f"URL: {url or 'NOT SET'}", f"Token: {'set' if token else 'NOT SET'}", ""]
    for c in caps:
        lines.append(f"  OK  {c}")
    for i in issues:
        lines.append(f"  !!  {i}")

    return "\n".join(lines)
