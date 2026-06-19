"""One-shot script: generate rogue reports on Desktop."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from fortinac_mcp.client import FortiNACClient


def get_adapter_ip(adapter):
    ip = adapter.get("ipaddress")
    if ip:
        return str(ip)
    ips = adapter.get("ips")
    if ips and isinstance(ips, list) and ips:
        first = ips[0]
        if isinstance(first, dict):
            return str(first.get("ip", ""))
        return str(first)
    return ""


async def main():
    url = os.environ.get("FORTINAC_URL")
    token = os.environ.get("FORTINAC_TOKEN")
    if not url or not token:
        print("Set FORTINAC_URL and FORTINAC_TOKEN environment variables.")
        sys.exit(1)
    verify = os.environ.get("FORTINAC_VERIFY_SSL", "false").lower() == "true"
    client = FortiNACClient(url, token, verify_ssl=verify)

    all_hosts = []
    start = 0
    while True:
        data = await client._get("/host", params={"start": start, "count": 200})
        results = data.get("results", [])
        all_hosts.extend(results)
        if len(results) < 200:
            break
        start += 200
        if start > 6000:
            break

    rogues = [h for h in all_hosts if h.get("role") is None]

    # --- Report 1: Snom diagnostic ---
    snom_report = []
    snom_report.append("Diagnostic IP Phones Snom restant en Rogue")
    snom_report.append("=" * 60)
    snom_report.append("")
    snom_report.append("2 regles de profiling ciblent les Snom : Profile-IPPHONE-detailed et Profile-IPPHONE.")
    snom_report.append("214 IP phones Snom sont correctement classes (role=Role-IPPHONE).")
    snom_report.append("16 IP phones Snom restent en Rogue (role=None). Voici pourquoi :")
    snom_report.append("")
    snom_report.append("CAUSE 1 : IP Range trop restreint")
    snom_report.append("  Les regles ne couvrent que 10.102.0.1 - 10.102.20.254.")
    snom_report.append("  Des Snom se trouvent sur d'autres reseaux (ex: 10.101.32.x sur VLAN COLLAB/IMP).")
    snom_report.append("  -> Elargir le range IP dans les profils, ou supprimer la condition IP Range.")
    snom_report.append("")
    snom_report.append("CAUSE 2 : Pas d'IP")
    snom_report.append("  Certains Snom sont connectes mais sans adresse IP.")
    snom_report.append("  Sans IP, les checks IP Range et TCP Ports echouent automatiquement.")
    snom_report.append("  -> Verifier la config DHCP sur les VLANs concernes.")
    snom_report.append("")
    snom_report.append("RECOMMANDATION :")
    snom_report.append("  Creer une regle IPPHONE simplifiee sans condition IP Range,")
    snom_report.append("  basee uniquement sur Vendor OUI snom + FortiGuard.")
    snom_report.append("  Ou ajouter les sous-reseaux manquants dans les regles existantes.")
    snom_report.append("")
    snom_report.append("Liste des 16 Snom rogues :")
    snom_report.append("-" * 60)

    snom_rogues = []
    for h in rogues:
        for a in h.get("adapterObjects", []):
            if isinstance(a, dict):
                v = a.get("vendorName") or ""
                if "snom" in v.lower():
                    snom_rogues.append(h)
                    break

    for h in snom_rogues:
        mac = h.get("primaryMac") or "?"
        ip = str(h.get("ip") or "")
        loc = ""
        for a in h.get("adapterObjects", []):
            if isinstance(a, dict):
                if not ip:
                    ip = get_adapter_ip(a)
                loc = loc or (a.get("location") or "")
        hostname = str(h.get("hostName") or "-")
        co = "connecte" if h.get("connected") else "offline"
        snom_report.append(f"  {mac}  {ip or '-':<18}  {hostname:<25}  {loc:<50}  {co}")

    with open("/Users/bbelot/Desktop/diagnostic_snom_rogues.txt", "w") as f:
        f.write("\n".join(snom_report))
    print(f"[1] diagnostic_snom_rogues.txt : {len(snom_rogues)} Snom")

    # --- Report 2: Non-DMZ rogues ---
    dmz_keywords = [
        "ETUDIANT", "ENSEIGNANT", "INVITE", "GUEST",
        "LOGE", "ESTP_", "EDUROAM", "WIFI",
    ]
    campus_vlan_prefixes = ["Campus-CACHAN VLAN"]

    def is_dmz_or_wifi(host):
        for a in host.get("adapterObjects", []):
            if isinstance(a, dict):
                loc = (a.get("location") or "").strip()
                loc_upper = loc.upper()
                if any(kw in loc_upper for kw in dmz_keywords):
                    return True
                if any(loc.startswith(p) for p in campus_vlan_prefixes):
                    return True
        return False

    non_dmz = [h for h in rogues if not is_dmz_or_wifi(h)]

    lines = []
    connected_count = sum(1 for h in non_dmz if h.get("connected"))
    lines.append(f"Rogues hors DMZ/WiFi campus : {len(non_dmz)} devices ({connected_count} connectes)")
    lines.append("Exclus : VLAN etudiant/enseignant/invite/eduroam/wifi, Campus-CACHAN VLAN xxx")
    lines.append("")
    header = f"{'MAC':<20} {'IP':<18} {'Vendor':<40} {'Hostname':<25} {'Location':<55} {'Co.'}"
    lines.append(header)
    lines.append("-" * len(header))

    for h in sorted(
        non_dmz,
        key=lambda x: (not x.get("connected"), x.get("primaryMac") or ""),
    ):
        mac = str(h.get("primaryMac") or "?")
        ip = str(h.get("ip") or "")
        vendor = ""
        loc = ""
        for a in h.get("adapterObjects", []):
            if isinstance(a, dict):
                if not ip:
                    ip = get_adapter_ip(a)
                vendor = vendor or str(a.get("vendorName") or "")
                loc = loc or str(a.get("location") or "")
        hostname = str(h.get("hostName") or "-")
        status = "OUI" if h.get("connected") else "non"
        lines.append(
            f"{mac:<20} {(ip or '-'):<18} {vendor:<40} {hostname:<25} {loc:<55} {status}"
        )

    with open("/Users/bbelot/Desktop/rogues_hors_dmz.txt", "w") as f:
        f.write("\n".join(lines))
    print(f"[2] rogues_hors_dmz.txt : {len(non_dmz)} devices ({connected_count} connectes)")

    await client.close()


asyncio.run(main())
