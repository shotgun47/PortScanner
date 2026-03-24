"""Inventory discovery helpers for range-based drift tracking."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

# import nmap

from backend.app.schemas import InventoryDrift, InventoryHost, InventoryHostChange, InventoryRunResponse
from scanner.nmap_scan import PROFILE_CONFIG
from scanner.scan import run_inventory_scan as scanner_run_inventory_scan


def run_inventory(scope: str, profile: str = "quick") -> InventoryRunResponse:
    # hosts = _discover_hosts(scope, profile)
    scan_result = scanner_run_inventory_scan(scope, profile=profile)

    raw_hosts = scan_result.get("hosts", [])
    hosts = [InventoryHost(**host) for host in raw_hosts]
    return InventoryRunResponse(
        inventory_id=f"inventory-{uuid4().hex[:8]}",
        scope=scope,
        profile=profile,
        created_at=datetime.now(timezone.utc),
        hosts=hosts,
        drift=InventoryDrift(),
    )


def calculate_inventory_drift(
    current_hosts: list[InventoryHost] | list[dict[str, object]],
    previous_hosts: list[InventoryHost] | list[dict[str, object]],
) -> InventoryDrift:
    normalized_current = [_normalize_host(host) for host in current_hosts]
    normalized_previous = [_normalize_host(host) for host in previous_hosts]
    current_map = {host.ip: sorted(set(host.open_ports)) for host in normalized_current}
    previous_map = {host.ip: sorted(set(host.open_ports)) for host in normalized_previous}

    new_hosts = sorted(set(current_map) - set(previous_map))
    missing_hosts = sorted(set(previous_map) - set(current_map))
    changed_hosts: list[InventoryHostChange] = []

    for ip in sorted(set(current_map).intersection(previous_map)):
        current_ports = set(current_map[ip])
        previous_ports = set(previous_map[ip])
        if current_ports == previous_ports:
            continue
        changed_hosts.append(
            InventoryHostChange(
                ip=ip,
                new_ports=sorted(current_ports - previous_ports),
                closed_ports=sorted(previous_ports - current_ports),
            )
        )

    return InventoryDrift(
        new_hosts=new_hosts,
        missing_hosts=missing_hosts,
        changed_hosts=changed_hosts,
    )


def _normalize_host(host: InventoryHost | dict[str, object]) -> InventoryHost:
    if isinstance(host, InventoryHost):
        return host
    return InventoryHost(**host)


# def _discover_hosts(scope: str, profile: str) -> list[InventoryHost]:
#     profile_config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["quick"])
#     discovery = nmap.PortScanner()
#     discovery.scan(hosts=scope, arguments="-sn")

#     up_hosts = [host for host in discovery.all_hosts() if discovery[host].state() == "up"]
#     if not up_hosts:
#         return []

#     port_scanner = nmap.PortScanner()
#     hosts_arg = " ".join(up_hosts)
#     scan_args = profile_config["args"]
#     scan_ports = profile_config["ports"]
#     port_scanner.scan(hosts=hosts_arg, ports=scan_ports, arguments=scan_args)

#     hosts: list[InventoryHost] = []
#     for host in sorted(up_hosts):
#         open_ports: list[int] = []
#         if host in port_scanner.all_hosts():
#             for proto in port_scanner[host].all_protocols():
#                 for port in sorted(port_scanner[host][proto].keys()):
#                     port_info = port_scanner[host][proto][port]
#                     if port_info.get("state") == "open":
#                         open_ports.append(int(port))
#         hosts.append(InventoryHost(ip=host, status="up", open_ports=sorted(set(open_ports))))
#     return hosts
