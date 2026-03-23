from __future__ import annotations

import nmap
import socket
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

PROFILE_CONFIG = {
    "common": {"ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,3306,3389,8080", "args": "-sV -T4"},
    "quick": {"ports": "80,443,22", "args": "-F -T5"},
    "full": {"ports": "1-65535", "args": "-sV -T4"},
    "redis": {"ports": "6379,22", "args": "-sV"},
    "web": {"ports": "80,443,8080,8443", "args": "-sV"}
}

def scan_single_host(target: str, profile: str = "common") -> dict[str, object]:
    """
    단일 타겟 스캔
    - target: 도메인(juice-shop.lab.local) 또는 IP
    """
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        resolved_ip = target

    try:
        arguments = f"{config.get('args', '-sV')} -Pn"
        scan_data = nm.scan(resolved_ip, config["ports"], arguments)
        
 
        if resolved_ip not in nm.all_hosts():
            raise Exception(f"Host {target} ({resolved_ip}) appears to be down or unreachable.")

        detailed_ports = []
        raw_open_ports = []
        
        for proto in nm[resolved_ip].all_protocols():
            lport = nm[resolved_ip][proto].keys()
            for port in sorted(lport):
                if nm[resolved_ip][proto][port]["state"] == "open":
                    p_info = nm[resolved_ip][proto][port]
                    port_int = int(port)
                    raw_open_ports.append(port_int)
                    detailed_ports.append({
                        "port": port_int,
                        "protocol": proto,
                        "service": {
                            "name": p_info.get("name", "unknown"),
                            "product": p_info.get("product", ""),
                            "version": p_info.get("version", "")
                        }
                    })
        
        return {
            "ip": resolved_ip,
            "status": "up",
            "ports": detailed_ports,
            "open_ports": raw_open_ports,
            "raw_log": str(scan_data)
        }
    except Exception as e:
        raise e

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """기존 계약(Main)을 준수하는 단일 스캔 실행 함수"""
    started_at = datetime.now(timezone.utc).astimezone()
    
    try:
        res = scan_single_host(target, profile)
        
        return {
            "scan_id": f"scan-{uuid4().hex[:8]}",
            "target": {
                "input_value": target,
                "resolved_ip": res["ip"]
            },
            "scan": {
                "started_at": started_at.isoformat(),
                "status": res["status"],
                "ports": res["ports"],
                "logs": [
                    {"level": "info", "message": f"Successfully scanned {target}"},
                    {"level": "debug", "message": res.get("raw_log", "")}
                ]
            }
        }
    except Exception as e:
        raise ValueError(f"Scan failed for {target}: {str(e)}")
