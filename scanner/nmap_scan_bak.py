from __future__ import annotations

import json
import re
import socket
import nmap
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed


TARGET_IPS = {
    "juice-shop": "172.28.0.11",
    "juice-shop.lab.local": "172.28.0.11",
    "tomcat-cve-2017-12615": "172.28.0.10",
    "tomcat-cve-2017-12615.lab.local": "172.28.0.10",
    "redis-4-unacc": "172.28.0.20",
    "redis-4-unacc.lab.local": "172.28.0.20",
    "sambacry": "172.28.0.30",
    "sambacry.lab.local": "172.28.0.30",
    "mysql-cve-2012-2122": "172.28.0.60",
    "mysql-cve-2012-2122.lab.local": "172.28.0.60",
    "elasticsearch-cve-2015-1427": "172.28.0.70",
    "elasticsearch-cve-2015-1427.lab.local": "172.28.0.70",
    "vsftpd-2-3-4": "172.28.0.80",
    "vsftpd-2-3-4.lab.local": "172.28.0.80",
}

# 스캔 프로필 설정
PROFILE_CONFIG = {
    "quick": {
        "ports": "21,22,80,139,443,445,3000,8080,3306,6379,9200",
        "args": "-sV",
    },
    "common": {
        "ports": None,
        "args": "-sV --top-ports 100",
    },
    "deep": {
        "ports": None,
        "args": "-sV --top-ports 1000",
    },
    "full": {
        "ports": None,
        "args": "-sV -p-",
    },
    "web": {
        "ports": "80,443,3000,8080,8443",
        "args": "-sV",
    },
}


def is_ip(address: str) -> bool:
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(address))


def scan_single_host(ip: str, profile: str = "common") -> dict[str, object]:
    """단일 호스트 상세 스캔 (서비스 정보 포함)"""
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    # -Pn: Ping 생략 (방화벽 우회 및 속도), -sV: 서비스 버전 탐지
    arguments = f"{config.get('args', '-sV')} -Pn"
    try:
        nm.scan(ip, config["ports"], arguments)
    except Exception as exc:
        raise RuntimeError(f"host scan failed for {ip}: {exc}") from exc
        
    if ip not in nm.all_hosts():
        return {"ip": ip, "status": "down", "ports": [], "open_ports": []}

    try:
        host_state = nm[ip].state()
    except Exception:
        host_state = "unknown"

    if host_state != "up":
        return {"ip": ip, "status": host_state, "ports": [], "open_ports": []}

    detailed_ports = []
    raw_open_ports = []
    
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in sorted(lport):
            p_info = nm[ip][proto][port]
            if p_info["state"] == "open":
                port_int = int(port)
                raw_open_ports.append(port_int)
                detailed_ports.append({
                    "port": port_int,
                    "protocol": proto,
                    "service": {
                        "name": p_info.get("name", "unknown"),
                        "product": p_info.get("product", ""),
                        "version": p_info.get("version", ""),
                        "cpe": p_info.get("cpe") or None,
                    }
                })
    
    return {
        "ip": ip,
        "status": "up",
        "ports": detailed_ports,
        "open_ports": sorted(raw_open_ports)
    }

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """
    [요구사항 구현] 대역 병렬 스캔
    반환 형식: {"hosts": [{"ip":..., "status":..., "open_ports": [...]}]}
    """
    nm = nmap.PortScanner()
    # 1단계: Host Discovery (Ping 스캔으로 살아있는 IP만 추출)
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = [
        host
        for host in nm.all_hosts()
        if nm[host].state() == "up"
    ]

    if not live_hosts:
        return {"hosts": []}
    
    results = []
    # 2단계: ThreadPoolExecutor로 병렬 상세 스캔 실행
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_single_host, ip, profile): ip 
            for ip in live_hosts
            }
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                results.append(
                    {
                        "ip": data["ip"],
                        "status": data["status"],
                        "open_ports": data["open_ports"],
                    }
                )
            except Exception:
                results.append(
                    {
                        "ip": ip,
                        "status": "error",
                        "open_ports": [],
                    }
                )

    return {"hosts": sorted(results, key=lambda x: x["ip"])}


def run_nmap_scan(target_input: str, profile: str = "common") -> dict[str, object]:
    normalized = target_input.strip().lower()
    if is_ip(normalized):
        target_ip = normalized
    elif normalized in TARGET_IPS:
        target_ip = TARGET_IPS[normalized]
    else:
        try:
            target_ip = socket.gethostbyname(target_input)
        except socket.gaierror as exc:
            raise ValueError("도메인을 찾을 수 없습니다.") from exc

    profile_config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])

    nm = nmap.PortScanner()
    started_at = datetime.now(timezone.utc).astimezone().isoformat()
    scan_args = profile_config["args"]
    scan_target_ports = profile_config["ports"]
    nm.scan(target_ip, scan_target_ports, scan_args)
    finished_at = datetime.now(timezone.utc).astimezone().isoformat()

    ports_data: list[dict[str, object]] = []
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            for port in sorted(nm[target_ip][proto].keys()):
                port_info = nm[target_ip][proto][port]
                if port_info["state"] == "open":
                    ports_data.append(
                        {
                            "port": int(port),
                            "protocol": proto,
                            "service": {
                                "name": port_info.get("name"),
                                "product": port_info.get("product"),
                                "version": port_info.get("version"),
                                "cpe": port_info.get("cpe") or None,
                            },
                        }
                    )

    if scan_target_ports:
        logged_command = f"nmap {scan_args} -p {scan_target_ports} {target_ip}"
    else:
        logged_command = f"nmap {scan_args} {target_ip}"

    try:
        csv_output = nm.csv()
    except Exception:
        csv_output = ""

    try:
        raw_output = json.dumps(nm._scan_result, ensure_ascii=False, indent=2, default=str)
    except Exception:
        raw_output = ""

    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {
            "input_value": target_input,
            "resolved_ip": target_ip,
        },
        "scan": {
            "started_at": started_at,
            "ports": ports_data,
            "logs": [
                {
                    "source": "nmap",
                    "phase": "service_detection_csv",
                    "command": logged_command,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "return_code": 0,
                    "stdout": csv_output or f"Nmap scan completed for {target_ip}",
                    "stderr": "",
                },
                {
                    "source": "nmap",
                    "phase": "service_detection_raw",
                    "command": logged_command,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "return_code": 0,
                    "stdout": raw_output,
                    "stderr": "",
                }
            ],
        },
    }