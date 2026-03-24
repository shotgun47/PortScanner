from __future__ import annotations

import json
import re
import socket
import ipaddress
import nmap
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

# 1. 타겟 및 프로필 설정
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
    "redis": {
        "ports": "6379",
        "args": "-sV",
    }
}

# 2. 유틸리티 함수
def is_ip(address: str) -> bool:
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(address))

# 3. 핵심 스캔 함수들
def scan_single_host(ip: str, profile: str = "common") -> dict[str, object]:
    """단일 호스트 상세 스캔 (병렬 워커에서 호출용)"""
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    # -Pn: 이미 Discovery에서 살아있음을 확인했으므로 Ping 생략
    arguments = f"{config.get('args', '-sV')} -Pn"
    
    try:
        nm.scan(ip, config.get("ports"), arguments)
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
        for port in sorted(nm[ip][proto].keys()):
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
        "open_ports": sorted(list(set(raw_open_ports)))
    }

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """대역 병렬 스캔 (Host Discovery 후 상세 스캔)"""
    nm = nmap.PortScanner()
    
    # 1단계: Host Discovery (-sn)
    try:
        nm.scan(hosts=scope, arguments="-sn")
    except Exception as e:
        return {"hosts": [], "error": f"Discovery failed: {e}"}

    live_hosts = [host for host in nm.all_hosts() if nm[host].state() == "up"]

    if not live_hosts:
        return {"hosts": []}
    
    results = []
    
    # 2단계: ThreadPoolExecutor로 병렬 상세 스캔
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_single_host, ip, profile): ip 
            for ip in live_hosts
        }
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                results.append({
                    "ip": data["ip"],
                    "status": data["status"],
                    "open_ports": data["open_ports"],
                })
            except Exception:
                results.append({
                    "ip": ip,
                    "status": "error",
                    "open_ports": [],
                })

    # IP 주소 기준으로 정렬
    def ip_sort_key(host_dict):
        try:
            return ipaddress.ip_address(host_dict["ip"])
        except ValueError:
            return host_dict["ip"]

    return {"hosts": sorted(results, key=ip_sort_key)}

def run_nmap_scan(target_input: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 대상 상세 스캔 및 결과 리포트 생성"""
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
                    ports_data.append({
                        "port": int(port),
                        "protocol": proto,
                        "service": {
                            "name": port_info.get("name"),
                            "product": port_info.get("product"),
                            "version": port_info.get("version"),
                            "cpe": port_info.get("cpe") or None,
                        },
                    })

    # 로그용 커맨드 생성
    logged_command = f"nmap {scan_args}"
    if scan_target_ports:
        logged_command += f" -p {scan_target_ports}"
    logged_command += f" {target_ip}"

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
                    "stdout": nm.csv() if hasattr(nm, 'csv') else "",
                },
                {
                    "source": "nmap",
                    "phase": "service_detection_raw",
                    "command": logged_command,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "stdout": json.dumps(nm._scan_result, ensure_ascii=False, indent=2, default=str),
                }
            ],
        },
    }