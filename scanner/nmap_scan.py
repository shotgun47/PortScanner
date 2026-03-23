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
    단일 타겟 상세 스캔 (서비스 정보 및 IP 해석 포함)
    """
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    # [계약 준수] 타겟 이름(DNS)을 IP로 해석
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        resolved_ip = target

    try:
        arguments = f"{config.get('args', '-sV')} -Pn"
        scan_data = nm.scan(resolved_ip, config["ports"], arguments)
        
        # [계약 준수] 호스트가 죽어있으면 예외를 발생시켜 backend가 실패를 인지하게 함
        if resolved_ip not in nm.all_hosts():
            raise Exception(f"Host {target} ({resolved_ip}) is down.")

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
            "raw_log": str(scan_data) # 대시보드 로그용
        }
    except Exception as e:
        raise e

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 (메인 브랜치 계약 준수 버전)"""
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
        # 실패 시 백엔드가 인지할 수 있도록 raise
        raise ValueError(f"Scan failed for {target}: {str(e)}")

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """대역 병렬 스캔 (팀원 요청 사양)"""
    nm = nmap.PortScanner()
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_single_host, ip, profile): ip for ip in live_hosts}
        for future in as_completed(future_to_ip):
            try:
                data = future.result()
                results.append({
                    "ip": data["ip"],
                    "status": data["status"],
                    "open_ports": data.get("open_ports", [])
                })
            except Exception:
                pass
    return {"hosts": sorted(results, key=lambda x: x["ip"])}