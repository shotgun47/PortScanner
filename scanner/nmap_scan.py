from __future__ import annotations

import nmap
import socket
from datetime import datetime, timezone
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

# 1. 프로필 설정 유지
PROFILE_CONFIG = {
    "common": {"ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,3306,3389,8080", "args": "-sV -T4"},
    "quick": {"ports": "80,443,22", "args": "-F -T5"},
    "full": {"ports": "1-65535", "args": "-sV -T4"},
    "redis": {"ports": "6379,22", "args": "-sV"},
    "web": {"ports": "80,443,8080,8443", "args": "-sV"}
}

def scan_single_host(target: str, profile: str = "common") -> dict[str, object]:
    """
    단일 호스트 스캔 및 결과 추출
    """
    config = PROFILE_CONFIG.get(profile, PROFILE_CONFIG["common"])
    nm = nmap.PortScanner()
    
    # [수정] 도메인/이름 해석 로직 추가 (.lab.local 대응)
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        # 해석 실패 시 원본 타겟 유지 (nmap 내부 로직에 맡김)
        resolved_ip = target

    try:
        arguments = f"{config.get('args', '-sV')} -Pn"
        # [수정] 해석된 IP를 사용하여 스캔 진행
        scan_data = nm.scan(resolved_ip, config["ports"], arguments)
        
        # [수정] 호스트가 다운되었거나 결과가 없을 경우 예외 발생 (정상 반환 방지)
        if resolved_ip not in nm.all_hosts():
            raise Exception(f"Host {target} ({resolved_ip}) is down or unreachable.")

        detailed_ports = []
        raw_open_ports = []
        
        host_data = nm[resolved_ip]
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in sorted(ports):
                state = host_data[proto][port]["state"]
                if state == "open":
                    p_info = host_data[proto][port]
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
            "raw_log": str(scan_data),
            "command_line": nm.command_line()
        }
    except Exception as e:
        # 상위 함수에서 처리하도록 예외 전파
        raise e

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """
    백엔드 계약(Contract)에 맞춘 최종 결과 생성 및 에러 처리
    """
    started_at = datetime.now(timezone.utc).astimezone()
    
    try:
        res = scan_single_host(target, profile)
        
        # [수정] 최신 main 계약 준수 (logs 필드 필수 데이터 포함)
        return {
            "scan_id": f"scan-{uuid4().hex[:8]}",
            "target": {
                "input_value": target, 
                "resolved_ip": res["ip"] # 실제 해석된 IP 반영
            },
            "scan": {
                "started_at": started_at.isoformat(),
                "status": "completed",
                "ports": res["ports"],
                "logs": [
                    {
                        "level": "info", 
                        "message": f"Successfully scanned {target} ({res['ip']})",
                        "source": "nmap",
                        "phase": "scan",
                        "command": res.get("command_line", "nmap")
                    },
                    {
                        "level": "debug", 
                        "message": res.get("raw_log", ""),
                        "source": "nmap",
                        "phase": "output",
                        "command": res.get("command_line", "nmap")
                    }
                ]
            }
        }
    except Exception as e:
        # [수정] 에러 발생 시 status를 'failed'로 명확히 표시하고 로그 남김
        return {
            "scan_id": f"error-{uuid4().hex[:4]}",
            "target": {"input_value": target, "resolved_ip": target},
            "scan": {
                "started_at": started_at.isoformat(),
                "status": "failed", # 백엔드에서 에러로 인지하도록 수정
                "ports": [],
                "logs": [{
                    "level": "error", 
                    "message": f"Scan failed: {str(e)}",
                    "source": "nmap",
                    "phase": "error",
                    "command": "nmap"
                }]
            }
        }

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """
    인벤토리 스캔 (멀티스레딩)
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_single_host, host, profile): host for host in live_hosts}
        for future in as_completed(future_to_ip):
            target_ip = future_to_ip[future]
            try:
                data = future.result()
                results.append({
                    "ip": data["ip"], 
                    "status": "completed", 
                    "open_ports": data.get("open_ports", [])
                })
            except Exception:
                results.append({
                    "ip": target_ip, 
                    "status": "failed", 
                    "open_ports": []
                })
    return {"hosts": sorted(results, key=lambda x: x["ip"])}