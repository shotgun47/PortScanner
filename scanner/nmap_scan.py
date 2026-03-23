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
        # 실제 nmap 스캔 실행
        scan_data = nm.scan(resolved_ip, config["ports"], arguments)
        
        # 호스트가 응답하지 않을 경우 처리
        if resolved_ip not in nm.all_hosts():
            # 단순히 0점을 주는 게 아니라 'down' 상태임을 명시적으로 예외 처리
            raise Exception(f"Target {target} ({resolved_ip}) is not responding to Nmap.")

        detailed_ports = []
        raw_open_ports = []
        
        for proto in nm[resolved_ip].all_protocols():
            ports = nm[resolved_ip][proto].keys()
            for port in sorted(ports):
                state = nm[resolved_ip][proto][port]["state"]
                if state == "open":
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
        # 상위 함수로 에러 전파
        raise e

def run_nmap_scan(target: str, profile: str = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 (메인 브랜치 계약 준수 및 AI 브리핑 연동용)"""
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
                "status": "completed",  # 'up' 대신 'completed'로 반환하여 워크플로우 호환성 향상
                "ports": res["ports"],
                "logs": [
                    {"level": "info", "message": f"Scan started for {target}"},
                    {"level": "info", "message": f"Found {len(res['ports'])} open ports."},
                    {"level": "debug", "message": res.get("raw_log", "")}
                ]
            }
        }
    except Exception as e:
        # AI 브리핑 실패(404)를 방지하기 위해 실패 시에도 규격화된 에러 반환
        return {
            "scan_id": f"error-{uuid4().hex[:4]}",
            "target": {"input_value": target, "resolved_ip": target},
            "scan": {
                "started_at": started_at.isoformat(),
                "status": "failed",
                "ports": [],
                "logs": [{"level": "error", "message": str(e)}]
            }
        }

def run_inventory_scan(scope: str, profile: str = "common", max_workers: int = 20) -> dict[str, object]:
    """대역 병렬 스캔 (팀원 요청 사양 - 변수명 수정 완료)"""
    nm = nmap.PortScanner()
    nm.scan(hosts=scope, arguments="-sn")
    live_hosts = nm.all_hosts()
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # submit 시 'ip' 대신 'host'를 사용하여 루프 변수 충돌 방지
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