"""Mock scanner implementation used until the real scanner is connected."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Literal
from uuid import uuid4


Profile = Literal["quick", "web", "redis", "mixed"]

TARGET_IPS = {
    "web-target": "172.28.0.10",
    "web.lab.local": "172.28.0.10",
    "redis-vuln": "172.28.0.20",
    "redis.lab.local": "172.28.0.20",
    "samba-vuln": "172.28.0.30",
    "samba.lab.local": "172.28.0.30",
    "ssh-target": "172.28.0.40",
    "ssh.lab.local": "172.28.0.40",
    "other-service": "172.28.0.50",
}


def run_mock_scan(target: str, profile: Profile = "mixed") -> dict[str, object]:
    """Create a deterministic scaffold-level scan result."""
    started_at = datetime.now(timezone.utc).astimezone()
    ports = _profile_ports(profile)
    return {
        "scan_id": f"scan-{uuid4().hex[:8]}",
        "target": {
            "input_value": target,
            "resolved_ip": _guess_ip(target, profile),
        },
        "scan": {
            "started_at": started_at.isoformat(),
            "ports": ports,
            "logs": _build_mock_logs(target, profile, started_at, ports),
        },
    }

def run_mock_inventory_scan(scope: str, profile: Profile = "mixed") -> dict[str, object]:
    """대역 스캔의 결과 구조를 흉내 내는 모크 함수"""
    # 간단하게 TARGET_IPS에 정의된 호스트들이 살아있다고 가정하고 반환
    hosts = []
    for name, ip in TARGET_IPS.items():
        if not name.endswith(".local"): # 중복 제거용
            continue
        hosts.append({
            "ip": ip,
            "status": "up",
            "open_ports": [p["port"] for p in _profile_ports(profile)]
        })
    
    return {
        "hosts": hosts
    }

def _profile_ports(profile: Profile) -> list[dict[str, object]]:
    base_ssh = {
        "port": 22,
        "protocol": "tcp",
        "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
    }
    web = {
        "port": 80,
        "protocol": "tcp",
        "service": {"name": "http", "product": "nginx", "version": "1.18.0"},
    }
    redis = {
        "port": 6379,
        "protocol": "tcp",
        "service": {"name": "redis", "product": "Redis", "version": "4.0.14"},
    }
    other = {
        "port": 5678,
        "protocol": "tcp",
        "service": {"name": "http-alt", "product": "hashicorp-http-echo", "version": "1.0.0"},
    }
    mapping: dict[str, list[dict[str, object]]] = {
        "quick": [web],
        "web": [web, other],
        "redis": [base_ssh, redis],
        "mixed": [base_ssh, web, redis, other],
    }
    return mapping[profile]


def _build_mock_logs(
    target: str,
    profile: Profile,
    started_at: datetime,
    ports: list[dict[str, object]],
) -> list[dict[str, object]]:
    finished_at = started_at
    port_list = ",".join(str(item["port"]) for item in ports)
    stdout = "\n".join(
        [
            f"Starting mock nmap scan against {target}",
            f"Profile: {profile}",
            f"Open ports: {port_list}",
            "Scan completed successfully",
        ]
    )
    return [
        {
            "source": "nmap",
            "phase": "service_detection",
            "command": f"nmap -sV {target}",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "return_code": 0,
            "stdout": stdout,
            "stderr": "",
        }
    ]


def _guess_ip(target: str, profile: Profile) -> str:
    normalized = target.strip().lower()
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    if normalized in TARGET_IPS:
        return TARGET_IPS[normalized]
    if "redis" in normalized or profile == "redis":
        return TARGET_IPS["redis.lab.local"]
    if "web" in normalized or profile == "web":
        return TARGET_IPS["web.lab.local"]
    return "172.28.0.99"
