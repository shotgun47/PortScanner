"""Scanner module entrypoint.

The backend should call this module instead of keeping scan logic under backend.
When the real scanner is ready, replace the body of ``run_scan`` or route it to the
actual implementation without changing the backend contract.
"""

from __future__ import annotations
from typing import Literal
from scanner.nmap_scan import run_nmap_scan, run_inventory_scan as nmap_inventory_scan

Profile = Literal["quick", "common", "deep", "full", "web", "redis"]

def run_scan(target: str, profile: Profile = "common") -> dict[str, object]:
    """기존 단일 타겟 스캔 유지"""
    return run_nmap_scan(target, profile=profile)

def run_inventory_scan(scope: str, profile: Profile = "common") -> dict[str, object]:
    """대역/CIDR 병렬 스캔 및 인벤토리 구조 반환"""
    return nmap_inventory_scan(scope, profile=profile)