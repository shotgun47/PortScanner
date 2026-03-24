"""Tests for the vulnerability analyzer."""

from __future__ import annotations

import pytest
import requests

from analysis.analyzer import AnalyzerConfig, analyze
from analysis.cve_lookup import NvdLookupConfig, lookup_cves


SAMPLE_SCAN = {
    "scan_id": "scan-001",
    "target": {"input_value": "redis.lab.local", "resolved_ip": "192.168.56.20"},
    "scan": {
        "started_at": "2026-03-10T21:00:00+09:00",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
            },
            {
                "port": 6379,
                "protocol": "tcp",
                "service": {
                    "name": "redis",
                    "product": "Redis",
                    "version": "4.0.14",
                    "cpe": "cpe:/a:redislabs:redis:4.0.14",
                },
            },
        ],
    },
}


def test_analyze_returns_expected_misconfiguration_findings() -> None:
    result = analyze(SAMPLE_SCAN).to_dict()

    assert result["scan_id"] == "scan-001"
    assert result["analysis"]["risk_summary"] == {"score": 100, "grade": "critical"}
    titles = {item["title"] for item in result["analysis"]["vulnerabilities"]}
    assert "Redis Unauthorized Access" in titles
    assert "Redis Replication Abuse RCE Risk" in titles
    assert "SSH Service Exposure" in titles
    assert result["drift"] == {"new_ports": [], "closed_ports": []}


def test_analyze_supports_planned_service_rules() -> None:
    scan = {
        "scan_id": "scan-003",
        "target": {"input_value": "infra.lab.local", "resolved_ip": "172.28.0.60"},
        "scan": {
            "started_at": "2026-03-10T21:10:00+09:00",
            "ports": [
                {
                    "port": 21,
                    "protocol": "tcp",
                    "service": {"name": "ftp", "product": "vsftpd", "version": "3.0.5"},
                },
                {
                    "port": 445,
                    "protocol": "tcp",
                    "service": {"name": "microsoft-ds", "product": "Samba", "version": "4.15.0"},
                },
                {
                    "port": 3306,
                    "protocol": "tcp",
                    "service": {"name": "mysql", "product": "MariaDB", "version": "10.5.23"},
                },
                {
                    "port": 9200,
                    "protocol": "tcp",
                    "service": {"name": "elasticsearch", "product": "Elasticsearch", "version": "7.17.0"},
                },
            ],
        },
    }

    result = analyze(scan).to_dict()
    titles = {item["title"] for item in result["analysis"]["vulnerabilities"]}

    assert "FTP Plaintext Service Exposure" in titles
    assert "SambaCry Remote Code Execution Risk" in titles
    assert "Database Service Exposure" in titles
    assert "Elasticsearch Unauthorized Access Risk" in titles
    assert result["analysis"]["risk_summary"]["grade"] == "critical"


# 회귀 방지: 아래 케이스는 포트 단독 일치로 finding이 생성되면 안 된다.
@pytest.mark.parametrize(
    ("port", "service_name", "service_product", "blocked_title"),
    [
        (9200, "kibana", "kibana", "Elasticsearch Unauthorized Access Risk"),
        (445, "windows-rpc", "rpc service", "Samba Service Exposure"),
        (3306, "custom-db", "proprietary database", "Database Service Exposure"),
        (21, "file-gateway", "data transfer daemon", "FTP Plaintext Service Exposure"),
    ],
)
def test_analyze_requires_alias_for_port_exposure_rules(
    port: int,
    service_name: str,
    service_product: str,
    blocked_title: str,
) -> None:
    scan = {
        "scan_id": f"scan-negative-{port}",
        "target": {"input_value": "negative.lab.local", "resolved_ip": "172.28.0.99"},
        "scan": {
            "started_at": "2026-03-10T23:00:00+09:00",
            "ports": [
                {
                    "port": port,
                    "protocol": "tcp",
                    "service": {"name": service_name, "product": service_product, "version": "1.0"},
                }
            ],
        },
    }

    result = analyze(scan).to_dict()
    titles = {item["title"] for item in result["analysis"]["vulnerabilities"]}
    assert blocked_title not in titles


def test_analyze_computes_drift_when_previous_scan_is_given() -> None:
    previous_scan = {
        **SAMPLE_SCAN,
        "scan_id": "scan-000",
        "scan": {
            "started_at": "2026-03-09T21:00:00+09:00",
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": {"name": "http", "product": "nginx", "version": "1.18.0"},
                },
            ],
        },
    }

    result = analyze(SAMPLE_SCAN, previous_scan=previous_scan).to_dict()

    assert result["drift"]["new_ports"] == [6379]
    assert result["drift"]["closed_ports"] == [80]


def test_live_cve_lookup_prefers_cpe_and_returns_empty_on_failure() -> None:
    class DummyResponse:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    class RecordingSession(requests.Session):
        def __init__(self) -> None:
            super().__init__()
            self.last_params: dict | None = None

        def get(self, *args, **kwargs):  # type: ignore[override]
            self.last_params = kwargs.get("params")
            return DummyResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2021-23017",
                                "descriptions": [
                                    {
                                        "lang": "en",
                                        "value": "NGINX resolver off-by-one vulnerability allows out-of-bounds write.",
                                    }
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseSeverity": "HIGH"}}
                                    ]
                                },
                            }
                        }
                    ]
                }
            )

    session = RecordingSession()
    findings = lookup_cves(
        service={
            "name": "http",
            "product": "nginx",
            "version": "1.18.0",
            "cpe": "cpe:/a:nginx:nginx:1.18.0",
        },
        config=NvdLookupConfig(use_live_api=True),
        session=session,
    )
    assert session.last_params is not None
    assert "cpeName" in session.last_params
    assert session.last_params["cpeName"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert any(item.cve_id == "CVE-2021-23017" for item in findings)

    class BrokenSession(requests.Session):
        def get(self, *args, **kwargs):  # type: ignore[override]
            raise requests.RequestException("network blocked")

    empty_findings = lookup_cves(
        service={"name": "http", "product": "nginx", "version": "1.18.0"},
        config=NvdLookupConfig(use_live_api=True),
        session=BrokenSession(),
    )
    assert empty_findings == []
