"""NVD-backed live CVE lookup with CPE-first matching."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Optional

import requests

from analysis.models import ServiceInfo, VulnerabilityFinding

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class NvdLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    max_results: int = 5
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: str | None = None


def lookup_cves(
    service: ServiceInfo | dict[str, Any],
    config: Optional[NvdLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> list[VulnerabilityFinding]:
    normalized = service if isinstance(service, ServiceInfo) else ServiceInfo(**service)
    resolved = config or NvdLookupConfig()
    if not resolved.use_live_api:
        return []
    try:
        return _lookup_cves_live(normalized, resolved, session)
    except Exception as exc:
        LOGGER.warning("Live CVE lookup failed for %s: %s", normalized.name, exc)
        return []


def _lookup_cves_live(
    service: ServiceInfo,
    config: NvdLookupConfig,
    session: Optional[requests.Session],
) -> list[VulnerabilityFinding]:
    client = session or requests.Session()
    headers = {"apiKey": config.api_key} if config.api_key else None

    cpe_params = _build_cpe_params(service, config.max_results)
    if cpe_params is not None:
        response = client.get(
            config.base_url,
            params=cpe_params,
            headers=headers,
            timeout=config.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        findings = _parse_nvd_items(service, payload.get("vulnerabilities", []))
        if findings:
            return findings

    keyword_params = _build_keyword_params(service, config.max_results)
    if keyword_params is None:
        return []
    response = client.get(
        config.base_url,
        params=keyword_params,
        headers=headers,
        timeout=config.timeout,
    )
    response.raise_for_status()
    payload = response.json()
    return _parse_nvd_items(service, payload.get("vulnerabilities", []))


def _build_cpe_params(service: ServiceInfo, max_results: int) -> dict[str, Any] | None:
    if service.cpe:
        cpe_name = _to_cpe23(service.cpe)
        if cpe_name:
            return {
                "cpeName": cpe_name,
                "resultsPerPage": max_results,
            }
    return None

def _build_keyword_params(service: ServiceInfo, max_results: int) -> dict[str, Any] | None:
    keyword = _build_keyword(service)
    if keyword:
        return {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }
    return None


def _parse_nvd_items(service: ServiceInfo, items: list[dict[str, Any]]) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for item in items:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = _extract_description(cve.get("descriptions", []))
        findings.append(
            VulnerabilityFinding(
                title=_build_title(cve_id, description),
                severity=_extract_severity(cve.get("metrics", {})),
                cve_id=cve_id,
                match_confidence=_estimate_match_confidence(service, description),
            )
        )
    return findings


def _build_keyword(service: ServiceInfo) -> str:
    value = service.product or service.name
    return value.strip() if value and value.strip() else ""


def _extract_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", "")).strip()
    return ""


def _build_title(cve_id: str, description: str) -> str:
    if not description:
        return cve_id
    sentence = description.split(". ")[0].strip()
    return sentence[:120] if sentence else cve_id


def _extract_severity(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        severity = values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity")
        if severity:
            return str(severity).lower()
    return "medium"


def _estimate_match_confidence(service: ServiceInfo, description: str) -> float:
    text = description.lower()
    score = 0.35
    for token in (service.name, service.product, service.version):
        if token and token.lower() in text:
            score += 0.2
    if service.cpe:
        score += 0.2
    return round(min(score, 0.95), 2)


def _to_cpe23(value: str) -> str | None:
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.startswith("cpe:2.3:"):
        return normalized
    if not normalized.startswith("cpe:/"):
        return None

    parts = normalized[5:].split(":")
    if len(parts) < 4:
        return None

    cpe23_parts = parts[:]
    while len(cpe23_parts) < 11:
        cpe23_parts.append("*")
    return "cpe:2.3:" + ":".join(cpe23_parts[:11])
