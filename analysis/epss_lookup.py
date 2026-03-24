"""EPSS live lookup helpers."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Optional

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class EpssLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    base_url: str = "https://api.first.org/data/v1/epss"


def lookup_epss(
    cve_id: Optional[str],
    config: Optional[EpssLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> Optional[float]:
    if not cve_id:
        return None
    resolved = config or EpssLookupConfig()
    if not resolved.use_live_api:
        return None
    try:
        return _lookup_epss_live(cve_id, resolved, session)
    except Exception as exc:
        LOGGER.warning("Live EPSS lookup failed for %s: %s", cve_id, exc)
        return None


def _lookup_epss_live(
    cve_id: str,
    config: EpssLookupConfig,
    session: Optional[requests.Session],
) -> Optional[float]:
    client = session or requests.Session()
    response = client.get(config.base_url, params={"cve": cve_id}, timeout=config.timeout)
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data") or []
    if not data:
        return None
    value = data[0].get("epss")
    return float(value) if value is not None else None
