"""Known Exploited Vulnerabilities live lookup."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Optional

import requests

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class KevLookupConfig:
    use_live_api: bool = False
    timeout: float = 5.0
    base_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def lookup_kev(
    cve_id: Optional[str],
    config: Optional[KevLookupConfig] = None,
    session: Optional[requests.Session] = None,
) -> bool:
    if not cve_id:
        return False
    resolved = config or KevLookupConfig()
    if not resolved.use_live_api:
        return False
    try:
        return _lookup_kev_live(cve_id, resolved, session)
    except Exception as exc:
        LOGGER.warning("Live KEV lookup failed for %s: %s", cve_id, exc)
        return False


def _lookup_kev_live(
    cve_id: str,
    config: KevLookupConfig,
    session: Optional[requests.Session],
) -> bool:
    client = session or requests.Session()
    response = client.get(config.base_url, timeout=config.timeout)
    response.raise_for_status()
    payload = response.json()
    for vulnerability in payload.get("vulnerabilities", []):
        if vulnerability.get("cveID") == cve_id:
            return True
    return False
