from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from backend.app.config import settings
from backend.app.storage import Storage


BASE_DIR = Path(__file__).resolve().parent
VERIFICATION_DIR = BASE_DIR / "verification"

TARGET_RULES: dict[str, dict[str, Any]] = {
    "tomcat": {
        "aliases": {"tomcat", "apache tomcat", "apache coyote jsp engine"},
        "ports": {8080},
        "version_prefixes": ("8.5.19",),
        "scheme": "http",
        "service_templates": [
            VERIFICATION_DIR / "service" / "tomcat.yaml",
        ],
        "risk_templates": [
            VERIFICATION_DIR / "risk" / "tomcat-put.yaml",
        ],
        "analysis_risk_titles": {
            "Apache Tomcat PUT JSP Upload Risk",
        },
    },
    "redis": {
        "aliases": {"redis"},
        "ports": {6379},
        "version_prefixes": ("4.0.14",),
        "scheme": "tcp",
        "service_templates": [
            VERIFICATION_DIR / "service" / "redis.yaml",
        ],
        "risk_templates": [
            VERIFICATION_DIR / "risk" / "redis-unauth.yaml",
        ],
        "analysis_risk_titles": {
            "Redis Unauthorized Access",
            "Redis Replication Abuse RCE Risk",
        },
    },
    "elasticsearch": {
        "aliases": {"elasticsearch"},
        "ports": {9200},
        "version_prefixes": ("1.4.2",),
        "scheme": "http",
        "service_templates": [
            VERIFICATION_DIR / "service" / "elasticsearch.yaml",
        ],
        "risk_templates": [
            VERIFICATION_DIR / "risk" / "elasticsearch-groovy.yaml",
        ],
        "analysis_risk_titles": {
            "Elasticsearch Unauthorized Access Risk",
            "Elasticsearch Groovy Sandbox Escape Risk",
        },
    },
    "samba": {
        "aliases": {"samba", "smb", "microsoft-ds", "netbios-ssn"},
        "ports": {139, 445},
        "version_prefixes": (),
        "scheme": "tcp",
        "service_templates": [
            VERIFICATION_DIR / "service" / "samba.yaml",
        ],
        "risk_templates": [],
        "analysis_risk_titles": {
            "SambaCry Remote Code Execution Risk",
        },
    },
    "vsftpd": {
        "aliases": {"ftp", "vsftpd"},
        "ports": {21},
        "version_prefixes": ("2.3.4",),
        "scheme": "tcp",
        "service_templates": [
            VERIFICATION_DIR / "service" / "vsftpd.yaml",
        ],
        "risk_templates": [
            VERIFICATION_DIR / "risk" / "vsftpd-backdoor.yaml",
        ],
        "analysis_risk_titles": {
            "vsftpd Backdoor Risk",
        },
    },
}


def _normalize_tokens(*values: str | None) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        normalized = value.strip().lower()
        if not normalized:
            continue
        tokens.add(normalized)
        tokens.update(part for part in normalized.replace("/", " ").replace("-", " ").split() if part)
    return tokens


def _extract_template_id(template_path: Path) -> str:
    if not template_path.exists():
        raise FileNotFoundError(f"template not found: {template_path}")

    for line in template_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("id:"):
            return stripped.split(":", 1)[1].strip()

    return template_path.stem


def _load_scan(storage: Storage, scan_id: str) -> dict[str, Any]:
    scan_result = storage.get_scan(scan_id)
    if scan_result is None:
        raise ValueError(f"scan not found: {scan_id}")
    return scan_result


def _load_analysis(storage: Storage, scan_id: str) -> dict[str, Any] | None:
    return storage.get_analysis(scan_id)


def _version_matches(version: str, prefixes: tuple[str, ...]) -> bool:
    if not prefixes:
        return True
    return any(version.startswith(prefix) for prefix in prefixes)


def _find_matching_port(scan_result: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any] | None:
    ports = scan_result.get("scan", {}).get("ports", [])
    for port_entry in ports:
        port = int(port_entry.get("port", 0))
        service = port_entry.get("service", {}) or {}

        tokens = _normalize_tokens(service.get("name"), service.get("product"))
        version = str(service.get("version") or "").strip().lower()

        alias_match = any(alias in tokens for alias in rule["aliases"])
        port_match = port in rule["ports"]
        version_match = _version_matches(version, rule["version_prefixes"])

        if alias_match and port_match and version_match:
            return port_entry

    return None


def _build_target_endpoint(scan_result: dict[str, Any], port_entry: dict[str, Any], rule: dict[str, Any]) -> str:
    target = scan_result.get("target", {}) or {}
    host = target.get("input_value") or target.get("resolved_ip") or "127.0.0.1"
    port = int(port_entry["port"])
    scheme = rule["scheme"]

    if scheme in {"http", "https"}:
        return f"{scheme}://{host}:{port}"

    return f"{host}:{port}"


def _ensure_nuclei_installed() -> None:
    if shutil.which("nuclei") is None:
        raise RuntimeError("nuclei command not found. Rebuild the backend container first.")


def _run_nuclei(target_endpoint: str, template_path: Path, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    command = [
        "nuclei",
        "-target",
        target_endpoint,
        "-t",
        str(template_path),
        "-jsonl",
        "-duc",
        "-silent",
    ]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _parse_nuclei_output(
    result: subprocess.CompletedProcess[str],
    template_id: str,
    target_endpoint: str,
    verification_type: str,
    template_group: str,
    matched_port: int,
) -> dict[str, Any]:
    raw_output = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        return {
            "template_id": template_id,
            "template_group": template_group,
            "verification_type": verification_type,
            "method": "nuclei",
            "status": "error",
            "target": target_endpoint,
            "matched_port": matched_port,
            "evidence": stderr or "nuclei execution failed",
            "raw_output": raw_output or stderr,
            "confidence": "low",
            "reason": "nuclei execution failed",
        }

    if not raw_output:
        return {
            "template_id": template_id,
            "template_group": template_group,
            "verification_type": verification_type,
            "method": "nuclei",
            "status": "not_verified",
            "target": target_endpoint,
            "matched_port": matched_port,
            "evidence": "template executed but no match was returned",
            "raw_output": "",
            "confidence": "low",
            "reason": "no direct nuclei match",
        }

    first_line = raw_output.splitlines()[0]
    evidence = f"nuclei matched template: {template_id}"

    try:
        first_json = json.loads(first_line)
        matcher_name = first_json.get("matcher-name")
        matched_at = first_json.get("matched-at")
        parts = [f"nuclei matched template: {template_id}"]
        if matcher_name:
            parts.append(f"matcher={matcher_name}")
        if matched_at:
            parts.append(f"matched_at={matched_at}")
        evidence = ", ".join(parts)
    except Exception:
        pass

    return {
        "template_id": template_id,
        "template_group": template_group,
        "verification_type": verification_type,
        "method": "nuclei",
        "status": "verified",
        "target": target_endpoint,
        "matched_port": matched_port,
        "evidence": evidence,
        "raw_output": raw_output,
        "confidence": "high",
        "reason": "direct nuclei match",
    }


def _extract_analysis_titles(analysis_result: dict[str, Any] | None) -> set[str]:
    if not analysis_result:
        return set()

    vulnerabilities = analysis_result.get("analysis", {}).get("vulnerabilities", [])
    titles: set[str] = set()
    for item in vulnerabilities:
        title = item.get("title")
        if isinstance(title, str) and title.strip():
            titles.add(title.strip())
    return titles


def _has_related_analysis_risk(analysis_result: dict[str, Any] | None, rule: dict[str, Any]) -> bool:
    titles = _extract_analysis_titles(analysis_result)
    return bool(titles.intersection(rule.get("analysis_risk_titles", set())))


def _promote_to_suspected_if_needed(
    parsed_result: dict[str, Any],
    *,
    target_type: str,
    rule: dict[str, Any],
    analysis_result: dict[str, Any] | None,
    service_verified: bool,
) -> dict[str, Any]:
    if parsed_result["status"] != "not_verified":
        return parsed_result

    if not _has_related_analysis_risk(analysis_result, rule):
        return parsed_result

    verification_type = parsed_result["verification_type"]

    # service도 공통 규칙으로 suspected 승격
    if verification_type == "service":
        promoted = dict(parsed_result)
        promoted["status"] = "suspected"
        promoted["confidence"] = "medium"
        promoted["reason"] = (
            "no direct nuclei service match, but scan matched the target rule "
            "and analyzer contains related findings"
        )
        promoted["evidence"] = (
            f"{parsed_result['evidence']}; promoted to suspected because "
            f"scan matched the {target_type} rule and analysis reported related findings"
        )
        return promoted

    # risk는 기존 규칙 유지하되, service가 verified 또는 suspected면 승격 가능
    if verification_type == "risk" and service_verified:
        promoted = dict(parsed_result)
        promoted["status"] = "suspected"
        promoted["confidence"] = "medium"
        promoted["reason"] = (
            "no direct nuclei risk match, but scan matched the target rule, "
            "service verification was at least suspected, and analyzer contains related risk findings"
        )
        promoted["evidence"] = (
            f"{parsed_result['evidence']}; promoted to suspected because "
            f"service was at least suspected and analysis reported related {target_type} risk findings"
        )
        return promoted

    return parsed_result


def _save_verification(
    storage: Storage,
    scan_id: str,
    target_type: str,
    parsed_result: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "verification_id": f"verify-{uuid4().hex[:8]}",
        "scan_id": scan_id,
        "target_type": target_type,
        "template_id": parsed_result["template_id"],
        "template_group": parsed_result["template_group"],
        "verification_type": parsed_result["verification_type"],
        "method": parsed_result["method"],
        "status": parsed_result["status"],
        "target": parsed_result["target"],
        "matched_port": parsed_result["matched_port"],
        "evidence": parsed_result["evidence"],
        "raw_output": parsed_result["raw_output"],
        "confidence": parsed_result.get("confidence"),
        "reason": parsed_result.get("reason"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    storage.save_verification(payload)
    return payload


def _execute_template(
    storage: Storage,
    scan_id: str,
    target_type: str,
    target_endpoint: str,
    matched_port: int,
    template_path: Path,
    verification_type: str,
    *,
    rule: dict[str, Any],
    analysis_result: dict[str, Any] | None,
    service_verified: bool,
) -> dict[str, Any]:
    template_id = _extract_template_id(template_path)
    result = _run_nuclei(target_endpoint, template_path)
    parsed = _parse_nuclei_output(
        result=result,
        template_id=template_id,
        target_endpoint=target_endpoint,
        verification_type=verification_type,
        template_group=target_type,
        matched_port=matched_port,
    )

    parsed = _promote_to_suspected_if_needed(
        parsed,
        target_type=target_type,
        rule=rule,
        analysis_result=analysis_result,
        service_verified=service_verified,
    )

    return _save_verification(
        storage=storage,
        scan_id=scan_id,
        target_type=target_type,
        parsed_result=parsed,
    )


def _execute_template_list(
    storage: Storage,
    scan_id: str,
    target_type: str,
    target_endpoint: str,
    matched_port: int,
    template_paths: list[Path],
    verification_type: str,
    *,
    rule: dict[str, Any],
    analysis_result: dict[str, Any] | None,
    service_verified: bool,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for template_path in template_paths:
        results.append(
            _execute_template(
                storage=storage,
                scan_id=scan_id,
                target_type=target_type,
                target_endpoint=target_endpoint,
                matched_port=matched_port,
                template_path=template_path,
                verification_type=verification_type,
                rule=rule,
                analysis_result=analysis_result,
                service_verified=service_verified,
            )
        )
    return results


def detect_target_type(scan_result: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]] | None:
    for target_type, rule in TARGET_RULES.items():
        port_entry = _find_matching_port(scan_result, rule)
        if port_entry is not None:
            return target_type, rule, port_entry
    return None


def verify_scan(scan_id: str, target_type: str | None = None) -> dict[str, Any]:
    storage = Storage(settings.sqlite_path)
    storage.initialize()

    scan_result = _load_scan(storage, scan_id)
    analysis_result = _load_analysis(storage, scan_id)
    _ensure_nuclei_installed()

    if target_type:
        if target_type not in TARGET_RULES:
            raise ValueError(f"unsupported target_type: {target_type}")
        rule = TARGET_RULES[target_type]
        port_entry = _find_matching_port(scan_result, rule)
        if port_entry is None:
            raise ValueError(
                f"scan does not match target_type={target_type}. "
                "Check service name/product/version/port."
            )
        detected_target_type = target_type
    else:
        detected = detect_target_type(scan_result)
        if detected is None:
            raise ValueError("could not detect supported target type from scan result")
        detected_target_type, rule, port_entry = detected

    matched_port = int(port_entry["port"])
    target_endpoint = _build_target_endpoint(scan_result, port_entry, rule)

    service_results = _execute_template_list(
        storage=storage,
        scan_id=scan_id,
        target_type=detected_target_type,
        target_endpoint=target_endpoint,
        matched_port=matched_port,
        template_paths=rule["service_templates"],
        verification_type="service",
        rule=rule,
        analysis_result=analysis_result,
        service_verified=False,
    )

    service_verified = any(item["status"] in {"verified", "suspected"} for item in service_results)

    risk_results = _execute_template_list(
        storage=storage,
        scan_id=scan_id,
        target_type=detected_target_type,
        target_endpoint=target_endpoint,
        matched_port=matched_port,
        template_paths=rule["risk_templates"],
        verification_type="risk",
        rule=rule,
        analysis_result=analysis_result,
        service_verified=service_verified,
    )

    return {
        "scan_id": scan_id,
        "target_type": detected_target_type,
        "target": target_endpoint,
        "results": {
            "service": service_results,
            "risk": risk_results,
        },
        "analysis_risk_titles": sorted(_extract_analysis_titles(analysis_result).intersection(rule["analysis_risk_titles"])),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run nuclei-based service/risk verification for an existing scan_id"
    )
    parser.add_argument("--scan-id", required=True, help="Existing scan_id stored in SQLite")
    parser.add_argument(
        "--target-type",
        required=False,
        choices=sorted(TARGET_RULES.keys()),
        help="Optional explicit target type. If omitted, target type is auto-detected from scan result.",
    )
    args = parser.parse_args()

    output = verify_scan(scan_id=args.scan_id, target_type=args.target_type)
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()