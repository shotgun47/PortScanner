"""FastAPI entrypoint for Tribest ASM."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import logging
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests

from analysis.analyzer import AnalyzerConfig, analyze
from analysis.verify import verify_scan
from backend.app.config import settings
from backend.app.schemas import (
    AnalyzeRequest,
    BatchScanRequest,
    InventoryRunRequest,
    InventoryRunResponse,
    ReportResponse,
    ScanRequest,
    VerificationRecordRequest,
    VerificationRecordResponse,
    WorkflowBatchItem,
    WorkflowBatchResponse,
    WorkflowResponse,
)
from backend.app.services.inventory_service import calculate_inventory_drift, run_inventory
from backend.app.services.report_service import build_report_bundle, build_report_payload
from backend.app.services.scenario_service import list_scenarios, run_scenario
from backend.app.storage import Storage
from scanner.scan import run_scan

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Tribest ASM Backend", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage = Storage(settings.sqlite_path)
storage.initialize()
analyzer_config = AnalyzerConfig(
    use_live_nvd=settings.use_live_nvd,
    use_live_kev=settings.use_live_kev,
    use_live_epss=settings.use_live_epss,
    request_timeout=settings.request_timeout,
    nvd_api_key=settings.nvd_api_key,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/scans")
def list_scans() -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_scans()}


@app.get("/api/v1/runs")
def list_runs() -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_runs()}


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    run_payload = storage.get_run(run_id)
    if run_payload is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run_payload


@app.get("/api/v1/ai/ollama/models")
def list_ollama_models(base_url: str = "http://host.docker.internal:11434") -> dict[str, Any]:
    try:
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"available": False, "models": [], "error": str(exc)}

    models = [
        item.get("name")
        for item in payload.get("models", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item.get("name").strip()
    ]
    return {"available": True, "models": models, "error": None}


@app.get("/api/v1/scenarios")
def get_scenarios() -> dict[str, list[dict[str, Any]]]:
    return {"items": list_scenarios()}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    scan = storage.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@app.get("/api/v1/analyses/{scan_id}")
def get_analysis(scan_id: str) -> dict[str, Any]:
    analysis_result = storage.get_analysis(scan_id)
    if analysis_result is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return analysis_result


@app.post("/api/v1/scans/run")
def run_scan_endpoint(payload: ScanRequest) -> dict[str, Any]:
    if payload.scenario:
        scenario_result = run_scenario(payload.scenario, payload.target)
        LOGGER.info("Scenario executed for scan: %s", scenario_result["name"])
    scan_result = run_scan(payload.target, profile=payload.profile)
    storage.save_scan(scan_result)
    return scan_result


@app.post("/api/v1/analysis/run")
def run_analysis(payload: AnalyzeRequest) -> dict[str, Any]:
    scan_result = storage.get_scan(payload.scan_id)
    if scan_result is None:
        raise HTTPException(status_code=404, detail="scan not found")
    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], payload.scan_id)
    analysis_result = analyze(scan_result, previous_scan=previous_scan, config=analyzer_config).to_dict()
    storage.save_analysis(analysis_result)
    return analysis_result


def _run_workflow(payload: ScanRequest) -> WorkflowResponse:
    if payload.scenario:
        scenario_result = run_scenario(payload.scenario, payload.target)
        LOGGER.info("Scenario executed for workflow: %s", scenario_result["name"])
    scan_result = run_scan(payload.target, profile=payload.profile)
    storage.save_scan(scan_result)
    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], scan_result["scan_id"])
    analysis_result = analyze(scan_result, previous_scan=previous_scan, config=analyzer_config).to_dict()
    storage.save_analysis(analysis_result)
    _run_verification_for_scan(scan_result["scan_id"])
    report_payload = build_report_payload(
        scan_result=scan_result,
        analysis_result=analysis_result,
        previous_scan=previous_scan,
        narrative_backend="template",
    )
    storage.save_report(report_payload)
    return WorkflowResponse(scan_result=scan_result, analysis_result=analysis_result)


def _run_single_target_batch_item(target: str, profile: str, scenario: str | None) -> WorkflowBatchItem:
    try:
        workflow = _run_workflow(ScanRequest(target=target, profile=profile, scenario=scenario))
        return WorkflowBatchItem(
            target=target,
            status="completed",
            scan_id=workflow.scan_result["scan_id"],
        )
    except Exception as exc:
        LOGGER.exception("Batch workflow failed for target %s", target)
        return WorkflowBatchItem(target=target, status="failed", error=str(exc))


def _summarize_verification_results(verification_result: dict[str, Any]) -> dict[str, int]:
    service_results = verification_result.get("results", {}).get("service", [])
    risk_results = verification_result.get("results", {}).get("risk", [])
    all_results = [*service_results, *risk_results]

    summary = {
        "service_templates": len(service_results),
        "risk_templates": len(risk_results),
        "verified": 0,
        "suspected": 0,
        "not_verified": 0,
        "error": 0,
    }
    for item in all_results:
        status = str(item.get("status", "")).strip().lower()
        if status in summary:
            summary[status] += 1
    return summary


def _run_verification_for_scan(scan_id: str, target_type: str | None = None) -> dict[str, Any]:
    try:
        verification_result = verify_scan(scan_id=scan_id, target_type=target_type)
        summary = _summarize_verification_results(verification_result)
        LOGGER.info(
            (
                "Verification completed for scan_id=%s "
                "(target_type=%s, service_templates=%s, risk_templates=%s, "
                "verified=%s, suspected=%s, not_verified=%s, error=%s)"
            ),
            scan_id,
            verification_result.get("target_type"),
            summary["service_templates"],
            summary["risk_templates"],
            summary["verified"],
            summary["suspected"],
            summary["not_verified"],
            summary["error"],
        )
        return verification_result
    except Exception as exc:
        LOGGER.warning("Verification skipped for scan_id=%s: %s", scan_id, exc)
        return {
            "scan_id": scan_id,
            "status": "skipped",
            "error": str(exc),
        }


@app.post("/api/v1/workflows/run", response_model=WorkflowResponse)
def run_workflow(payload: ScanRequest) -> WorkflowResponse:
    return _run_workflow(payload)


@app.post("/api/v1/workflows/run-batch", response_model=WorkflowBatchResponse)
def run_batch_workflow(payload: BatchScanRequest) -> WorkflowBatchResponse:
    run_id = f"run-{uuid4().hex[:8]}"
    items: list[WorkflowBatchItem] = []
    with ThreadPoolExecutor(max_workers=payload.max_concurrency) as executor:
        futures = {
            executor.submit(_run_single_target_batch_item, target, payload.profile, payload.scenario): target
            for target in payload.targets
        }
        for future in as_completed(futures):
            items.append(future.result())

    items.sort(key=lambda item: payload.targets.index(item.target))
    statuses = {item.status for item in items}
    if statuses == {"completed"}:
        status = "completed"
    elif statuses == {"failed"}:
        status = "failed"
    else:
        status = "partial_failed"

    run_payload = {
        "run_id": run_id,
        "requested_targets": payload.targets,
        "profile": payload.profile,
        "scenario": payload.scenario,
        "status": status,
        "items": [item.model_dump(exclude_none=True) for item in items],
    }
    storage.save_run(run_payload)
    return WorkflowBatchResponse(run_id=run_id, status=status, items=items)


@app.post("/api/v1/workflows/demo", response_model=WorkflowResponse, deprecated=True)
def run_demo_workflow(payload: ScanRequest) -> WorkflowResponse:
    return _run_workflow(payload)


@app.get("/api/v1/inventories")
def list_inventories() -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_inventories()}


@app.get("/api/v1/inventories/{inventory_id}")
def get_inventory(inventory_id: str) -> dict[str, Any]:
    inventory_payload = storage.get_inventory(inventory_id)
    if inventory_payload is None:
        raise HTTPException(status_code=404, detail="inventory not found")
    return inventory_payload


@app.post("/api/v1/inventories/run", response_model=InventoryRunResponse)
def run_inventory_endpoint(payload: InventoryRunRequest) -> InventoryRunResponse:
    inventory_result = run_inventory(payload.scope, profile=payload.profile)
    previous_inventory = storage.get_previous_inventory_for_scope(payload.scope, inventory_result.inventory_id)
    if previous_inventory is not None:
        previous_hosts = previous_inventory.get("hosts", [])
        inventory_result.drift = calculate_inventory_drift(inventory_result.hosts, previous_hosts)
    inventory_payload = inventory_result.model_dump(mode="json")
    storage.save_inventory(inventory_payload)
    return InventoryRunResponse(**inventory_payload)


@app.get("/api/v1/verifications/{scan_id}")
def list_verification_records(scan_id: str) -> dict[str, list[dict[str, Any]]]:
    return {"items": storage.list_verifications(scan_id)}


@app.post("/api/v1/verifications/{scan_id}/run")
def run_verification_record(scan_id: str, target_type: str | None = None) -> dict[str, Any]:
    if storage.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return _run_verification_for_scan(scan_id, target_type=target_type)


@app.post("/api/v1/verifications", response_model=VerificationRecordResponse)
def create_verification_record(payload: VerificationRecordRequest) -> VerificationRecordResponse:
    if storage.get_scan(payload.scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")

    verification = VerificationRecordResponse(
        verification_id=f"verify-{uuid4().hex[:8]}",
        scan_id=payload.scan_id,
        template_id=payload.template_id,
        method=payload.method,
        status=payload.status,
        target=payload.target,
        evidence=payload.evidence,
        raw_output=payload.raw_output,
        created_at=datetime.now(timezone.utc),
    )
    storage.save_verification(verification.model_dump(mode="json"))
    return verification


def _generate_report_payload(
    scan_id: str,
    *,
    narrative_backend: str = "template",
    gemini_api_key: str | None = None,
    gemini_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    scan_result = storage.get_scan(scan_id)
    analysis_result = storage.get_analysis(scan_id)
    if scan_result is None or analysis_result is None:
        raise HTTPException(status_code=404, detail="scan or analysis not found")

    previous_scan = storage.get_previous_scan_for_target(scan_result["target"]["input_value"], scan_id)
    report_payload = build_report_payload(
        scan_result=scan_result,
        analysis_result=analysis_result,
        previous_scan=previous_scan,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )
    storage.save_report(report_payload)
    return report_payload


@app.get("/api/v1/reports/{scan_id}")
def get_report(scan_id: str) -> dict[str, Any]:
    report_payload = storage.get_report(scan_id)
    if report_payload is not None:
        return report_payload
    return _generate_report_payload(scan_id, narrative_backend="template")


@app.post("/api/v1/reports/{scan_id}/regenerate")
def regenerate_report(
    scan_id: str,
    narrative_backend: str = "template",
    gemini_api_key: str | None = None,
    gemini_model: str | None = None,
    ollama_base_url: str | None = None,
    ollama_model: str | None = None,
) -> dict[str, Any]:
    return _generate_report_payload(
        scan_id,
        narrative_backend=narrative_backend,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )


@app.post("/api/v1/reports/{scan_id}", response_model=ReportResponse)
def create_report(scan_id: str) -> ReportResponse:
    report_payload = get_report(scan_id)
    formats = build_report_bundle(scan_id, report_payload)
    return ReportResponse(scan_id=scan_id, formats=formats)
