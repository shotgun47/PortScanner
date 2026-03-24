"""Pydantic models for scan input and analysis output."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
RiskGrade = Literal["critical", "high", "medium", "low", "info"]
FindingKind = Literal["cve", "misconfiguration"]


class AppModel(BaseModel):
    """Base model with a version-safe dict serializer."""

    model_config = ConfigDict(extra="ignore")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the model while omitting ``None`` fields."""
        if hasattr(self, "model_dump"):
            return self.model_dump(exclude_none=True)
        return self.dict(exclude_none=True)


class ServiceInfo(AppModel):
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None


class PortScanResult(AppModel):
    port: int = Field(..., ge=1, le=65535)
    protocol: str
    service: ServiceInfo


class ScanLogEntry(AppModel):
    source: str
    phase: str
    command: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""


class TargetInfo(AppModel):
    input_value: str
    resolved_ip: str


class ScanData(AppModel):
    started_at: datetime
    ports: list[PortScanResult]
    logs: list[ScanLogEntry] = Field(default_factory=list)


class ScanResult(AppModel):
    scan_id: str
    target: TargetInfo
    scan: ScanData


class VulnerabilityFinding(AppModel):
    port: int = Field(default=0, ge=0, le=65535)
    service_name: str = ""
    title: str
    severity: Severity
    cve_id: Optional[str] = None
    kev: bool = False
    epss: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    match_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    kind: FindingKind = "cve"


class RiskSummary(AppModel):
    score: int = Field(..., ge=0, le=100)
    grade: RiskGrade


class AnalysisBlock(AppModel):
    vulnerabilities: list[VulnerabilityFinding]
    risk_summary: RiskSummary


class DriftResult(AppModel):
    new_ports: list[int]
    closed_ports: list[int]


class AnalysisResponse(AppModel):
    scan_id: str
    analysis: AnalysisBlock
    drift: DriftResult
