"""
Data models for CSPM scan findings and reports.

Provides structured dataclasses and enums used by all checker modules
to represent security findings in a consistent, serializable format.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict


class Severity(Enum):
    """Severity levels for security findings, ordered from most to least severe."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckType(Enum):
    """Enumeration of all security checks performed by the CSPM scanner."""
    # S3 checks
    S3_PUBLIC_ACL = "S3_PUBLIC_ACL"
    S3_PUBLIC_POLICY = "S3_PUBLIC_POLICY"
    S3_PUBLIC_ACCESS_BLOCK = "S3_PUBLIC_ACCESS_BLOCK"
    S3_POLICY_STATUS = "S3_POLICY_STATUS"
    # Security Group checks
    SG_OPEN_INBOUND = "SG_OPEN_INBOUND"


@dataclass
class Finding:
    """
    A single security finding from a CSPM check.

    Attributes:
        resource_type: The AWS resource type (e.g., "S3", "SecurityGroup").
        resource_id:   The resource identifier (bucket name, sg-xxxxx, etc.).
        check_type:    Which specific check produced this finding.
        severity:      The severity level of the finding.
        detail:        A human-readable description of the issue.
        region:        The AWS region where the resource resides.
        metadata:      Additional context (vpc_id, port, protocol, etc.).
    """
    resource_type: str
    resource_id: str
    check_type: CheckType
    severity: Severity
    detail: str
    region: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    """
    Aggregated report from a full CSPM scan run.

    Attributes:
        account_id:     The AWS account ID that was scanned.
        region:         The AWS region that was scanned.
        scan_timestamp: ISO 8601 timestamp of when the scan started.
        findings:       List of all findings discovered during the scan.
        total_checks:   Total number of individual checks performed.
    """
    account_id: str
    region: str
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: List[Finding] = field(default_factory=list)
    total_checks: int = 0

    def summary(self) -> Dict[str, int]:
        """Count findings grouped by severity level."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        """Serialize the entire report to a plain dict for JSON output."""
        return asdict(self)
