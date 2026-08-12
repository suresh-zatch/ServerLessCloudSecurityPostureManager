"""
CSPM Main Orchestrator & AWS Lambda Handler.

Combines S3 and Security Group checks into a unified security audit report.
Provides CLI execution as well as AWS Lambda handler entry point.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any

import boto3
from botocore.exceptions import ClientError

from src.models import ScanReport, Finding, Severity
from src.s3_checker import check_all_buckets
from src.sg_checker import check_all_security_groups

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def run_scan(session: boto3.Session, region: str) -> ScanReport:
    """
    Run full security posture scan across S3 and Security Groups.

    Args:
        session: boto3 Session object.
        region: AWS region string.

    Returns:
        ScanReport object containing findings and metadata.
    """
    account_id = get_account_id(session)
    report = ScanReport(account_id=account_id, region=region)

    logger.info("Starting CSPM scan — Account: %s, Region: %s", account_id, region)

    # 1. S3 Checks
    s3_findings = check_all_buckets(session)
    report.findings.extend(s3_findings)

    # 2. Security Group Checks
    sg_findings = check_all_security_groups(session, region)
    report.findings.extend(sg_findings)

    report.total_checks = len(s3_findings) + len(sg_findings)
    logger.info(
        "Scan complete — Total findings: %d (Summary: %s)",
        len(report.findings),
        report.summary(),
    )
    return report


def get_account_id(session: boto3.Session) -> str:
    """Retrieve AWS Account ID using STS GetCallerIdentity."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity().get("Account", "000000000000")
    except Exception as e:
        logger.warning("Could not retrieve AWS account ID: %s", e)
        return "000000000000"


def format_report_json(report: ScanReport) -> str:
    """Format ScanReport as formatted JSON string."""
    return json.dumps(report.to_dict(), indent=2, default=str)


def format_report_text(report: ScanReport) -> str:
    """Format ScanReport as a human-readable CLI summary."""
    lines = [
        "═" * 60,
        "  SERVERLESS CSPM SCAN REPORT",
        f"  Account: {report.account_id}  |  Region: {report.region}",
        f"  Timestamp: {report.scan_timestamp}",
        "═" * 60,
        "",
        f"  Summary: {report.summary()}",
        "",
    ]

    if not report.findings:
        lines.append("  ✅ No security misconfigurations detected!")
    else:
        for f in report.findings:
            sev_marker = f"[{f.severity.value}]"
            lines.append(f"  {sev_marker:<10} {f.check_type.value:<25} — {f.resource_id}")
            lines.append(f"             → {f.detail}")
            lines.append("")

    lines.append("═" * 60)
    return "\n".join(lines)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point triggered by EventBridge or manual invocation.
    """
    region = os.environ.get("SCAN_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    session = boto3.Session(region_name=region)

    report = run_scan(session, region)
    
    return {
        "statusCode": 200,
        "body": {
            "account_id": report.account_id,
            "region": report.region,
            "scan_timestamp": report.scan_timestamp,
            "summary": report.summary(),
            "findings_count": len(report.findings),
            "findings": [f.to_dict() if hasattr(f, "to_dict") else str(f) for f in report.findings],
        },
    }


def main():
    """CLI entry point for local execution."""
    parser = argparse.ArgumentParser(description="Serverless CSPM Security Scanner")
    parser.add_argument("--region", default="us-east-1", help="AWS region to scan")
    parser.add_argument("--output-format", choices=["json", "text"], default="text", help="Output format")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    report = run_scan(session, args.region)

    if args.output_format == "json":
        print(format_report_json(report))
    else:
        print(format_report_text(report))


if __name__ == "__main__":
    main()
