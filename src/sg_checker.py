"""
Security Group checker — detects inbound rules open to the world.

Scans all EC2 Security Groups in a given region and flags any inbound
rules that allow traffic from 0.0.0.0/0 (IPv4) or ::/0 (IPv6).
Sensitive ports (SSH, RDP, database ports) are classified as CRITICAL;
all other open-to-world rules are classified as HIGH.
"""

import logging
from typing import List, Optional

import boto3

from src.models import Finding, Severity, CheckType

logger = logging.getLogger(__name__)

# Ports whose exposure to the public internet is considered CRITICAL.
# Maps port number -> human-readable service name.
CRITICAL_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
}


def check_all_security_groups(
    session: boto3.Session, region: str
) -> List[Finding]:
    """
    Scan every Security Group in *region* for inbound rules open to the world.

    Args:
        session: A boto3 Session (can be real or moto-mocked).
        region:  The AWS region to scan (e.g. "us-east-1").

    Returns:
        A list of Finding objects, one per offending inbound rule.
    """
    ec2_client = session.client("ec2", region_name=region)
    findings: List[Finding] = []

    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            vpc_id = sg.get("VpcId", "N/A")

            for rule in sg.get("IpPermissions", []):
                rule_findings = _evaluate_inbound_rule(
                    rule, sg_id, sg_name, vpc_id, region
                )
                findings.extend(rule_findings)

    logger.info(
        "SG check complete — region=%s, groups_scanned=%d, findings=%d",
        region,
        sum(
            len(page["SecurityGroups"])
            for page in ec2_client.get_paginator("describe_security_groups").paginate()
        ),
        len(findings),
    )
    return findings


def _evaluate_inbound_rule(
    rule: dict,
    sg_id: str,
    sg_name: str,
    vpc_id: str,
    region: str,
) -> List[Finding]:
    """
    Check a single inbound rule for open-to-world CIDRs.

    A rule may contain multiple IpRanges and Ipv6Ranges entries,
    so this can return more than one finding per rule.
    """
    findings: List[Finding] = []
    protocol = rule.get("IpProtocol", "tcp")
    from_port = rule.get("FromPort", 0)
    to_port = rule.get("ToPort", 0)

    # When protocol is "-1" (all traffic), ports are not specified by AWS.
    if protocol == "-1":
        from_port = 0
        to_port = 65535

    # Check IPv4 ranges
    for ip_range in rule.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            severity = _classify_severity(from_port, to_port, protocol)
            detail = _build_detail(from_port, to_port, protocol, "0.0.0.0/0")
            findings.append(
                Finding(
                    resource_type="SecurityGroup",
                    resource_id=sg_id,
                    check_type=CheckType.SG_OPEN_INBOUND,
                    severity=severity,
                    detail=detail,
                    region=region,
                    metadata={
                        "sg_name": sg_name,
                        "vpc_id": vpc_id,
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                        "cidr": "0.0.0.0/0",
                    },
                )
            )

    # Check IPv6 ranges
    for ip_range in rule.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") == "::/0":
            severity = _classify_severity(from_port, to_port, protocol)
            detail = _build_detail(from_port, to_port, protocol, "::/0")
            findings.append(
                Finding(
                    resource_type="SecurityGroup",
                    resource_id=sg_id,
                    check_type=CheckType.SG_OPEN_INBOUND,
                    severity=severity,
                    detail=detail,
                    region=region,
                    metadata={
                        "sg_name": sg_name,
                        "vpc_id": vpc_id,
                        "from_port": from_port,
                        "to_port": to_port,
                        "protocol": protocol,
                        "cidr": "::/0",
                    },
                )
            )

    return findings


def _classify_severity(from_port: int, to_port: int, protocol: str) -> Severity:
    """
    Determine severity based on the exposed port range and protocol.

    Rules:
    - Protocol "-1" (all traffic) open to the world → CRITICAL
    - Any critical port (SSH, RDP, DB) within the port range → CRITICAL
    - Everything else open to the world → HIGH
    """
    if protocol == "-1":
        return Severity.CRITICAL

    for port in CRITICAL_PORTS:
        if from_port <= port <= to_port:
            return Severity.CRITICAL

    return Severity.HIGH


def _build_detail(
    from_port: int, to_port: int, protocol: str, cidr: str
) -> str:
    """Build a human-readable detail string for a finding."""
    if protocol == "-1":
        return f"All traffic open to {cidr}"

    # Check if a single critical port is exposed
    if from_port == to_port and from_port in CRITICAL_PORTS:
        service = CRITICAL_PORTS[from_port]
        return f"Port {from_port} ({service}) open to {cidr}"

    # Port range
    if from_port == to_port:
        return f"Port {from_port} ({protocol}) open to {cidr}"

    return f"Ports {from_port}-{to_port} ({protocol}) open to {cidr}"
