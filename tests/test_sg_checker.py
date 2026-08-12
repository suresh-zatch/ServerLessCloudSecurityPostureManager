"""
Unit tests for src.sg_checker — Security Group open-to-world detection.

Each test creates a VPC and Security Group inside moto's mock AWS
environment, applies specific inbound rules, and asserts that
check_all_security_groups produces the expected findings.
"""

import pytest
from src.sg_checker import check_all_security_groups
from src.models import Severity, CheckType

REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_vpc_and_sg(ec2_client, sg_name="test-sg"):
    """Create a VPC and an empty Security Group, returning (vpc_id, sg_id)."""
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sg = ec2_client.create_security_group(
        GroupName=sg_name,
        Description=f"Test SG: {sg_name}",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    # Revoke the default egress rule so we start completely clean.
    # (Default SGs in a VPC have an allow-all egress rule; moto may or
    #  may not add one, but revoking it keeps tests deterministic.)
    try:
        ec2_client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    except Exception:
        pass  # moto may not add the default egress rule

    return vpc_id, sg_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNoFindings:
    """Cases that should produce zero findings."""

    def test_no_inbound_rules(self, boto_session, ec2_client):
        """A Security Group with no inbound rules should not be flagged."""
        _create_vpc_and_sg(ec2_client)
        findings = check_all_security_groups(boto_session, REGION)
        assert findings == []

    def test_restricted_cidr_not_flagged(self, boto_session, ec2_client):
        """A rule allowing SSH only from 10.0.0.0/8 should not be flagged."""
        _, sg_id = _create_vpc_and_sg(ec2_client)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)
        assert findings == []


class TestCriticalFindings:
    """Cases that should produce CRITICAL-severity findings."""

    def test_ssh_open_to_world(self, boto_session, ec2_client):
        """Port 22 open to 0.0.0.0/0 should be flagged as CRITICAL."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "ssh-open-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        # Filter to only our SG (moto may have a default SG)
        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert sg_findings[0].check_type == CheckType.SG_OPEN_INBOUND
        assert "SSH" in sg_findings[0].detail
        assert "0.0.0.0/0" in sg_findings[0].detail

    def test_rdp_open_to_world(self, boto_session, ec2_client):
        """Port 3389 open to 0.0.0.0/0 should be flagged as CRITICAL."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "rdp-open-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert "RDP" in sg_findings[0].detail

    def test_ipv6_open_to_world(self, boto_session, ec2_client):
        """Port 22 open to ::/0 (IPv6) should be flagged as CRITICAL."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "ipv6-open-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert "::/0" in sg_findings[0].detail

    def test_all_traffic_open_to_world(self, boto_session, ec2_client):
        """Protocol -1 (all traffic) open to 0.0.0.0/0 → CRITICAL."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "all-traffic-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert "All traffic" in sg_findings[0].detail

    def test_database_port_open_to_world(self, boto_session, ec2_client):
        """Port 5432 (PostgreSQL) open to 0.0.0.0/0 → CRITICAL."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "db-open-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert "PostgreSQL" in sg_findings[0].detail


class TestHighFindings:
    """Cases that should produce HIGH-severity findings."""

    def test_custom_port_open_to_world(self, boto_session, ec2_client):
        """Port 8080 open to 0.0.0.0/0 should be flagged as HIGH."""
        _, sg_id = _create_vpc_and_sg(ec2_client, "custom-port-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.HIGH
        assert "8080" in sg_findings[0].detail


class TestFindingMetadata:
    """Verify that finding metadata is populated correctly."""

    def test_metadata_fields(self, boto_session, ec2_client):
        """The finding metadata should include sg_name, vpc_id, port info."""
        vpc_id, sg_id = _create_vpc_and_sg(ec2_client, "meta-test-sg")
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        findings = check_all_security_groups(boto_session, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1

        meta = sg_findings[0].metadata
        assert meta["sg_name"] == "meta-test-sg"
        assert meta["vpc_id"] == vpc_id
        assert meta["from_port"] == 443
        assert meta["to_port"] == 443
        assert meta["protocol"] == "tcp"
        assert meta["cidr"] == "0.0.0.0/0"

        assert sg_findings[0].resource_type == "SecurityGroup"
        assert sg_findings[0].region == REGION
