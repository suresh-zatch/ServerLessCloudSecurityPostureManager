"""
S3 Bucket Security Checker — detects publicly accessible S3 buckets.

Scans all S3 buckets in the AWS account for public ACLs, wildcard bucket policies,
disabled Public Access Block settings, and public policy status.
"""

import json
import logging
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

from src.models import Finding, Severity, CheckType

logger = logging.getLogger(__name__)

# ACL Uri for public access groups
PUBLIC_ACL_URIS = [
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]


def check_all_buckets(session: boto3.Session) -> List[Finding]:
    """
    Scan every S3 bucket in the account for public access configurations.

    Args:
        session: A boto3 Session (real or moto-mocked).

    Returns:
        List of Finding objects for any public exposure detected.
    """
    s3_client = session.client("s3")
    findings: List[Finding] = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as e:
        logger.error("Failed to list S3 buckets: %s", e)
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]
        
        # 1. Check Public Access Block settings
        pab_finding = _check_public_access_block(s3_client, bucket_name)
        if pab_finding:
            findings.append(pab_finding)

        # 2. Check Bucket ACL
        acl_finding = _check_bucket_acl(s3_client, bucket_name)
        if acl_finding:
            findings.append(acl_finding)

        # 3. Check Bucket Policy
        policy_finding = _check_bucket_policy(s3_client, bucket_name)
        if policy_finding:
            findings.append(policy_finding)

        # 4. Check Policy Status (IsPublic)
        status_finding = _check_policy_status(s3_client, bucket_name)
        if status_finding:
            findings.append(status_finding)

    return findings


def _check_public_access_block(s3_client, bucket_name: str) -> Optional[Finding]:
    """Flag if Public Access Block configuration is disabled or incomplete."""
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        conf = resp.get("PublicAccessBlockConfiguration", {})
        is_fully_blocked = (
            conf.get("BlockPublicAcls") is True
            and conf.get("IgnorePublicAcls") is True
            and conf.get("BlockPublicPolicy") is True
            and conf.get("RestrictPublicBuckets") is True
        )
        if not is_fully_blocked:
            return Finding(
                resource_type="S3",
                resource_id=bucket_name,
                check_type=CheckType.S3_PUBLIC_ACCESS_BLOCK,
                severity=Severity.MEDIUM,
                detail="Public Access Block is disabled or incompletely configured",
                metadata={"config": conf},
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "NoSuchPublicAccessBlockConfiguration":
            return Finding(
                resource_type="S3",
                resource_id=bucket_name,
                check_type=CheckType.S3_PUBLIC_ACCESS_BLOCK,
                severity=Severity.MEDIUM,
                detail="Public Access Block configuration is missing",
                metadata={},
            )
        logger.warning("Could not fetch Public Access Block for %s: %s", bucket_name, e)
    return None


def _check_bucket_acl(s3_client, bucket_name: str) -> Optional[Finding]:
    """Flag if Bucket ACL grants read/write permissions to AllUsers or AuthenticatedUsers."""
    try:
        resp = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = resp.get("Grants", [])
        for grant in grants:
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_ACL_URIS:
                permission = grant.get("Permission", "READ")
                return Finding(
                    resource_type="S3",
                    resource_id=bucket_name,
                    check_type=CheckType.S3_PUBLIC_ACL,
                    severity=Severity.HIGH,
                    detail=f"Bucket ACL grants public {permission} to {grantee.get('URI')}",
                    metadata={"permission": permission, "grantee_uri": grantee.get("URI")},
                )
    except ClientError as e:
        logger.warning("Could not fetch ACL for %s: %s", bucket_name, e)
    return None


def _check_bucket_policy(s3_client, bucket_name: str) -> Optional[Finding]:
    """Flag if Bucket Policy contains a wildcard Principal ("*" or {"AWS": "*"})."""
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = resp.get("Policy", "{}")
        policy = json.loads(policy_str)
        
        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow":
                principal = statement.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    return Finding(
                        resource_type="S3",
                        resource_id=bucket_name,
                        check_type=CheckType.S3_PUBLIC_POLICY,
                        severity=Severity.CRITICAL,
                        detail="Bucket policy allows public access with wildcard Principal '*'",
                        metadata={"statement_sid": statement.get("Sid", "N/A")},
                    )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code != "NoSuchBucketPolicy":
            logger.warning("Could not fetch policy for %s: %s", bucket_name, e)
    return None


def _check_policy_status(s3_client, bucket_name: str) -> Optional[Finding]:
    """Flag if AWS PolicyStatus indicates the bucket is public."""
    try:
        resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if resp.get("PolicyStatus", {}).get("IsPublic") is True:
            return Finding(
                resource_type="S3",
                resource_id=bucket_name,
                check_type=CheckType.S3_POLICY_STATUS,
                severity=Severity.CRITICAL,
                detail="AWS policy status confirms bucket policy makes resource public",
                metadata={},
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("NoSuchBucketPolicy", "ServerSideEncryptionConfigurationNotFoundError"):
            logger.warning("Could not fetch policy status for %s: %s", bucket_name, e)
    return None
