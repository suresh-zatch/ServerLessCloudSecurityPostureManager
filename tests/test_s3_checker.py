"""
Unit tests for S3 security checker using moto.
"""

import json
import pytest
from src.s3_checker import check_all_buckets
from src.models import Severity, CheckType

REGION = "us-east-1"


def test_private_bucket_no_findings(boto_session, s3_client):
    """A standard private bucket with Public Access Block fully enabled should have no findings."""
    bucket_name = "secure-private-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = check_all_buckets(boto_session)
    assert len(findings) == 0


def test_public_acl_bucket_flagged(boto_session, s3_client):
    """A bucket with public-read ACL should be flagged."""
    bucket_name = "public-acl-bucket"
    s3_client.create_bucket(Bucket=bucket_name, ACL="public-read")
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = check_all_buckets(boto_session)
    acl_findings = [f for f in findings if f.check_type == CheckType.S3_PUBLIC_ACL]
    assert len(acl_findings) == 1
    assert acl_findings[0].severity == Severity.HIGH
    assert acl_findings[0].resource_id == bucket_name


def test_wildcard_policy_bucket_flagged(boto_session, s3_client):
    """A bucket with policy granting '*' principal should be flagged."""
    bucket_name = "wildcard-policy-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(wildcard_policy))

    findings = check_all_buckets(boto_session)
    policy_findings = [f for f in findings if f.check_type == CheckType.S3_PUBLIC_POLICY]
    assert len(policy_findings) == 1
    assert policy_findings[0].severity == Severity.CRITICAL
    assert policy_findings[0].resource_id == bucket_name
