"""
Shared pytest fixtures for CSPM unit tests.

Uses moto to mock AWS services so tests run without real AWS credentials.
"""

import os
import pytest
import boto3
from moto import mock_aws


@pytest.fixture(scope="session", autouse=True)
def aws_credentials():
    """
    Set dummy AWS credentials for the entire test session.

    Ensures boto3 never accidentally hits real AWS, even if a local
    AWS config file exists.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield
    # cleanup is not strictly necessary for tests, but good practice
    for key in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    ]:
        os.environ.pop(key, None)


@pytest.fixture
def boto_session():
    """
    Provide a moto-mocked boto3 Session.

    Each test function gets a fresh mock AWS environment.
    """
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield session


@pytest.fixture
def ec2_client(boto_session):
    """Provide a moto-mocked EC2 client."""
    return boto_session.client("ec2", region_name="us-east-1")


@pytest.fixture
def s3_client(boto_session):
    """Provide a moto-mocked S3 client."""
    return boto_session.client("s3", region_name="us-east-1")
