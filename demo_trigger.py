"""
Demo Trigger Script — Simulates Real-World AWS Misconfigurations and Executes CSPM Scan.

Uses moto to safely mock AWS resources locally without touching live AWS infrastructure.
Creates high-risk security misconfigurations (public S3 buckets, exposed SSH/DB/RDP ports),
executes the CSPM scanner, outputs the findings in JSON format, and writes to demo_output.txt.
"""

import json
import os
import sys

# Ensure local packages in src/ are importable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure UTF-8 output formatting for Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import boto3
from moto import mock_aws
from src.scanner import run_scan, format_report_json, format_report_text


def setup_mock_misconfigurations(session: boto3.Session, region: str):
    """Create a realistic mix of insecure and compliant AWS resources."""
    s3_client = session.client("s3", region_name=region)
    ec2_client = session.client("ec2", region_name=region)

    print("🛠️  Provisioning mock AWS environment with security misconfigurations...")

    # -----------------------------------------------------------------------
    # 1. Compliant S3 Bucket
    # -----------------------------------------------------------------------
    s3_client.create_bucket(Bucket="company-secure-backups-2026")
    s3_client.put_public_access_block(
        Bucket="company-secure-backups-2026",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # -----------------------------------------------------------------------
    # 2. Insecure S3 Bucket — Wildcard Policy
    # -----------------------------------------------------------------------
    s3_client.create_bucket(Bucket="customer-data-export-public")
    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::customer-data-export-public",
                    "arn:aws:s3:::customer-data-export-public/*",
                ],
            }
        ],
    }
    s3_client.put_bucket_policy(
        Bucket="customer-data-export-public",
        Policy=json.dumps(wildcard_policy),
    )

    # -----------------------------------------------------------------------
    # 3. Insecure S3 Bucket — Public ACL
    # -----------------------------------------------------------------------
    s3_client.create_bucket(Bucket="public-assets-static-media", ACL="public-read")

    # -----------------------------------------------------------------------
    # 4. Compliant Security Group (Restricted Ingress)
    # -----------------------------------------------------------------------
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    secure_sg = ec2_client.create_security_group(
        GroupName="internal-microservice-sg",
        Description="Restricted to VPC internal traffic",
        VpcId=vpc_id,
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=secure_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 8080,
                "ToPort": 8080,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            }
        ],
    )

    # -----------------------------------------------------------------------
    # 5. Insecure Security Group — Critical Port Exposed (SSH Port 22 to 0.0.0.0/0)
    # -----------------------------------------------------------------------
    bastion_sg = ec2_client.create_security_group(
        GroupName="dev-bastion-host-sg",
        Description="Exposed SSH Bastion Host",
        VpcId=vpc_id,
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=bastion_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # -----------------------------------------------------------------------
    # 6. Insecure Security Group — Database Exposed (PostgreSQL 5432 to 0.0.0.0/0)
    # -----------------------------------------------------------------------
    db_sg = ec2_client.create_security_group(
        GroupName="prod-db-cluster-sg",
        Description="Production Database exposed publicly",
        VpcId=vpc_id,
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=db_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # -----------------------------------------------------------------------
    # 7. Insecure Security Group — IPv6 RDP Exposed (Port 3389 to ::/0)
    # -----------------------------------------------------------------------
    win_sg = ec2_client.create_security_group(
        GroupName="win-admin-rdp-sg",
        Description="Windows RDP Server exposed on IPv6",
        VpcId=vpc_id,
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=win_sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    )

    print("✅ Environment setup complete!")


def main():
    region = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = region
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"

    with mock_aws():
        session = boto3.Session(region_name=region)

        # 1. Setup mock resources
        setup_mock_misconfigurations(session, region)

        # 2. Run scan
        print("\n🔍 Executing Serverless CSPM Security Audit...")
        report = run_scan(session, region)

        # 3. Format outputs
        json_output = format_report_json(report)
        text_output = format_report_text(report)

        print("\n" + text_output)

        # 4. Save demo output log
        output_filepath = os.path.join(os.path.dirname(__file__), "demo_output.txt")
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(text_output + "\n\n" + "="*60 + "\nFULL JSON PAYLOAD:\n" + "="*60 + "\n" + json_output)

        print(f"\n💾 Demo execution results saved to: {output_filepath}")


if __name__ == "__main__":
    main()
