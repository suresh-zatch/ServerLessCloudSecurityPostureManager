# Serverless Cloud Security Posture Manager (CSPM) — Task Breakdown

> A serverless tool that continuously audits AWS resources for security misconfigurations and alerts via Slack.

---

## Phase 1 — Local Setup & IAM Mock Roles

- [x] Initialize project directory structure
  - [x] Create `src/` for application source code
  - [x] Create `tests/` for unit and integration tests
  - [ ] Create `infra/` for IaC templates (SAM / Terraform)
  - [ ] Create `config/` for environment-specific configuration files
  - [x] Add `.gitignore` (Python, AWS SAM, Terraform, virtualenv)
  - [ ] Add `README.md` with project overview, architecture diagram placeholder, and setup instructions
- [x] Set up Python virtual environment and dependency management
  - [x] Create `requirements.txt` with initial dependencies (`boto3`, `moto`, `requests`, `pytest`)
  - [x] Create `requirements-dev.txt` for development/test dependencies (`moto[all]`, `pytest-cov`, `black`, `flake8`)
- [ ] Configure AWS credentials for local development
  - [ ] Document usage of `AWS_PROFILE` / `AWS_DEFAULT_REGION` environment variables
  - [ ] Create a sample `.env.example` file (no real secrets)
- [ ] Define IAM mock roles and policies
  - [ ] Draft a least-privilege IAM policy JSON for the CSPM Lambda role
    - `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`, `s3:ListAllMyBuckets`
    - `ec2:DescribeSecurityGroups`
    - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`
  - [ ] Create a mock IAM role definition (`infra/iam_policy.json`) for documentation and deployment
  - [x] Write a `moto`-based test fixture that mocks `sts:AssumeRole` and validates the policy permissions
- [x] Validate local tooling
  - [x] Verify `aws sts get-caller-identity` works with local profile (or mock)
  - [x] Verify `moto` mock environment spins up correctly in a smoke test

---

## Phase 2 — Security Posture Checks (S3 & Security Groups)

### 2A — Public S3 Bucket Detection

- [ ] Implement `s3_checker.py` module
  - [ ] List all S3 buckets in the account via `s3:ListAllMyBuckets`
  - [ ] For each bucket, retrieve:
    - [ ] Bucket ACL (`get_bucket_acl`) — flag grants to `AllUsers` or `AuthenticatedUsers`
    - [ ] Bucket Policy (`get_bucket_policy`) — parse JSON for `"Principal": "*"` or overly permissive `Action`/`Resource`
    - [ ] Bucket Public Access Block (`get_public_access_block`) — flag if any of the four block settings is `False` or missing
    - [ ] Bucket Policy Status (`get_bucket_policy_status`) — flag `IsPublic: true`
  - [ ] Return a structured list of findings: `{ bucket_name, check_type, severity, detail }`
- [ ] Write unit tests with `moto`
  - [ ] Test a private bucket returns zero findings
  - [ ] Test a bucket with public ACL is flagged
  - [ ] Test a bucket with a wildcard principal policy is flagged
  - [ ] Test a bucket with Public Access Block fully enabled returns zero findings

### 2B — Open Security Group Detection

- [x] Implement `sg_checker.py` module
  - [x] Describe all Security Groups via `ec2:DescribeSecurityGroups`
  - [x] For each Security Group, inspect **inbound rules** (`IpPermissions`):
    - [x] Flag rules with `CidrIp: 0.0.0.0/0` or `CidrIpv6: ::/0`
    - [x] Record the exposed port range (`FromPort` – `ToPort`) and protocol
    - [x] Assign severity: **Critical** for SSH (22), RDP (3389), DB ports (3306, 5432, 1433); **High** for all other open-to-world rules
  - [x] Return a structured list of findings: `{ sg_id, sg_name, vpc_id, rule, severity, detail }`
- [x] Write unit tests with `moto`
  - [x] Test a Security Group with no inbound rules returns zero findings
  - [x] Test a Security Group open to `0.0.0.0/0` on port 22 is flagged as Critical
  - [x] Test a Security Group open to `0.0.0.0/0` on port 8080 is flagged as High
  - [x] Test a Security Group restricted to a specific CIDR (e.g., `10.0.0.0/8`) is not flagged

### 2C — Orchestration & Reporting

- [ ] Implement `scanner.py` — main orchestrator
  - [ ] Call `s3_checker` and `sg_checker` in sequence
  - [ ] Aggregate all findings into a unified report structure
  - [ ] Add metadata: scan timestamp (ISO 8601), AWS account ID, region
  - [ ] Support output formats: JSON (for downstream processing) and human-readable summary (for logs)
- [ ] Add CLI entry point for local testing
  - [ ] Accept `--region`, `--output-format`, and `--dry-run` flags
  - [ ] Print summary stats: total checks run, findings by severity

---

## Phase 3 — Slack API Integration for Alerting

- [ ] Set up Slack integration
  - [ ] Create a Slack App (document steps in `README.md`)
  - [ ] Configure a Slack Incoming Webhook **or** Bot Token with `chat:write` scope
  - [ ] Store Slack webhook URL / token in environment variable (`SLACK_WEBHOOK_URL`)
- [ ] Implement `notifier.py` module
  - [ ] Build a Slack message formatter
    - [ ] Use Slack Block Kit for rich formatting (header, sections, dividers)
    - [ ] Color-code by severity: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Info
    - [ ] Include scan metadata (timestamp, account, region) in the header
    - [ ] Group findings by resource type (S3 / Security Groups)
    - [ ] Truncate payload if findings exceed Slack's message size limit (3000 chars per block)
  - [ ] Send alert via `requests.post` to Slack webhook
  - [ ] Handle HTTP errors and retries (exponential backoff, max 3 retries)
  - [ ] Support a `--dry-run` mode that prints the Slack payload without sending
- [ ] Write unit tests
  - [ ] Mock `requests.post` to verify payload structure matches Slack Block Kit schema
  - [ ] Test message truncation when findings exceed size limit
  - [ ] Test retry logic on 429 (rate limit) and 5xx responses
  - [ ] Test that zero-findings scan sends a "✅ All clear" summary instead of an empty message
- [ ] Add alerting threshold configuration
  - [ ] Allow filtering alerts by minimum severity (e.g., only alert on Critical + High)
  - [ ] Add config option `ALERT_MIN_SEVERITY` in environment / config file

---

## Phase 4 — Infrastructure as Code & Deployment

### 4A — AWS SAM Template

- [ ] Create `infra/template.yaml` (SAM)
  - [ ] Define Lambda function resource
    - [ ] Runtime: Python 3.12
    - [ ] Handler: `src/scanner.lambda_handler`
    - [ ] Memory: 256 MB, Timeout: 300 seconds
    - [ ] Environment variables: `SLACK_WEBHOOK_URL`, `ALERT_MIN_SEVERITY`, `SCAN_REGION`
  - [ ] Define IAM Role with the least-privilege policy from Phase 1
  - [ ] Define EventBridge (CloudWatch Events) scheduled rule
    - [ ] Default schedule: `rate(24 hours)` — daily scan
    - [ ] Allow schedule override via SAM parameter
  - [ ] Define CloudWatch Log Group with 30-day retention
  - [ ] Add SAM parameters for: `SlackWebhookUrl`, `ScanSchedule`, `AlertMinSeverity`
  - [ ] Add `Outputs` section: Lambda ARN, EventBridge Rule ARN, Log Group name

### 4B — Terraform Alternative (Optional)

- [x] Create `infra/main.tf`
  - [x] Define `aws_lambda_function` resource mirroring SAM config
  - [x] Define `aws_iam_role` and `aws_iam_role_policy` for Lambda
  - [x] Define `aws_cloudwatch_event_rule` and `aws_cloudwatch_event_target`
  - [x] Define `aws_cloudwatch_log_group` with retention
- [x] Create `infra/variables.tf` for input variables
- [x] Create `infra/outputs.tf` for resource ARNs

### 4C — Packaging & CI/CD

- [ ] Add Lambda handler wrapper in `src/scanner.py`
  - [ ] Implement `lambda_handler(event, context)` entry point
  - [ ] Parse EventBridge event payload (if needed)
  - [ ] Return structured response with scan summary
- [ ] Create `Makefile` or shell scripts for common operations
  - [ ] `make build` — install dependencies, package Lambda zip
  - [ ] `make test` — run pytest with coverage
  - [ ] `make lint` — run `flake8` and `black --check`
  - [ ] `make deploy` — `sam deploy --guided` or `terraform apply`
- [ ] Document deployment steps in `README.md`
  - [ ] Prerequisites (AWS CLI, SAM CLI, Python 3.12, Slack App)
  - [ ] Step-by-step first-time deployment guide
  - [ ] How to update the scan schedule
  - [ ] How to add new security checks in the future

---

## Target Project Structure

```
ServerLessCloudSecurityPostureManager/
├── config/
│   └── .env.example
├── infra/
│   ├── iam_policy.json
│   ├── template.yaml          # AWS SAM
│   ├── main.tf                # Terraform (optional)
│   ├── variables.tf
│   └── outputs.tf
├── src/
│   ├── __init__.py
│   ├── scanner.py             # Orchestrator + Lambda handler
│   ├── s3_checker.py          # S3 public bucket checks
│   ├── sg_checker.py          # Security Group checks
│   └── notifier.py            # Slack alerting
├── tests/
│   ├── __init__.py
│   ├── test_s3_checker.py
│   ├── test_sg_checker.py
│   ├── test_notifier.py
│   └── conftest.py            # Shared moto fixtures
├── .gitignore
├── Makefile
├── README.md
├── requirements.txt
├── requirements-dev.txt
└── tasks.md                   # ← This file
```
