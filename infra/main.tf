# ===========================================================================
# Terraform Configuration — Serverless CSPM (Cloud Security Posture Manager)
#
# Deploys the CSPM scanner as an AWS Lambda function triggered daily by
# an Amazon EventBridge scheduled rule. Includes least-privilege IAM,
# CloudWatch Log retention, and Lambda packaging.
# ===========================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region                      = var.aws_region
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

# ---------------------------------------------------------------------------
# Local values
# ---------------------------------------------------------------------------

locals {
  function_name = "cspm-scanner"
  lambda_handler = "scanner.lambda_handler"
  lambda_runtime = "python3.12"

  # Tags applied to every resource
  common_tags = {
    Project     = "ServerlessCSPM"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ---------------------------------------------------------------------------
# Lambda Deployment Package
# ---------------------------------------------------------------------------

# Package the src/ directory into a zip for Lambda deployment.
# In production you would use a CI/CD layer or S3 bucket; this is
# suitable for initial deployment and development workflows.
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/cspm_lambda.zip"
}

# ---------------------------------------------------------------------------
# IAM Role & Policy for Lambda
# ---------------------------------------------------------------------------

# Trust policy: allows Lambda service to assume this role
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cspm_lambda_role" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.common_tags
}

# Execution policy: least-privilege access for S3, EC2, STS, and CloudWatch Logs
data "aws_iam_policy_document" "cspm_permissions" {
  # S3 posture checks
  statement {
    sid    = "S3ReadPosture"
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = ["*"]
  }

  # EC2 Security Group inspection
  statement {
    sid    = "EC2ReadSecurityGroups"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
    ]
    resources = ["*"]
  }

  # STS identity lookup (for account ID in reports)
  statement {
    sid    = "STSIdentity"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }

  # CloudWatch Logs — scoped to this function's log group
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.cspm_logs.arn}",
      "${aws_cloudwatch_log_group.cspm_logs.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "cspm_policy" {
  name   = "${local.function_name}-policy"
  role   = aws_iam_role.cspm_lambda_role.id
  policy = data.aws_iam_policy_document.cspm_permissions.json
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cspm_logs" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "cspm_scanner" {
  function_name    = local.function_name
  description      = "Serverless CSPM — scans for public S3 buckets and open Security Groups"
  role             = aws_iam_role.cspm_lambda_role.arn
  handler          = local.lambda_handler
  runtime          = local.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SCAN_REGION        = var.aws_region
      SLACK_WEBHOOK_URL  = var.slack_webhook_url
      ALERT_MIN_SEVERITY = var.alert_min_severity
    }
  }

  depends_on = [
    aws_iam_role_policy.cspm_policy,
    aws_cloudwatch_log_group.cspm_logs,
  ]

  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# EventBridge Scheduled Rule (Daily Scan)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "cspm_schedule" {
  name                = "${local.function_name}-daily-schedule"
  description         = "Triggers the CSPM scanner on a recurring schedule"
  schedule_expression = var.scan_schedule
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "cspm_target" {
  rule      = aws_cloudwatch_event_rule.cspm_schedule.name
  target_id = "${local.function_name}-target"
  arn       = aws_lambda_function.cspm_scanner.arn
}

# Grant EventBridge permission to invoke the Lambda function
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cspm_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cspm_schedule.arn
}
