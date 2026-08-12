# ===========================================================================
# Outputs
# ===========================================================================

output "lambda_function_arn" {
  description = "ARN of the deployed CSPM Lambda function"
  value       = aws_lambda_function.cspm_scanner.arn
}

output "lambda_function_name" {
  description = "Name of the deployed CSPM Lambda function"
  value       = aws_lambda_function.cspm_scanner.function_name
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution IAM role"
  value       = aws_iam_role.cspm_lambda_role.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge scheduled rule"
  value       = aws_cloudwatch_event_rule.cspm_schedule.arn
}

output "log_group_name" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.cspm_logs.name
}

output "scan_schedule" {
  description = "The configured scan schedule expression"
  value       = var.scan_schedule
}
