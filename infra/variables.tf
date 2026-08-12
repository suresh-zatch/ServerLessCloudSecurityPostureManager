# ===========================================================================
# Input Variables
# ===========================================================================

variable "aws_region" {
  description = "AWS region to deploy into and scan"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

# --- Lambda Configuration ---

variable "lambda_memory" {
  description = "Memory allocation for the Lambda function (MB)"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Lambda function timeout (seconds)"
  type        = number
  default     = 300
}

# --- Scheduling ---

variable "scan_schedule" {
  description = "EventBridge schedule expression for the CSPM scan (cron or rate)"
  type        = string
  default     = "rate(24 hours)"
}

# --- Alerting ---

variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL for sending scan alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "alert_min_severity" {
  description = "Minimum severity level to send Slack alerts for (CRITICAL, HIGH, MEDIUM, LOW, INFO)"
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], var.alert_min_severity)
    error_message = "alert_min_severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO."
  }
}

# --- Logging ---

variable "log_retention_days" {
  description = "CloudWatch Log Group retention period (days)"
  type        = number
  default     = 30
}
