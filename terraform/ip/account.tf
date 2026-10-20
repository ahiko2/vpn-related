variable "expected_account_id" {
  description = "Safety guard: deployment must use this AWS account. Set explicitly before deploying."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Expected a 12 digit AWS account ID."
  }
}
