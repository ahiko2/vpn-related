variable "region" {
  type    = string
  default = "ap-northeast-1"
}

variable "instance_type" {
  description = "T4g ARM or T3 x86 instance. Standard credits prevent ongoing surplus CPU charges."
  type        = string
  default     = "t3.micro"
  validation {
    condition     = contains(["t4g.nano", "t4g.micro", "t4g.small", "t3.micro"], var.instance_type)
    error_message = "Choose t4g.nano, t4g.micro, t4g.small, or t3.micro."
  }
}

variable "availability_zone" {
  description = "Optional AZ override if the first available AZ lacks T4g capacity."
  type        = string
  default     = null
}

variable "ami_id" {
  description = "Optional pinned Canonical Ubuntu 24.04 AMI matching instance architecture and region."
  type        = string
  default     = null
}

variable "allowed_client_cidrs" {
  description = "IPv4 source networks allowed to reach WireGuard. Roaming devices require 0.0.0.0/0."
  type        = list(string)
  default     = ["0.0.0.0/0"]
  validation {
    condition     = length(var.allowed_client_cidrs) > 0 && alltrue([for c in var.allowed_client_cidrs : can(cidrnetmask(c))])
    error_message = "Provide at least one valid IPv4 CIDR."
  }
}
