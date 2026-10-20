terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-northeast-1"
}

provider "aws" {
  region              = var.region
  profile             = "terraform-admin"
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = "home-server-vpn", ManagedBy = "Terraform" }
  }
}

# Independent state: destroying terraform/server does not release this address.
resource "aws_eip" "vpn" {
  domain = "vpc"
  tags   = { Name = "home-server-vpn" }
}

output "allocation_id" {
  value = aws_eip.vpn.id
}

output "public_ip" {
  value = aws_eip.vpn.public_ip
}

output "region" {
  value = var.region
}

output "account_id" {
  description = "Expected AWS account used by the CLI and local dashboard safety checks."
  value       = var.expected_account_id
}
