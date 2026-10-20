terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = var.region
  profile             = "terraform-admin"
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = "home-server-vpn", ManagedBy = "Terraform" }
  }
}

# Reads only the IP stack's outputs. Both stacks must use the same account/region.
data "terraform_remote_state" "ip" {
  backend = "local"
  config = {
    path = "${path.module}/../ip/terraform.tfstate"
  }
}

locals {
  architecture = startswith(var.instance_type, "t4g.") ? "arm64" : "x86_64"
  ubuntu_arch  = local.architecture == "arm64" ? "arm64" : "amd64"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${local.ubuntu_arch}-server-*"]
  }
  filter {
    name   = "architecture"
    values = [local.architecture]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Validate pinned images too, so an ARM image cannot be paired with T3.
data "aws_ami" "selected" {
  owners = ["099720109477"]
  filter {
    name   = "image-id"
    values = [coalesce(var.ami_id, data.aws_ami.ubuntu.id)]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "vpn" {
  cidr_block           = "10.77.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "home-server-vpn" }
}

resource "aws_internet_gateway" "vpn" {
  vpc_id = aws_vpc.vpn.id
}

resource "aws_subnet" "vpn" {
  vpc_id                  = aws_vpc.vpn.id
  cidr_block              = "10.77.0.0/28"
  availability_zone       = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])
  map_public_ip_on_launch = false
}

resource "aws_route_table" "vpn" {
  vpc_id = aws_vpc.vpn.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.vpn.id
  }
}

resource "aws_route_table_association" "vpn" {
  subnet_id      = aws_subnet.vpn.id
  route_table_id = aws_route_table.vpn.id
}

resource "aws_security_group" "vpn" {
  name_prefix = "home-server-vpn-"
  description = "WireGuard only; administration via SSM"
  vpc_id      = aws_vpc.vpn.id
}

resource "aws_vpc_security_group_ingress_rule" "wireguard" {
  for_each          = toset(var.allowed_client_cidrs)
  security_group_id = aws_security_group.vpn.id
  cidr_ipv4         = each.value
  ip_protocol       = "udp"
  from_port         = 51820
  to_port           = 51820
}

resource "aws_vpc_security_group_egress_rule" "internet" {
  security_group_id = aws_security_group.vpn.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_iam_role" "ssm" {
  name_prefix = "home-server-vpn-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole", Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "vpn" {
  name_prefix = "home-server-vpn-"
  role        = aws_iam_role.ssm.name
}

resource "aws_instance" "vpn" {
  ami                         = data.aws_ami.selected.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.vpn.id
  vpc_security_group_ids      = [aws_security_group.vpn.id]
  associate_public_ip_address = false
  source_dest_check           = false
  iam_instance_profile        = aws_iam_instance_profile.vpn.name
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    client_helper = filebase64("${path.module}/../../scripts/vpn-client.py")
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }
  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 8
    delete_on_termination = true
  }
  credit_specification {
    cpu_credits = "standard"
  }
  lifecycle {
    # EC2 reports this as true after the separately managed EIP is associated.
    # Ignoring that computed drift avoids replacing a healthy server on every plan.
    ignore_changes = [associate_public_ip_address]
    precondition {
      condition     = data.aws_ami.selected.architecture == local.architecture
      error_message = "The pinned Ubuntu AMI architecture must match the instance type (T3=x86_64, T4g=arm64)."
    }
    precondition {
      condition     = var.region == data.terraform_remote_state.ip.outputs.region
      error_message = "Use the same region as the IP stack."
    }
  }
  depends_on = [aws_iam_role_policy_attachment.ssm, aws_route_table_association.vpn]
  tags       = { Name = "home-server-vpn" }
}

resource "aws_eip_association" "vpn" {
  instance_id   = aws_instance.vpn.id
  allocation_id = data.terraform_remote_state.ip.outputs.allocation_id
}

output "public_ip" {
  value = data.terraform_remote_state.ip.outputs.public_ip
}

output "instance_id" {
  value = aws_instance.vpn.id
}

output "connect" {
  value = "aws --profile terraform-admin ssm start-session --region ${var.region} --target ${aws_instance.vpn.id}"
}

output "account_id" {
  description = "Expected AWS account used by the CLI and local dashboard safety checks."
  value       = var.expected_account_id
}
