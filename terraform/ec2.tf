# --- Security group ---------------------------------------------------------
# HTTP, HTTPS, and SSH. SSH uses key-only auth. Source CIDR is local.web_cidr
# (open by default; set var.restrict_to_cidr to lock a box to your IP).
resource "aws_security_group" "web" {
  name        = "${local.name_prefix}-web"
  description = "HTTP/HTTPS/SSH in"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP (also used for Lets Encrypt challenges)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.web_cidr]
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.web_cidr]
  }
  ingress {
    description = "SSH (key-only auth)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.web_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-web", Environment = local.env }
}

# Use the account's default VPC/subnet to keep this simple.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# --- SSH key pair (imported from your existing local public key) ------------
resource "aws_key_pair" "this" {
  key_name   = "${local.name_prefix}-key"
  public_key = file(pathexpand(var.public_key_path))
}

# --- The instance -----------------------------------------------------------
resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = local.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.web.id]
  key_name               = aws_key_pair.this.key_name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  # Full provisioning baked into cloud-init: Docker, Node, Caddy, the demo image,
  # and the orchestrator service. gzip keeps it under EC2's 16 KB user_data limit.
  # The Caddyfile (incl. dev staging CA vs prod) is computed in locals.
  user_data_base64 = base64gzip(templatefile("${path.module}/user_data.sh.tftpl", {
    caddyfile         = local.caddyfile
    site_index        = file("${path.module}/../site/index.html")
    lab_html          = file("${path.module}/../lab/frontend/lab.html")
    client_dockerfile = file("${path.module}/../lab/client-image/Dockerfile")
    pkg_json          = file("${path.module}/../lab/orchestrator/package.json")
    server_js         = file("${path.module}/../lab/orchestrator/server.js")
    challenges_js     = file("${path.module}/../lab/orchestrator/challenges.js")
    svc_file          = file("${path.module}/../lab/orchestrator/demo-orchestrator.service")
  }))

  # Rebuild the instance from scratch whenever any of the above changes.
  user_data_replace_on_change = true

  tags = { Name = "${local.name_prefix}-web", Environment = local.env }
}

# --- Stable public IP -------------------------------------------------------
resource "aws_eip" "web" {
  instance = aws_instance.web.id
  domain   = "vpc"
  tags     = { Name = "${local.name_prefix}-web", Environment = local.env }
}
