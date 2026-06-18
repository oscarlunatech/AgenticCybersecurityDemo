# --- Security group ---------------------------------------------------------
# HTTP, HTTPS, and SSH open to the internet. SSH uses key-only auth.
resource "aws_security_group" "web" {
  name        = "oscarlunatech-web"
  description = "HTTP/HTTPS/SSH in"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP (also used for Lets Encrypt challenges)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere (key-only auth)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "oscarlunatech-web" }
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
  key_name   = "oscarlunatech-key"
  public_key = file(pathexpand(var.public_key_path))
}

# --- The instance -----------------------------------------------------------
resource "aws_instance" "web" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
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

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    domain   = var.domain_name
    www      = local.www
    site_b64 = base64encode(file("${path.module}/../site/index.html"))
  })

  # Re-run user_data if the page changes
  user_data_replace_on_change = true

  tags = { Name = "oscarlunatech-web" }
}

# --- Stable public IP -------------------------------------------------------
resource "aws_eip" "web" {
  instance = aws_instance.web.id
  domain   = "vpc"
  tags     = { Name = "oscarlunatech-web" }
}
