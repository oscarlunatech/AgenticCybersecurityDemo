# Hosted zone created when you registered the domain in Route 53.
data "aws_route53_zone" "this" {
  name         = var.domain_name
  private_zone = false
}

# Latest Ubuntu 24.04 LTS (Noble) image from Canonical. Caddy installs cleanly here.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name = "name"
    values = [
      "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
      "ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*",
    ]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
