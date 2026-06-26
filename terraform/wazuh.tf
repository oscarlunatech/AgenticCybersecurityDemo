# ===========================================================================
# Phase 6 — Wazuh all-in-one monitoring box (per env)
# ---------------------------------------------------------------------------
# A second EC2 instance in the default VPC running Wazuh manager + indexer +
# dashboard. The lab box (aws_instance.web) runs a Wazuh AGENT that reports here
# over the PRIVATE VPC network on 1514/1515 — never the public internet. Only the
# dashboard (443) is exposed publicly, fronted by Caddy (TLS) + basic_auth.
#
# The manager's address must be baked into the lab box's agent config at boot.
# Wiring aws_instance.wazuh.private_ip into that user_data would be an apply-time
# UNKNOWN feeding user_data under replace_on_change => "inconsistent final plan"
# (the same trap documented for the s3 etag in ec2.tf). So we pin a STATIC private
# IP derived from the subnet's CIDR with cidrhost() — plan-known, and guaranteed
# in-range because the box sits in that very subnet. See local.wazuh_private_ip.
#
# IMPORTANT: dev and prod share this same default VPC + subnet, so the static IP
# MUST differ per environment — otherwise both Wazuh boxes demand the same address
# and the second apply fails with InvalidIPAddress.InUse (it did: prod couldn't
# come up until dev was destroyed). The lab boxes never collided because they take
# DHCP-assigned (dynamic) IPs; only the Wazuh box pins a static one. We keep prod on
# .250 (so the live box is untouched) and give dev .249. Both the box IP and the
# lab agent's manager IP derive from local.wazuh_private_ip, so they stay in lockstep.
# ===========================================================================

# Deterministic subnet pick: resolve one default subnet so its CIDR (and thus the
# computed manager IP) is stable, rather than trusting data.aws_subnets ordering.
data "aws_subnet" "wazuh" {
  id = data.aws_subnets.default.ids[0]
}

locals {
  # Static private IP for the manager: a high host of the subnet (low chance of
  # colliding with a DHCP-assigned address). Plan-known. Per-env so dev and prod,
  # which share this subnet, don't both claim the same address: prod keeps .250
  # (live box untouched), dev uses .249.
  wazuh_private_ip = cidrhost(data.aws_subnet.wazuh.cidr_block, local.is_dev ? 249 : 250)
}

# --- Security group ---------------------------------------------------------
# Dashboard (443) public per decision (monitoring_admin_cidr defaults open); the
# agent ports (1514/1515) are reachable ONLY from the lab box's SG, never a CIDR;
# 9200 (indexer) is never opened. SSH follows the same allowlist as the lab box.
resource "aws_security_group" "wazuh" {
  name        = "${local.name_prefix}-wazuh"
  description = "Wazuh dashboard (public), agent comms (VPC-internal), SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Dashboard HTTPS (Caddy)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.monitoring_admin_cidr]
  }
  ingress {
    description = "HTTP (Lets Encrypt challenges only)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description     = "Wazuh agent comms + enrollment (lab box only)"
    from_port       = 1514
    to_port         = 1515
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id] # the lab box's SG, not a CIDR
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
    cidr_blocks = ["0.0.0.0/0"] # install, package updates, Lets Encrypt
  }

  tags = { Name = "${local.name_prefix}-wazuh", Environment = local.env }
}

# --- The instance -----------------------------------------------------------
resource "aws_instance" "wazuh" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.wazuh_instance_type
  subnet_id              = data.aws_subnet.wazuh.id
  private_ip             = local.wazuh_private_ip # static => plan-known for the agent wiring
  vpc_security_group_ids = [aws_security_group.wazuh.id]
  key_name               = aws_key_pair.this.key_name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.wazuh_volume_gb
    encrypted   = true
  }

  # Wazuh install + Caddy front are baked into cloud-init. The admin password is a
  # secret that lands in user_data/state — the same deliberate tradeoff as the
  # Bedrock and read-only-S3 keys (set +x keeps it out of the cloud-init log).
  user_data_base64 = base64gzip(templatefile("${path.module}/wazuh_user_data.sh.tftpl", {
    monitoring_host = local.monitoring_host
    is_dev          = local.is_dev # selects the Lets Encrypt STAGING CA on dev
    admin_password  = var.wazuh_admin_password
    # Phase 6 Grafana: public read-only stats, served by this box's Caddy from a
    # hardened Grafana container (Docker). Anonymous Viewer; admin password gates
    # only the operator login. Both secrets land in user_data/state (same tradeoff).
    stats_host         = local.stats_host
    grafana_admin_pass = var.grafana_admin_password
    # Public lab host Grafana scrapes for usage stats (GET /api/stats). The query
    # runs server-side from the Grafana container (access: proxy), not the browser.
    lab_host = local.host
    # dev serves the lab on a Lets Encrypt STAGING (untrusted) cert, which Grafana's
    # server-side fetch would reject — so skip TLS verification on dev only. prod has
    # a real cert and is verified. (The data is public aggregates either way.)
    lab_tls_skip = local.is_dev ? "true" : "false"
  }))
  user_data_replace_on_change = true

  tags = { Name = "${local.name_prefix}-wazuh", Environment = local.env }
}

# --- Stable public IP -------------------------------------------------------
# Same rationale as the lab box: replace_on_change swaps the instance, so an EIP
# keeps DNS + the issued cert stable across rebuilds. (AWS now bills every public
# IPv4 the same, EIP or not, so there's no extra cost over an auto-assigned one.)
resource "aws_eip" "wazuh" {
  instance = aws_instance.wazuh.id
  domain   = "vpc"
  tags     = { Name = "${local.name_prefix}-wazuh", Environment = local.env }
}

# --- DNS --------------------------------------------------------------------
resource "aws_route53_record" "monitoring" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.monitoring_host
  type    = "A"
  ttl     = 300
  records = [aws_eip.wazuh.public_ip]
}

# Public Grafana stats page — same box, same Caddy, separate vhost.
resource "aws_route53_record" "stats" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.stats_host
  type    = "A"
  ttl     = 300
  records = [aws_eip.wazuh.public_ip]
}
