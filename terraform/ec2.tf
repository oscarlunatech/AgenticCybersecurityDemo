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
  # and the orchestrator service. gzip keeps it under EC2's 16 KB user_data limit;
  # the large static files (index.html, lab.html) are fetched from S3 at boot
  # rather than inlined. The Caddyfile (dev staging CA vs prod) is computed in locals.
  user_data_base64 = base64gzip(templatefile("${path.module}/user_data.sh.tftpl", {
    caddyfile        = local.caddyfile
    artifacts_bucket = aws_s3_bucket.artifacts.id
    aws_region       = var.region
    ro_key_id        = var.artifacts_ro_access_key_id
    ro_key_secret    = var.artifacts_ro_secret_access_key
    # Embed the file content hashes so an edit re-renders user_data, which (with
    # replace_on_change) rebuilds the box and re-fetches the new files. Use
    # filemd5 of the LOCAL file (known at plan time), not the s3_object etag
    # (unknown until apply) — an unknown user_data here flips the instance's
    # planned action mid-apply and trips "Provider produced inconsistent final
    # plan". filemd5 equals the etag for these single-part AES256 uploads.
    site_index_hash = filemd5("${path.module}/../site/index.html")
    lab_html_hash   = filemd5("${path.module}/../lab/frontend/lab.html")
    # Combined hash of the SQLi target build context: changes if any file does,
    # re-rendering user_data so the box rebuilds the image. filemd5 is plan-known.
    sqli_target_hash = md5(join("", [
      for f in fileset("${path.module}/../lab/targets/sqli-login", "*") :
      filemd5("${path.module}/../lab/targets/sqli-login/${f}")
    ]))
    client_dockerfile = file("${path.module}/../lab/client-image/Dockerfile")
    pkg_json          = file("${path.module}/../lab/orchestrator/package.json")
    server_js         = local.min_js["server.js"] # comments/blank lines stripped to fit user_data's 16 KB cap
    challenges_js     = local.min_js["challenges.js"]
    agent_js          = local.min_js["agent.js"]
    bedrock_api_key   = var.bedrock_api_key # secret; written to a 0600 EnvironmentFile at boot
    svc_file          = file("${path.module}/../lab/orchestrator/demo-orchestrator.service")
    # Phase 6: static, plan-known private IP of the per-env Wazuh manager, baked
    # into the agent config at boot. Plan-known (cidrhost of an existing subnet's
    # CIDR), so it's safe to feed user_data under replace_on_change.
    wazuh_manager_ip = local.wazuh_private_ip
  }))

  # Rebuild the instance from scratch whenever any of the above changes.
  user_data_replace_on_change = true

  # The boot script fetches index.html/lab.html from the bucket, so the objects
  # must be uploaded before the box (re)boots. filemd5 above keeps user_data
  # plan-known; this just orders the upload ahead of the instance.
  depends_on = [aws_s3_object.site_index, aws_s3_object.lab_html, aws_s3_object.sqli_target]

  tags = { Name = "${local.name_prefix}-web", Environment = local.env }
}

# --- Stable public IP -------------------------------------------------------
resource "aws_eip" "web" {
  instance = aws_instance.web.id
  domain   = "vpc"
  tags     = { Name = "${local.name_prefix}-web", Environment = local.env }
}
