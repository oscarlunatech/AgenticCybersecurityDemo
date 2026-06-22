variable "domain_name" {
  description = "Apex domain registered in Route 53"
  type        = string
  default     = "oscarlunatech.com"
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "instance_type" {
  description = "Start small; change later with a stop/start (EBS data persists)."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_gb" {
  description = "Size of the gp3 EBS root volume in GiB. Can be grown later with no downtime."
  type        = number
  default     = 16
}

variable "public_key_path" {
  description = "Path to your existing local SSH PUBLIC key. Change to ~/.ssh/id_rsa.pub if that's what you have."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

# Normally left empty so the environment is taken from the Terraform workspace
# (workspace "dev" => dev, anything else => prod). Override only if you must.
variable "environment" {
  description = "Override the environment. Empty = use the workspace name."
  type        = string
  default     = ""
}

# Lock the site/SSH to a single CIDR (e.g. "203.0.113.4/32"). Empty = open to all.
# Handy for keeping the rebuildable dev box off the public internet.
variable "restrict_to_cidr" {
  description = "If set, only this CIDR may reach ports 80/443/22. Empty = 0.0.0.0/0."
  type        = string
  default     = ""
}

# Credentials for the READ-ONLY IAM user the box uses to fetch artifacts from S3
# (its policy is just s3:GetObject on oscarlunatech-*-artifacts/*). Distinct from
# the deploy identity, which has full S3 and uploads the objects. Set these via
# the environment: TF_VAR_artifacts_ro_access_key_id / TF_VAR_artifacts_ro_secret_access_key.
variable "artifacts_ro_access_key_id" {
  description = "Access key ID for the read-only artifacts-bucket IAM user (placed on the box)."
  type        = string
  sensitive   = true
}

variable "artifacts_ro_secret_access_key" {
  description = "Secret access key matching artifacts_ro_access_key_id."
  type        = string
  sensitive   = true
}

# Amazon Bedrock API key (bearer) for the Phase 4 guidance agent. The orchestrator
# calls Gemma 4 on Bedrock's OpenAI-compatible "mantle" endpoint to produce hints.
# Written to a 0600 EnvironmentFile on the box at boot (see user_data.sh.tftpl) —
# like the artifacts RO key, it is injected via env (TF_VAR_bedrock_api_key) and
# ends up in user_data/state (the same deliberate tradeoff). Scope the IAM behind
# it to bedrock-mantle inference only. Empty (default) => guidance is disabled and
# the hint control is hidden, so apply still works without it set.
variable "bedrock_api_key" {
  description = "Bedrock API key for the Gemma 4 guidance agent. Set via TF_VAR_bedrock_api_key. Empty => guidance disabled."
  type        = string
  sensitive   = true
  default     = ""
}

# --- Phase 6: Wazuh monitoring box ------------------------------------------
# Per-env Wazuh all-in-one (manager + indexer + dashboard) on its own EC2 box.
# The lab box runs a Wazuh agent reporting to it over the PRIVATE VPC network;
# only the dashboard (443) is public, fronted by Caddy + basic_auth.
variable "wazuh_instance_type" {
  description = "EC2 type for the Wazuh all-in-one box. 4 GB (t3.medium) is Wazuh's documented minimum; a boot-time swap file cushions it."
  type        = string
  default     = "t3.medium"
}

variable "wazuh_volume_gb" {
  description = "Root gp3 EBS size for the Wazuh box. The indexer (OpenSearch) needs headroom."
  type        = number
  default     = 50
}

variable "wazuh_admin_password" {
  description = "Replaces the Wazuh dashboard default admin password at boot, and gates Caddy basic_auth. Set via TF_VAR_wazuh_admin_password (.env). Must meet Wazuh complexity rules (upper/lower/number/symbol)."
  type        = string
  sensitive   = true
}

# Source CIDR allowed to reach the public dashboard (443). Open for now per
# decision; set to your IP later to lock it down (no rebuild of the design).
variable "monitoring_admin_cidr" {
  description = "CIDR allowed to reach the Wazuh dashboard on 443. Defaults open; narrow to your IP to restrict."
  type        = string
  default     = "0.0.0.0/0"
}

locals {
  raw_env     = var.environment != "" ? var.environment : terraform.workspace
  is_dev      = local.raw_env == "dev"
  env         = local.is_dev ? "dev" : "prod"
  name_prefix = "oscarlunatech-${local.env}"

  # Hostname this box answers on.
  host = local.is_dev ? "dev.${var.domain_name}" : var.domain_name

  # Wazuh dashboard hostname, env-scoped off local.host:
  # monitoring.dev.oscarlunatech.com (dev) / monitoring.oscarlunatech.com (prod).
  monitoring_host = "monitoring.${local.host}"

  # Instance sizing. The Juice Shop target needs ~1 GB to itself, so dev runs on
  # a larger box; prod keeps var.instance_type until we deliberately promote the
  # new target there. An explicit -var="instance_type=..." still wins on either.
  instance_type = var.instance_type != "t3.micro" ? var.instance_type : (local.is_dev ? "t3.small" : "t3.micro")

  # The whole stack is inlined into EC2 user_data, which is gzip-bounded to 16 KB.
  # For the DEPLOYED copy only, strip blank lines and whole-line // comments from
  # the orchestrator JS to reclaim space; the repo keeps the readable source.
  # We filter whole lines (never merge them), so // comment terminators survive.
  # HTML/bash are left untouched — their comment syntax and significant whitespace
  # (CSS #id selectors, <pre>, shebang) make blanket stripping unsafe.
  min_js = { for f in ["server.js", "challenges.js", "agent.js"] :
    f => join("\n", [
      for l in split("\n", file("${path.module}/../lab/orchestrator/${f}")) :
      l if trimspace(l) != "" && !startswith(trimspace(l), "//")
    ])
  }

  # Who may reach the box.
  web_cidr = var.restrict_to_cidr != "" ? var.restrict_to_cidr : "0.0.0.0/0"

  # Caddyfile: dev uses the Let's Encrypt STAGING CA (untrusted certs, but no rate
  # limits while you destroy/rebuild). prod uses the real CA and adds the www redirect.
  caddyfile = join("\n", concat(
    local.is_dev ? [
      "{",
      "    acme_ca https://acme-staging-v02.api.letsencrypt.org/directory",
      "}",
      "",
    ] : [],
    [
      "${local.host} {",
      "    encode gzip",
      "    @lab path /api/* /demo/* /shell/*",
      "    reverse_proxy @lab 127.0.0.1:8080",
      "    root * /var/www/html",
      "    file_server",
      "}",
    ],
    local.is_dev ? [] : [
      "",
      "www.${var.domain_name} {",
      "    redir https://${var.domain_name}{uri} permanent",
      "}",
    ],
  ))
}
