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

locals {
  raw_env     = var.environment != "" ? var.environment : terraform.workspace
  is_dev      = local.raw_env == "dev"
  env         = local.is_dev ? "dev" : "prod"
  name_prefix = "oscarlunatech-${local.env}"

  # Hostname this box answers on.
  host = local.is_dev ? "dev.${var.domain_name}" : var.domain_name

  # Instance sizing. The Juice Shop target needs ~1 GB to itself, so dev runs on
  # a larger box; prod keeps var.instance_type until we deliberately promote the
  # new target there. An explicit -var="instance_type=..." still wins on either.
  instance_type = var.instance_type != "t3.micro" ? var.instance_type : (local.is_dev ? "t3.small" : "t3.micro")

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
